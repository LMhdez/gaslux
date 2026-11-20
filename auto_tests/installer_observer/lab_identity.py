"""Read-only Linux QEMU/QMP identity witness. Never authorizes guest input.

QMP is connected through a private Unix socket and bound to the actual
QEMU process with SO_PEERCRED. Independent /proc and fd inspection checks
against a prepared, immutable run contract. It is not an input lock.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evidence import Refusal, digest
from .state_machine import LabAuthority


@dataclass(frozen=True)
class ProcessSeal:
    pid: int
    uid: int
    start_ticks: int
    command_sha256: str
    executable_dev: int
    executable_ino: int


def process_seal(pid: int) -> ProcessSeal:
    """Read a PID fingerprint; caller must seal it before the VM is used."""
    if os.name != "posix" or type(pid) is not int or pid <= 1:
        raise Refusal("Linux QEMU process required")
    root = Path("/proc") / str(pid)
    try:
        raw = (root / "stat").read_text()
        fields = raw[raw.rfind(")") + 2 :].split()
        if not raw.startswith(str(pid) + " (") or len(fields) < 20:
            raise Refusal("Malformed process identity")
        command = (root / "cmdline").read_bytes()
        executable = (root / "exe").stat()
        owner = root.stat().st_uid
        if not command or b"qemu-system-" not in Path(os.readlink(root / "exe")).name.encode():
            raise Refusal("Unexpected VM executable")
        return ProcessSeal(
            pid, owner, int(fields[19]), digest(command), executable.st_dev, executable.st_ino
        )
    except (OSError, ValueError, IndexError) as exc:
        raise Refusal("Cannot independently establish QEMU process identity") from exc


@dataclass(frozen=True)
class AttachedFile:
    path: Path
    dev: int
    ino: int
    size: int
    mtime_ns: int


def seal_file(path: Path) -> AttachedFile:
    try:
        if path.is_symlink() or path.resolve(strict=True) != path.absolute():
            raise Refusal("Noncanonical VM media path")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            raise Refusal("VM media must be a single-link regular file")
        return AttachedFile(
            path.absolute(), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
        )
    except OSError as exc:
        raise Refusal("Cannot seal VM media") from exc


@dataclass(frozen=True)
class QemuRunSeal:
    authority: LabAuthority
    process: ProcessSeal
    qmp_socket: Path
    vnc_port: int
    iso: AttachedFile
    cow: AttachedFile
    vnc_socket: Path | None = None

    def __post_init__(self) -> None:
        if (
            not self.authority.run_id
            or not self.authority.snapshot_id
            or not self.authority.source_commit
            or self.authority.synthetic_cow_only is not True
            or self.authority.physical_disk_attached is not False
            or type(self.vnc_port) is not int
            or (self.vnc_socket is None and not 5900 <= self.vnc_port <= 5999)
            or self.iso.path == self.cow.path
            or self.process.uid != os.geteuid()
        ):
            raise Refusal("Unsafe or incomplete QEMU run seal")


def _read_response(stream: Any) -> dict:
    for _ in range(20):
        raw = stream.readline(262145)
        if not raw or len(raw) > 262144:
            raise Refusal("Truncated or oversized QMP message")
        try:
            obj = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise Refusal("Invalid QMP reply") from exc
        if not isinstance(obj, dict):
            raise Refusal("Invalid QMP response type")
        if "event" in obj:
            continue
        return obj
    raise Refusal("Unbounded QMP asynchronous messages")


def _execute(sock: socket.socket, stream: Any, name: str) -> Any:
    if name not in ("qmp_capabilities", "query-block", "query-vnc", "query-status"):
        raise Refusal("QMP command is not allowed")
    sock.sendall((json.dumps({"execute": name}) + "\r\n").encode("ascii"))
    reply = _read_response(stream)
    if set(reply) != {"return"}:
        raise Refusal("QMP command rejected or unexpected response")
    return reply["return"]


def _check_attachment(
    blocks: list[dict], sealed: AttachedFile, fmt: str, *, read_only: bool
) -> dict:
    matched = [
        b["inserted"]
        for b in blocks
        if isinstance(b, dict)
        and isinstance(b.get("inserted"), dict)
        and b["inserted"].get("file") == str(sealed.path)
    ]
    if len(matched) != 1:
        raise Refusal("Missing or ambiguous QMP attached image")
    inserted = matched[0]
    image = inserted.get("image")
    if not isinstance(image, dict) or image.get("filename") != str(sealed.path):
        raise Refusal("QMP image provenance mismatch")
    if image.get("format") != fmt or inserted.get("ro") is not read_only:
        raise Refusal("QMP media format/read-only mismatch")
    if image.get("backing-image") or image.get("full-backing-filename"):
        raise Refusal("Unverified image backing chain")
    return image


def verify_qmp_report(seal: QemuRunSeal, blocks: Any, vnc: Any, status: Any) -> None:
    """Pure contract. A JSON report alone is NEVER valid attestation."""
    if not isinstance(blocks, list) or len(blocks) != 2:
        raise Refusal("Unexpected number of QEMU block devices")
    if not isinstance(status, dict) or status.get("status") not in (
        "running",
        "prelaunch",
        "paused",
    ):
        raise Refusal("VM is not in an allowed observation state")
    if not isinstance(vnc, dict) or vnc.get("enabled") is not True:
        raise Refusal("QMP VNC endpoint disabled or malformed")
    if vnc.get("clients") != []:
        raise Refusal("Unbound graphical endpoint or another VNC client")
    if seal.vnc_socket is None:
        if vnc.get("host") != "127.0.0.1" or str(vnc.get("service")) != str(
            seal.vnc_port
        ):
            raise Refusal("Unbound graphical endpoint or another VNC client")
    elif vnc.get("family") != "unix":
        raise Refusal("VNC endpoint is not a Unix socket: " + str(vnc.get("family")))
    _check_attachment(blocks, seal.iso, "raw", read_only=True)
    cow = _check_attachment(blocks, seal.cow, "qcow2", read_only=False)
    snapshots = cow.get("snapshots")
    if (
        not isinstance(snapshots, list)
        or sum(
            isinstance(item, dict) and item.get("name") == seal.authority.snapshot_id
            for item in snapshots
        )
        != 1
    ):
        raise Refusal("Snapshot identity cannot be corroborated by QMP")


class LocalQemuAttestor:
    """Corroborates process, open file descriptors, QMP peer and VNC endpoint.

    Designed for a dedicated unprivileged Unix user, not a hostile same-UID or
    privileged host. No exclusive framebuffer/input ownership is claimed.
    """

    def __init__(self, seal: QemuRunSeal):
        if seal.iso.size != seal.authority.media.size_bytes:
            raise Refusal("ISO size differs from pinned laboratory identity")
        # Full ISO SHA-256 checked once; every subsequent check pins its inode,
        # size and modification time (not an upstream signature).
        seal.authority.media.verify_iso(seal.iso.path)
        self.seal = seal

    def verify(self, deadline: float) -> LabAuthority:
        seal = self.seal
        if time.monotonic() >= deadline:
            raise Refusal("QEMU attestation deadline expired")
        if process_seal(seal.process.pid) != seal.process:
            raise Refusal("QEMU process replaced or reconfigured")
        if seal_file(seal.iso.path) != seal.iso:
            raise Refusal("ISO identity changed")
        # COW contents/size/mtime may legitimately change while QEMU runs.
        cow = seal_file(seal.cow.path)
        if (cow.dev, cow.ino) != (seal.cow.dev, seal.cow.ino):
            raise Refusal("COW inode replaced")
        with seal.cow.path.open("rb") as handle:
            header = handle.read(20)
        if (
            len(header) != 20
            or header[:4] != bytes.fromhex("514649fb")
            or int.from_bytes(header[8:16], "big") != 0
            or int.from_bytes(header[16:20], "big") != 0
        ):
            raise Refusal("Unexpected QCOW2 header or backing file")
        root = Path("/proc") / str(seal.process.pid) / "fd"
        found = set()
        try:
            for entry in root.iterdir():
                desc = entry.stat()
                if stat.S_ISBLK(desc.st_mode):
                    raise Refusal("Physical block device attached to QEMU")
                if stat.S_ISREG(desc.st_mode):
                    identity = (desc.st_dev, desc.st_ino)
                    if identity in ((seal.iso.dev, seal.iso.ino), (seal.cow.dev, seal.cow.ino)):
                        found.add(identity)
            if found != {(seal.iso.dev, seal.iso.ino), (seal.cow.dev, seal.cow.ino)}:
                raise Refusal("QEMU file descriptors do not corroborate both media")
            socket_path = seal.qmp_socket
            directory = socket_path.parent.stat()
            endpoint = socket_path.lstat()
            if seal.vnc_socket is not None:
                vnc_path = seal.vnc_socket
                vnc_endpoint = vnc_path.lstat()
                if (
                    vnc_path.is_symlink()
                    or vnc_path.parent != socket_path.parent
                    or not stat.S_ISSOCK(vnc_endpoint.st_mode)
                    or vnc_endpoint.st_uid != seal.process.uid
                    or vnc_endpoint.st_mode & 0o077
                ):
                    raise Refusal("VNC Unix endpoint not private")
            if (
                socket_path.parent.resolve(strict=True) != socket_path.parent.absolute()
                or not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != seal.process.uid
                or directory.st_mode & 0o077
                or not stat.S_ISSOCK(endpoint.st_mode)
                or endpoint.st_uid != seal.process.uid
                or endpoint.st_mode & 0o077
            ):
                raise Refusal("QMP socket is not private to the VM controller")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as qmp:
                qmp.settimeout(max(0.001, deadline - time.monotonic()))
                qmp.connect(str(socket_path))
                peer_pid, peer_uid, _ = struct.unpack(
                    "3i", qmp.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                if (peer_pid, peer_uid) != (seal.process.pid, seal.process.uid):
                    raise Refusal("QMP peer is not the sealed QEMU process")
                with qmp.makefile("rb") as stream:
                    greeting = _read_response(stream)
                    if not isinstance(greeting.get("QMP"), dict):
                        raise Refusal("QMP greeting missing")
                    _execute(qmp, stream, "qmp_capabilities")
                    blocks = _execute(qmp, stream, "query-block")
                    vnc = _execute(qmp, stream, "query-vnc")
                    status = _execute(qmp, stream, "query-status")
                    verify_qmp_report(seal, blocks, vnc, status)
        except (OSError, struct.error, TimeoutError) as exc:
            raise Refusal("QMP or process inspection failed closed") from exc
        if time.monotonic() >= deadline or process_seal(seal.process.pid) != seal.process:
            raise Refusal("QEMU identity diverged during QMP interrogation")
        return seal.authority
