"""Fail-closed Unix endpoint witness for *read-only* disposable QEMU laboratories.

This module does not grant input or protect against an adversarial same-UID
process. The latter can access both sockets despite cooperative controller
leases, so the Observer must keep refusing guest events.
"""

from __future__ import annotations

import os
import socket
import stat
from dataclasses import dataclass
from pathlib import Path

from .evidence import Refusal
from .lab_identity import ProcessSeal, process_seal


@dataclass(frozen=True)
class Endpoint:
    path: Path
    device: int
    inode: int
    uid: int


def seal_endpoint(path: Path, uid: int) -> Endpoint:
    """Pin a private Unix socket, its inode and its containing directory."""
    try:
        parent = path.parent
        folder = parent.lstat()
        entry = path.lstat()
        if (
            parent.is_symlink()
            or path.is_symlink()
            or parent.resolve(strict=True) != parent.absolute()
            or not stat.S_ISDIR(folder.st_mode)
            or folder.st_uid != uid
            or folder.st_mode & 0o077
            or not stat.S_ISSOCK(entry.st_mode)
            or entry.st_uid != uid
            or entry.st_mode & 0o077
        ):
            raise Refusal("Unix endpoint not private")
        return Endpoint(path, entry.st_dev, entry.st_ino, uid)
    except Refusal:
        raise
    except OSError as exc:
        raise Refusal("Cannot authenticate Unix endpoint") from exc


def verify_endpoint(sealed: Endpoint) -> None:
    current = seal_endpoint(sealed.path, sealed.uid)
    if current != sealed:
        raise Refusal("Unix endpoint replaced or reused")


def verified_unix_peer(endpoint: Endpoint, process: ProcessSeal, deadline: float) -> None:
    """Authenticate server PID/UID via kernel SO_PEERCRED, without RFB messages."""
    import time

    verify_endpoint(endpoint)
    if time.monotonic() >= deadline or process_seal(process.pid) != process:
        raise Refusal("QEMU identity or endpoint deadline changed")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect(str(endpoint.path))
            import struct

            peer_pid, peer_uid, _peer_gid = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if (peer_pid, peer_uid) != (process.pid, process.uid):
                raise Refusal("Unix socket peer is not the authenticated QEMU process")
    except (OSError, TimeoutError) as exc:
        raise Refusal("Unix endpoint peer verification failed") from exc
    if process_seal(process.pid) != process:
        raise Refusal("QEMU identity changed after Unix peer connection")
    verify_endpoint(endpoint)


def assert_no_qemu_tcp_listeners(process: ProcessSeal) -> None:
    """Reject TCP LISTEN inodes owned by QEMU in its network namespace."""
    if process_seal(process.pid) != process:
        raise Refusal("QEMU identity changed before TCP inventory")
    root = Path("/proc") / str(process.pid)
    try:
        owned = set()
        for descriptor in (root / "fd").iterdir():
            target = os.readlink(descriptor)
            if target.startswith("socket:[") and target.endswith("]"):
                owned.add(target[8:-1])
        for table in (root / "net/tcp", root / "net/tcp6"):
            for row in table.read_text().splitlines()[1:]:
                fields = row.split()
                if len(fields) < 10:
                    raise Refusal("Invalid kernel TCP inventory")
                if fields[3] == "0A" and fields[9] in owned:
                    raise Refusal("QEMU owns an unexpected TCP listening socket")
    except Refusal:
        raise
    except OSError as exc:
        raise Refusal("Cannot inventory QEMU TCP socket descriptors") from exc
    if process_seal(process.pid) != process:
        raise Refusal("QEMU identity changed during TCP inventory")


def clean_owned_endpoint(sealed: Endpoint) -> None:
    """Only unlink our exact original inode, after QEMU has exited."""
    if not sealed.path.exists() and not sealed.path.is_symlink():
        return
    verify_endpoint(sealed)
    try:
        sealed.path.unlink()
    except OSError as exc:
        raise Refusal("Unable to remove owned Unix endpoint") from exc
    if sealed.path.exists() or sealed.path.is_symlink():
        raise Refusal("Unix endpoint cleanup incomplete")
