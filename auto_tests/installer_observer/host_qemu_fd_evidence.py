"""Experimental HOST-only QEMU/FD measurements; NEVER a launch or write authority.

Uses Observer v1 process/QMP witnesses, pinned Safety GPT-FD parser (#286)
and optional pinned Safety QCOW2 chain verifier (#267). The requesting branch,
process, QMP and signatures from one runner cannot attest external provenance.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import socket
import stat
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .host_fd_boundary import (
    ProcessSeal,
    _execute,
    _qemu_executable_hash,
    _read_response,
    process_seal,
)

MAX_FDS = 4096
MAX_SECTORS_BYTES = 4 * 1024 * 1024
MAX_MEDIA_BYTES = 512 * 1024 * 1024


class HostEvidenceRefused(ValueError):
    """No association or authority is inferred from a failed local inspection."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise HostEvidenceRefused(code)


@dataclass(frozen=True)
class HostPins:
    """Externally supplied expectations; this object does NOT authenticate them."""

    process: ProcessSeal
    qemu_executable_sha256: str
    transaction_id: str
    vm_uuid: str
    challenge: str
    device_name: str
    serial: str
    fd_number: int
    media_path: Path
    expected_dev: int
    expected_inode: int
    expected_size: int
    logical_sector_size: int = 512

    def __post_init__(self) -> None:
        require(
            self.process.pid > 1
            and self.process.start_ticks > 0
            and type(self.fd_number) is int
            and 0 <= self.fd_number < MAX_FDS
            and type(self.expected_dev) is int
            and type(self.expected_inode) is int
            and self.expected_inode > 0
            and type(self.expected_size) is int
            and 68 * self.logical_sector_size <= self.expected_size <= MAX_MEDIA_BYTES
            and self.logical_sector_size in (512, 4096)
            and self.expected_size % self.logical_sector_size == 0,
            "INVALID_EXTERNAL_PIN_GEOMETRY",
        )
        require(
            all(
                isinstance(value, str) and 1 <= len(value) <= 128
                for value in (
                    self.transaction_id,
                    self.vm_uuid,
                    self.challenge,
                    self.device_name,
                    self.serial,
                )
            )
            and isinstance(self.qemu_executable_sha256, str)
            and len(self.qemu_executable_sha256) == 64
            and all(c in "0123456789abcdef" for c in self.qemu_executable_sha256),
            "INVALID_EXTERNAL_PIN_IDENTITY",
        )
        require(
            self.media_path.is_absolute() and self.media_path.name not in (".", ".."),
            "INVALID_EXTERNAL_MEDIA_PATH",
        )


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _process_start_ticks(pid: int) -> int:
    """Read Linux process creation ticks; used with an independently pinned PID."""
    raw = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    marker = raw.rfind(") ")
    require(raw.startswith(f"{pid} (") and marker >= 0, "PROCESS_STAT_INVALID")
    fields = raw[marker + 2 :].split()
    require(len(fields) > 19, "PROCESS_STAT_INVALID")
    ticks = int(fields[19])
    require(ticks > 0, "PROCESS_STAT_INVALID")
    return ticks


def _remote_fd_flags(proc: Path, fd_number: int) -> int:
    """Read actual flags of the *original remote descriptor*, not our reopen."""
    info = (proc / "fdinfo" / str(fd_number)).read_text(encoding="ascii")
    flags = [row.partition(":")[2].strip() for row in info.splitlines() if row.startswith("flags:")]
    require(len(flags) == 1, "REMOTE_FD_FLAGS_MISSING")
    return int(flags[0], 8)


@contextmanager
def borrowed_readonly_proc_fd(
    pid: int,
    fd_number: int,
    path: Path,
    *,
    expected_dev: int,
    expected_inode: int,
    expected_size: int,
    expected_start_ticks: int | None = None,
) -> Iterator[int]:
    """Reopen /proc/PID/fd/N read-only; check remote PID/start/FD *before and after*.

    The reopened handle is a NEW local open-file description, NOT the QEMU
    original. Two samples cannot exclude transient FD swaps or ABA; the
    externally pinned run identity and host isolation are separate controls.
    """
    require(os.name == "posix" and Path("/proc").is_dir(), "PROCFS_UNAVAILABLE")
    require(
        type(pid) is int and pid > 1 and type(fd_number) is int and 0 <= fd_number < MAX_FDS,
        "INVALID_PID_OR_FD",
    )
    require(path.is_absolute() and not path.is_symlink(), "UNSAFE_MEDIA_PATH")
    proc = Path("/proc") / str(pid)
    fd_path = proc / "fd" / str(fd_number)
    try:
        before_ticks = _process_start_ticks(pid)
        if expected_start_ticks is not None:
            require(
                type(expected_start_ticks) is int and expected_start_ticks == before_ticks,
                "PROCESS_START_TICKS_MISMATCH",
            )
        before = path.lstat()
        remote_before = fd_path.stat()
        actual_link = os.readlink(fd_path)
        qemu_flags = _remote_fd_flags(proc, fd_number)
        require((qemu_flags & os.O_ACCMODE) == os.O_RDONLY, "QEMU_FD_NOT_READONLY")
        require(
            stat.S_ISREG(before.st_mode)
            and stat.S_ISREG(remote_before.st_mode)
            and before.st_nlink == remote_before.st_nlink == 1
            and before.st_uid == remote_before.st_uid
            and actual_link == str(path)
            and path.resolve(strict=True) == path
            and _identity(before) == _identity(remote_before)
            and (before.st_dev, before.st_ino, before.st_size)
            == (expected_dev, expected_inode, expected_size),
            "FD_MEDIA_IDENTITY_MISMATCH",
        )
        # /proc/PID/fd/N is necessarily a symlink. Follow only this special
        # procfd after fstat/path checks; revalidate inode/ctime afterward.
        opened = os.open(fd_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            pinned = os.fstat(opened)
            require(
                _identity(pinned) == _identity(before)
                and (fcntl.fcntl(opened, fcntl.F_GETFL) & os.O_ACCMODE) == os.O_RDONLY,
                "PROC_FD_REOPEN_CHANGED",
            )
            yield opened
            require(
                _process_start_ticks(pid) == before_ticks,
                "PROCESS_START_TICKS_CHANGED_DURING_CAPTURE",
            )
            # The originally numbered process FD can be dup2() replaced with
            # O_RDWR on the SAME inode while this reopened local FD stays
            # read-only. Re-read remote fdinfo and reject that substitution.
            final_flags = _remote_fd_flags(proc, fd_number)
            require(
                (final_flags & os.O_ACCMODE) == os.O_RDONLY,
                "REMOTE_FD_NOT_READONLY_AT_COMPLETION",
            )
            require(
                os.readlink(fd_path) == actual_link
                and _identity(os.fstat(opened))
                == _identity(path.lstat())
                == _identity(fd_path.stat())
                == _identity(remote_before)
                == _identity(before),
                "PROC_FD_CHANGED_DURING_CAPTURE",
            )
        finally:
            os.close(opened)
    except (OSError, ValueError, UnicodeError) as exc:
        if isinstance(exc, HostEvidenceRefused):
            raise
        raise HostEvidenceRefused("PROC_FD_OBSERVATION_FAILED") from exc


def require_process_identity(expected: ProcessSeal, measured: ProcessSeal) -> None:
    """Exact PID/start/executable inode+command match, no PID reuse assumption."""
    require(expected == measured, "QEMU_PID_OR_START_TICKS_MISMATCH")


def declared_context(pins: HostPins) -> dict[str, Any]:
    """All caller-supplied VM, nonce and serial strings are CLAIMED only."""
    return {
        "transactionId": {"value": pins.transaction_id, "assurance": "CLAIMED"},
        "vmUuid": {"value": pins.vm_uuid, "assurance": "CLAIMED"},
        "challenge": {"value": pins.challenge, "assurance": "CLAIMED"},
        "serial": {"value": pins.serial, "assurance": "CLAIMED"},
    }


def observe_descriptor(pins: HostPins) -> dict[str, Any]:
    """Measure a real Linux process FD, including an unprivileged fixture PID.

    This function alone does NOT say the process is QEMU or FD is a VM disk.
    """
    with borrowed_readonly_proc_fd(
        pins.process.pid,
        pins.fd_number,
        pins.media_path,
        expected_dev=pins.expected_dev,
        expected_inode=pins.expected_inode,
        expected_size=pins.expected_size,
        expected_start_ticks=pins.process.start_ticks,
    ) as fd:
        st = os.fstat(fd)
        first = os.pread(fd, min(512, st.st_size), 0)
        return {
            "fdNumber": pins.fd_number,
            "fileDev": st.st_dev,
            "fileInode": st.st_ino,
            "fileSizeBytes": st.st_size,
            "fileMtimeNs": st.st_mtime_ns,
            "fileCtimeNs": st.st_ctime_ns,
            "firstSectorSha256": hashlib.sha256(first).hexdigest(),
            "readMethod": "proc-fd-reopened-readonly-pread",
            "assurance": "LOCALLY_MEASURED",
        }


def _raw_gpt_regions(fd: int, gate: Any, sector: int, size: int) -> dict[str, Any]:
    """Use canonical #286 GPT FD parser, not an independent GPT implementation."""
    before = os.fstat(fd)
    snapshot = gate.inspect_gpt_fd(fd, logical_sector_size=sector)
    sectors = size // sector
    primary = gate.read_header(fd, sector, 1, sectors)
    backup = gate.read_header(fd, sector, sectors - 1, sectors)
    require(primary["entries"] == backup["entries"], "GPT_ARRAYS_DIFFER")
    regions: dict[str, Any] = {}
    for name, header, header_region in (
        ("primaryHeader", primary, True),
        ("primaryArray", primary, False),
        ("backupHeader", backup, True),
        ("backupArray", backup, False),
    ):
        offset = (header["current"] if header_region else header["array_lba"]) * sector
        length = sector if header_region else header["count"] * header["entry_size"]
        require(
            0 < length <= MAX_SECTORS_BYTES and offset + length <= size, "GPT_REGION_OUT_OF_BOUNDS"
        )
        data = gate.exact_read(fd, offset, length)
        regions[name] = {
            "offsetBytes": offset,
            "lengthBytes": length,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    require(_identity(before) == _identity(os.fstat(fd)), "GPT_SOURCE_CHANGED_DURING_CAPTURE")
    return {"snapshot": snapshot, "regions": regions, "assurance": "LOCALLY_MEASURED"}


def measure_gpt_from_proc_fd(pins: HostPins, gate: Any) -> dict[str, Any]:
    """Measure genuine GPT bytes only if pinned descriptor is a RAW disk image.

    A QCOW2 descriptor is never parsed as GPT; its RAW backing is a different
    source and cannot establish the guest's effective overlay GPT contents.
    """
    with borrowed_readonly_proc_fd(
        pins.process.pid,
        pins.fd_number,
        pins.media_path,
        expected_dev=pins.expected_dev,
        expected_inode=pins.expected_inode,
        expected_size=pins.expected_size,
        expected_start_ticks=pins.process.start_ticks,
    ) as fd:
        try:
            return _raw_gpt_regions(fd, gate, pins.logical_sector_size, pins.expected_size)
        except (ValueError, OSError, IndexError) as exc:
            raise HostEvidenceRefused("GPT_FD_INVALID_OR_UNSTABLE") from exc


def query_qemu_block_readonly(pins: HostPins, socket_path: Path) -> list[dict[str, Any]]:
    """Only QMP capabilities/query-block; no guest input, no commands to installer.

    Reuses Observer v1 QMP reply parser and allowlisted commands. QMP
    peercred proves SAME local process, never independent VM authority.
    """
    root = socket_path.parent
    try:
        require(
            socket_path.is_absolute()
            and not socket_path.is_symlink()
            and root.resolve(strict=True) == root
            and root.stat().st_uid == pins.process.uid
            and root.stat().st_mode & 0o077 == 0
            and stat.S_ISSOCK(socket_path.lstat().st_mode)
            and socket_path.stat().st_uid == pins.process.uid
            and socket_path.stat().st_mode & 0o077 == 0,
            "QMP_ENDPOINT_UNTRUSTED",
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(3)
            conn.connect(str(socket_path))
            pid, uid, _ = struct.unpack(
                "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            require(
                (pid, uid) == (pins.process.pid, pins.process.uid),
                "QMP_PEER_PROCESS_MISMATCH",
            )
            with conn.makefile("rb") as stream:
                require(isinstance(_read_response(stream).get("QMP"), dict), "QMP_GREETING_INVALID")
                _execute(conn, stream, "qmp_capabilities")
                blocks = _execute(conn, stream, "query-block")
                require(type(blocks) is list, "QMP_BLOCK_LIST_INVALID")
                return blocks
    except (OSError, ValueError, TimeoutError, struct.error) as exc:
        if isinstance(exc, HostEvidenceRefused):
            raise
        raise HostEvidenceRefused("QMP_QUERY_FAILED") from exc


def correlate_qmp_fd(
    pins: HostPins,
    descriptor: dict[str, Any],
    blocks: Any,
) -> dict[str, Any]:
    """Compare caller-provided QMP *claims*; never certify their provenance.

    Only observe_host_qemu's peer-checked socket acquisition may classify
    the act of receiving a QMP reply as LOCALLY_MEASURED. Values inside
    that reply remain QEMU claims, not verified FD/VM identity.
    """
    require(type(blocks) is list, "QMP_MISSING")
    matches = [b for b in blocks if type(b) is dict and b.get("device") == pins.device_name]
    require(len(matches) == 1, "QMP_DEVICE_MISSING_OR_AMBIGUOUS")
    inserted = matches[0].get("inserted")
    require(type(inserted) is dict, "QMP_INSERTED_MISSING")
    if "vmUuid" in matches[0]:
        require(matches[0]["vmUuid"] == pins.vm_uuid, "QMP_VM_UUID_MISMATCH")
    if "serial" in inserted:
        require(inserted["serial"] == pins.serial, "QMP_SERIAL_MISMATCH")
    image = inserted.get("image")
    require(
        type(image) is dict
        and inserted.get("file") == str(pins.media_path)
        and image.get("filename") == str(pins.media_path)
        and image.get("format") == "raw"
        and inserted.get("ro") is True
        and (descriptor["fileDev"], descriptor["fileInode"], descriptor["fileSizeBytes"])
        == (pins.expected_dev, pins.expected_inode, pins.expected_size),
        "QMP_FD_IMAGE_IDENTITY_MISMATCH",
    )
    # A name and image pathname reported by QMP are insufficient to prove
    # serial/UUID or the QEMU backend maps that specific FD. No promotion.
    return {
        "qmpDeviceName": {"value": matches[0]["device"], "assurance": "CLAIMED"},
        "claimedQmpFdConsistency": True,
        "localQmpFdConsistency": False,
        "deviceFdAssociationProven": False,
        "vmDiskBindingProven": False,
        "reason": "QMP_BACKEND_TO_FD_NOT_INDEPENDENTLY_BOUND",
    }


def observe_host_qemu(
    pins: HostPins,
    *,
    gpt_fd_gate: Any,
    qmp_socket: Path | None = None,
    qmp_blocks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Host witness only. Never starts a VM, authorizes use or grants provenance.

    qmp_blocks is a *synthetic test injection*; never a trusted alternative to
    peer-credential-checked query_qemu_block_readonly in operational code.
    """
    require(qmp_blocks is None or qmp_socket is None, "AMBIGUOUS_QMP_ORIGIN")
    initial = process_seal(pins.process.pid)
    require_process_identity(pins.process, initial)
    require(
        _qemu_executable_hash(pins.process.pid) == pins.qemu_executable_sha256,
        "QEMU_EXECUTABLE_HASH_MISMATCH",
    )
    measured_fd = observe_descriptor(pins)
    gpt = measure_gpt_from_proc_fd(pins, gpt_fd_gate)
    require(process_seal(pins.process.pid) == initial, "QEMU_PROCESS_CHANGED")
    if qmp_socket is not None:
        blocks = query_qemu_block_readonly(pins, qmp_socket)
        qmp_provenance = "LOCALLY_MEASURED"
    elif qmp_blocks is not None:
        blocks = qmp_blocks
        qmp_provenance = "CLAIMED"
    else:
        blocks = None
        qmp_provenance = "CLAIMED"
    try:
        mapping = correlate_qmp_fd(pins, measured_fd, blocks)
        if qmp_provenance == "LOCALLY_MEASURED":
            mapping["localQmpFdConsistency"] = mapping["claimedQmpFdConsistency"]
    except (HostEvidenceRefused, KeyError, TypeError):
        mapping = {
            "localQmpFdConsistency": False,
            "deviceFdAssociationProven": False,
            "vmDiskBindingProven": False,
            "reason": "QMP_FD_MAPPING_NOT_DEMONSTRATED",
        }
    require(process_seal(pins.process.pid) == initial, "QEMU_PROCESS_CHANGED")
    # NEVER publish injected QMP as a locally measured observation.
    if qmp_provenance != "LOCALLY_MEASURED":
        mapping["localQmpFdConsistency"] = False
        mapping["qmpDeviceName"] = {"value": pins.device_name, "assurance": "CLAIMED"}
    return {
        "status": "HOST_MEASUREMENT_DIAGNOSTIC_ONLY",
        "classification": "NOT_INDEPENDENT",
        "safetyAssessment": "DIAGNOSTIC_ONLY",
        "process": {
            "pid": {"value": initial.pid, "assurance": "LOCALLY_MEASURED"},
            "startTicks": {"value": initial.start_ticks, "assurance": "LOCALLY_MEASURED"},
            "uid": {"value": initial.uid, "assurance": "LOCALLY_MEASURED"},
            "executableSha256": {
                "value": pins.qemu_executable_sha256,
                "assurance": "LOCALLY_MEASURED",
            },
        },
        "diskFd": measured_fd,
        "gptFd": gpt,
        "declared": declared_context(pins),
        "qmp": mapping,
        "qmpOrigin": "CLAIMED",
        "qmpReplyAcquisition": {
            "assurance": qmp_provenance,
            "transportVerified": qmp_socket is not None,
            "payloadDeviceClaimsAuthenticated": False,
        },
        "associationDecision": "DENY_UNVERIFIED_VM_FD_BINDING",
        "originAuthenticated": False,
        "freshnessAuthenticated": False,
        "replayProtected": False,
        "checkpointImmutable": False,
        "externallyAttested": False,
        "writerAuthorized": False,
        "inputAuthorized": False,
        "diskWritesAuthorized": False,
        "productionInstallationAuthorized": False,
        "productionWriteAuthorized": False,
        "windowsGenuine": False,
        "rollbackProven": False,
        "diskWriterCalled": False,
        "guestInputs": 0,
        "measuredAt": datetime.now(UTC).isoformat(),
    }


def observe_pinned_qcow2_chain(
    pins: HostPins,
    backing: Path,
    workspace: Path,
    safety_lab: Any,
) -> dict[str, Any]:
    """Measure only QCOW2 magic locally, NEVER trust a caller-injected verifier.

    The supplied safety_lab object is deliberately NOT invoked. Until a
    protected controller loads and pins the genuine #267 implementation,
    the backing chain, effective overlay bytes and guest GPT remain unproven.
    In particular, arbitrary verify_chain() methods cannot self-certify.
    """
    require(
        pins.media_path == workspace / "overlay.qcow2"
        and backing == workspace / "base.raw"
        and workspace.is_absolute()
        and workspace.resolve(strict=True) == workspace
        and not workspace.is_symlink()
        and not backing.is_symlink()
        and backing.is_file()
        and backing.stat().st_nlink == 1,
        "UNOWNED_QCOW2_BACKING",
    )
    with borrowed_readonly_proc_fd(
        pins.process.pid,
        pins.fd_number,
        pins.media_path,
        expected_dev=pins.expected_dev,
        expected_inode=pins.expected_inode,
        expected_size=pins.expected_size,
        expected_start_ticks=pins.process.start_ticks,
    ) as fd:
        before = _identity(os.fstat(fd))
        magic = os.pread(fd, 4, 0)
        require(magic == bytes.fromhex("514649fb"), "QCOW2_HEADER_INVALID")
        require(_identity(os.fstat(fd)) == before, "QCOW2_FD_CHANGED")
        return {
            "qcow2HeaderMagic": {
                "valueHex": magic.hex(),
                "assurance": "LOCALLY_MEASURED",
                "scope": "FOUR_MAGIC_BYTES_ONLY",
            },
            "chain": None,
            "assurance": "CLAIMED",
            "backingChainVerified": False,
            "verifierAuthenticated": False,
            "overlayEffectiveContentVerified": False,
            "diskReadFromOverlayAsRaw": False,
            "guestEffectiveGptProven": False,
            "vmDiskBindingProven": False,
            "originAuthenticated": False,
            "reason": "QCOW2_VERIFIER_ORIGIN_NOT_PROVEN",
        }
