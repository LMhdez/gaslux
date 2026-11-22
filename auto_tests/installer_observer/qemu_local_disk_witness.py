"""Real Linux HOST QEMU→open regular-file FD observation; no guest trust or writer.

This module *never starts a VM*. It is usable only on a pre-existing QEMU
started by an isolated supervisor. POSITIVE means QEMU has a locally observed
read-only FD to a pinned regular file, never a signed VM, guest, or boot proof.
"""

from __future__ import annotations

import os
import select
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .host_fd_boundary import ProcessSeal, process_seal
from .host_qemu_fd_evidence import (
    HostEvidenceRefused,
    HostPins,
    _remote_fd_flags,
    borrowed_readonly_proc_fd,
    query_qemu_block_readonly,
)

MAX_FDS = 4096
MAX_IMAGE_BYTES = 512 * 1024 * 1024
ALLOWED_FORMATS = frozenset({"raw", "qcow2"})


class QemuDiskRefused(ValueError):
    """Explicit failure before publishing any QEMU-to-disk local evidence."""


def _require(value: bool, code: str) -> None:
    if not value:
        raise QemuDiskRefused(code)


def _file_identity(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _local_file(path: Path, workspace: Path, size: int) -> os.stat_result:
    _require(
        isinstance(path, Path)
        and path.is_absolute()
        and path.parent == workspace
        and not path.is_symlink(),
        "UNOWNED_OR_AMBIGUOUS_IMAGE_PATH",
    )
    try:
        st = path.lstat()
        _require(
            stat.S_ISREG(st.st_mode)
            and st.st_nlink == 1
            and st.st_uid == os.getuid()
            and st.st_size == size,
            "IMAGE_IDENTITY_OR_OWNERSHIP_CHANGED",
        )
        return st
    except OSError as exc:
        raise QemuDiskRefused("IMAGE_STAT_UNAVAILABLE") from exc


@dataclass(frozen=True)
class QemuDiskPins:
    """Reference identity supplied by supervisor; reference origin remains CLAIMED."""

    process: ProcessSeal
    media_path: Path
    workspace: Path
    qmp_socket: Path
    media_dev: int
    media_inode: int
    media_size: int
    disk_format: str
    qmp_device: str
    transaction_id: str
    vm_label: str

    def __post_init__(self) -> None:
        _require(type(self.process) is ProcessSeal, "INVALID_PROCESS_REFERENCE")
        _require(
            isinstance(self.workspace, Path)
            and self.workspace.is_absolute()
            and isinstance(self.media_path, Path)
            and self.media_path.parent == self.workspace
            and isinstance(self.qmp_socket, Path)
            and self.qmp_socket.parent == self.workspace
            and type(self.media_dev) is int
            and self.media_dev >= 0
            and type(self.media_inode) is int
            and self.media_inode > 0
            and type(self.media_size) is int
            and 68 * 512 <= self.media_size <= MAX_IMAGE_BYTES
            and self.disk_format in ALLOWED_FORMATS
            and type(self.qmp_device) is str
            and 1 <= len(self.qmp_device) <= 128
            and type(self.transaction_id) is str
            and 1 <= len(self.transaction_id) <= 128
            and type(self.vm_label) is str
            and 1 <= len(self.vm_label) <= 128,
            "INVALID_UNTRUSTED_REFERENCE",
        )


class QemuLocalDiskWitness:
    """Two-sample Linux procfs/QMP diagnostic, with a pidfd retained throughout.

    The pinned names, transaction, QMP reply contents and local machine are
    NOT independently authenticated. A pidfd rules out a PID replacement
    between samples, but does not freeze FD tables or prevent transient ABA.
    """

    def __init__(self, pins: QemuDiskPins):
        _require(type(self) is QemuLocalDiskWitness, "OVERRIDDEN_WITNESS_UNTRUSTED")
        _require(type(pins) is QemuDiskPins, "UNTRUSTED_REFERENCE_OBJECT")
        _require(hasattr(os, "pidfd_open"), "PIDFD_UNAVAILABLE")
        self._pins = pins
        self._closed = False
        self._completed = False
        self._pidfd = -1
        try:
            self._pidfd = os.pidfd_open(pins.process.pid, 0)
            self._initial = self._snapshot()
        except (OSError, ValueError, HostEvidenceRefused) as exc:
            self.close()
            if isinstance(exc, QemuDiskRefused):
                raise
            raise QemuDiskRefused("INITIAL_QEMU_DISK_SAMPLE_REFUSED") from exc
        except QemuDiskRefused:
            self.close()
            raise

    def __enter__(self) -> QemuLocalDiskWitness:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._pidfd >= 0:
            os.close(self._pidfd)
            self._pidfd = -1
        self._closed = True

    def _alive(self) -> None:
        _require(not self._closed and self._pidfd >= 0, "PIDFD_ALREADY_CLOSED")
        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        _require(not poller.poll(0), "QEMU_PROCESS_EXITED")

    def _remote_file_fd(self, expected: os.stat_result) -> int:
        proc = Path("/proc") / str(self._pins.process.pid)
        matches: list[int] = []
        try:
            for entry in (proc / "fd").iterdir():
                if not entry.name.isdecimal():
                    continue
                value = int(entry.name)
                if value >= MAX_FDS:
                    raise QemuDiskRefused("UNBOUNDED_QEMU_FD_TABLE")
                try:
                    if os.readlink(entry) == str(self._pins.media_path):
                        flags = _remote_fd_flags(proc, value)
                        _require(
                            (flags & os.O_ACCMODE) == os.O_RDONLY
                            and not (flags & getattr(os, "O_PATH", 0)),
                            "QEMU_IMAGE_FD_NOT_READONLY",
                        )
                        _require(
                            _file_identity(entry.stat()) == _file_identity(expected),
                            "REMOTE_FILE_IDENTITY_MISMATCH",
                        )
                        matches.append(value)
                except FileNotFoundError as exc:
                    raise QemuDiskRefused("REMOTE_FD_DISAPPEARED") from exc
            _require(len(matches) == 1, "QEMU_IMAGE_FD_NOT_UNIQUE_OR_MISSING")
            return matches[0]
        except OSError as exc:
            raise QemuDiskRefused("QEMU_FD_ENUMERATION_FAILED") from exc

    def _qmp(self) -> dict[str, str]:
        p = self._pins
        host_pin = HostPins(
            p.process,
            "0" * 64,
            p.transaction_id,
            p.vm_label,
            "claim-only",
            p.qmp_device,
            "claim-only",
            self._fd_number,
            p.media_path,
            p.media_dev,
            p.media_inode,
            p.media_size,
        )
        try:
            blocks = query_qemu_block_readonly(host_pin, p.qmp_socket)
        except (HostEvidenceRefused, OSError, ValueError) as exc:
            raise QemuDiskRefused("QMP_KERNEL_PEER_OR_REPLY_INVALID") from exc
        _require(type(blocks) is list, "QMP_BLOCK_GRAPH_INVALID")
        matches = [b for b in blocks if type(b) is dict and b.get("device") == p.qmp_device]
        _require(len(matches) == 1, "QMP_BLOCK_DEVICE_MISSING_OR_DUPLICATE")
        inserted = matches[0].get("inserted")
        _require(type(inserted) is dict and inserted.get("ro") is True, "QMP_DISK_NOT_READONLY")
        image = inserted.get("image")
        _require(type(image) is dict, "QMP_IMAGE_CLAIM_MISSING")
        _require(
            inserted.get("file") == str(p.media_path)
            and image.get("filename") == str(p.media_path)
            and image.get("format") == p.disk_format,
            "QMP_BLOCK_PATH_OR_FORMAT_DIVERGED",
        )
        return {
            "device": p.qmp_device,
            "file": str(p.media_path),
            "format": p.disk_format,
        }

    def _snapshot(self) -> dict[str, Any]:
        p = self._pins
        self._alive()
        _require(process_seal(p.process.pid) == p.process, "PROCESS_SEAL_DIFFERENT")
        try:
            workspace = p.workspace.lstat()
            _require(
                p.workspace.resolve(strict=True) == p.workspace
                and not p.workspace.is_symlink()
                and stat.S_ISDIR(workspace.st_mode)
                and workspace.st_uid == p.process.uid == os.getuid()
                and workspace.st_mode & 0o077 == 0,
                "WORKSPACE_NOT_PRIVATE",
            )
        except OSError as exc:
            raise QemuDiskRefused("WORKSPACE_STAT_UNAVAILABLE") from exc
        st = _local_file(p.media_path, p.workspace, p.media_size)
        _require(
            (st.st_dev, st.st_ino) == (p.media_dev, p.media_inode),
            "SELECTED_IMAGE_IDENTITY_DIVERGED",
        )
        self._fd_number = self._remote_file_fd(st)
        host_pin = HostPins(
            p.process,
            "0" * 64,
            p.transaction_id,
            p.vm_label,
            "claim-only",
            p.qmp_device,
            "claim-only",
            self._fd_number,
            p.media_path,
            p.media_dev,
            p.media_inode,
            p.media_size,
        )
        with borrowed_readonly_proc_fd(
            p.process.pid,
            self._fd_number,
            p.media_path,
            expected_dev=p.media_dev,
            expected_inode=p.media_inode,
            expected_size=p.media_size,
            expected_start_ticks=p.process.start_ticks,
        ) as borrowed:
            _require(
                _file_identity(os.fstat(borrowed)) == _file_identity(st),
                "BORROWED_QEMU_FD_DIFFERENT",
            )
        qmp = self._qmp()
        _require(process_seal(p.process.pid) == p.process, "QEMU_IDENTITY_CHANGED")
        self._alive()
        return {
            "process": p.process,
            "media": _file_identity(st),
            "fd": self._fd_number,
            "qmp": qmp,
        }

    def finish(self) -> dict[str, Any]:
        """Return HOST-only proof after second real sample; never grant writes."""
        _require(not self._completed, "LOCAL_OBSERVATION_ALREADY_USED")
        self._completed = True
        latest = self._snapshot()
        _require(latest == self._initial, "QEMU_FD_OR_QMP_CHANGED_BETWEEN_SAMPLES")
        pins = self._pins
        return {
            "status": "BLOCKED_TRUST_ROOT",
            "classification": "NOT_INDEPENDENT",
            "safetyAssessment": "DIAGNOSTIC_ONLY",
            "localQemuProcessIdentityMeasured": True,
            "pidfdHeldDuringObservation": True,
            "localQemuReadonlyDiskFdOpenProven": True,
            "localQmpPeerProcessMatched": True,
            "qmpReadOnlyDeviceClaimConsistent": True,
            "process": {
                "pid": {"value": pins.process.pid, "assurance": "LOCALLY_MEASURED"},
                "startTicks": {
                    "value": pins.process.start_ticks,
                    "assurance": "LOCALLY_MEASURED",
                },
            },
            "disk": {
                "dev": {"value": pins.media_dev, "assurance": "LOCALLY_MEASURED"},
                "inode": {"value": pins.media_inode, "assurance": "LOCALLY_MEASURED"},
                "sizeBytes": {"value": pins.media_size, "assurance": "LOCALLY_MEASURED"},
                "fdNumber": latest["fd"],
                "format": {"value": pins.disk_format, "assurance": "CLAIMED"},
            },
            "qmpReply": {
                "acquisition": "LOCALLY_MEASURED",
                "payload": {**latest["qmp"], "assurance": "CLAIMED"},
            },
            "transactionId": {"value": pins.transaction_id, "assurance": "CLAIMED"},
            "vmLabel": {"value": pins.vm_label, "assurance": "CLAIMED"},
            "qemuBackendToFdBindingIndependentlyProven": False,
            "qcow2BackingChainAuthenticated": False,
            "guestEffectiveGptAuthenticated": False,
            "guestChannelAuthenticated": False,
            "anacondaProcessVerified": False,
            "diskWriteAuthorized": False,
            "inputAuthorized": False,
            "productionInstallationAuthorized": False,
            "productionWriteAuthorized": False,
            "rollbackProven": False,
            "stable": False,
            "externallyAttested": False,
            "freshnessAuthenticated": False,
            "replayProtected": False,
        }

    def assert_stopped(self) -> dict[str, bool]:
        """Must be called after supervisor has reaped QEMU; no process kill here."""
        _require(self._completed, "OBSERVATION_NOT_COMPLETED")
        _require(not self._closed and self._pidfd >= 0, "PIDFD_ALREADY_CLOSED")
        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        _require(bool(poller.poll(0)), "QEMU_CLEANUP_NOT_CONFIRMED")
        _require(
            not (Path("/proc") / str(self._pins.process.pid)).exists(),
            "QEMU_PID_NOT_REAPED",
        )
        return {
            "qemuPidfdExited": True,
            "qemuProcessReaped": True,
            "guestAuthenticated": False,
            "windowsRollbackProven": False,
        }
