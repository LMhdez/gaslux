"""Linux HOST transport peer/descriptor witness; never authenticates a guest.

Witnesses only a local AF_UNIX stream socket and its SO_PEERCRED peer against
externally supplied reference pins at TWO instants. No socket I/O, QEMU, guest
operations, disk writes or operational authorization. Pins are merely claims.
"""

from __future__ import annotations

import hashlib
import os
import re
import select
import socket
import stat
import struct
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .host_fd_boundary import ProcessSeal

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_CLAIMS = frozenset(
    {
        "sessionId",
        "transactionId",
        "hostVmId",
        "diskIdentitySha256",
        "collectorSha256",
        "challenge",
        "provenance",
    }
)


class TransportBoundaryRefused(ValueError):
    """No local evidence, contradictory identity, substituted FD: DENY."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise TransportBoundaryRefused(reason)


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


@dataclass(frozen=True)
class LocalSessionPins:
    """Untrusted caller references; neither their origin nor approval is verified."""

    process: ProcessSeal
    transport_dev: int
    transport_inode: int
    session_id: str
    transaction_id: str
    host_vm_id: str
    disk_identity_sha256: str
    collector_sha256: str
    challenge: str

    def __post_init__(self) -> None:
        proc = self.process
        _require(
            type(proc) is ProcessSeal
            and all(
                type(value) is int and value >= minimum
                for value, minimum in (
                    (proc.pid, 2),
                    (proc.uid, 0),
                    (proc.start_ticks, 1),
                    (proc.executable_dev, 0),
                    (proc.executable_ino, 1),
                )
            )
            and type(proc.command_sha256) is str
            and _HEX64.fullmatch(proc.command_sha256) is not None,
            "INVALID_EXTERNAL_PROCESS_PINS",
        )
        _require(
            type(self.transport_dev) is int
            and self.transport_dev >= 0
            and type(self.transport_inode) is int
            and self.transport_inode > 0,
            "INVALID_EXTERNAL_TRANSPORT_PINS",
        )
        _require(
            _canonical_uuid(self.session_id)
            and _canonical_uuid(self.transaction_id)
            and type(self.host_vm_id) is str
            and 1 <= len(self.host_vm_id) <= 128
            and all(
                type(v) is str and _HEX64.fullmatch(v) is not None
                for v in (
                    self.disk_identity_sha256,
                    self.collector_sha256,
                    self.challenge,
                )
            ),
            "INVALID_EXTERNAL_SESSION_CLAIMS",
        )


def _process_snapshot(pid: int) -> ProcessSeal:
    """Read a Linux process fingerprint, NOT a VM or guest attestation."""
    root = Path("/proc") / str(pid)
    try:
        raw = (root / "stat").read_text(encoding="ascii")
        marker = raw.rfind(") ")
        _require(raw.startswith(f"{pid} (") and marker >= 0, "PROCESS_STAT_INVALID")
        fields = raw[marker + 2 :].split()
        _require(len(fields) > 19, "PROCESS_STAT_INVALID")
        cmdline = (root / "cmdline").read_bytes()
        _require(bool(cmdline), "PROCESS_COMMAND_MISSING")
        executable = (root / "exe").stat()
        return ProcessSeal(
            pid,
            root.stat().st_uid,
            int(fields[19]),
            hashlib.sha256(cmdline).hexdigest(),
            executable.st_dev,
            executable.st_ino,
        )
    except (OSError, ValueError, UnicodeError, IndexError) as exc:
        raise TransportBoundaryRefused("PROCESS_IDENTITY_UNAVAILABLE") from exc


def _kernel_sample(conn: socket.socket) -> tuple[tuple[int, int], ProcessSeal, tuple[int, int]]:
    """Only fstat/getsockopt/procfs/poll: never read or write guest data."""
    _require(
        os.name == "posix" and hasattr(socket, "SO_PEERCRED") and hasattr(socket, "SO_DOMAIN"),
        "KERNEL_PEER_UNAVAILABLE",
    )
    try:
        fd = conn.fileno()
        _require(fd >= 0, "TRANSPORT_DESCRIPTOR_CLOSED")
        st = os.fstat(fd)
        _require(stat.S_ISSOCK(st.st_mode), "TRANSPORT_NOT_SOCKET")
        domain = conn.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN)
        kind = conn.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        listening = conn.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        _require(
            domain == socket.AF_UNIX and kind == socket.SOCK_STREAM and listening == 0,
            "TRANSPORT_NOT_CONNECTED_UNIX_STREAM",
        )
        poller = select.poll()
        poller.register(fd, select.POLLHUP | select.POLLERR | select.POLLNVAL)
        abnormal = select.POLLHUP | select.POLLERR | select.POLLNVAL
        _require(
            not any(events & abnormal for _, events in poller.poll(0)),
            "TRANSPORT_DISCONNECTED",
        )
        cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", cred)
        _require(pid > 1 and uid >= 0, "PEER_CREDENTIALS_INVALID")
        measured = _process_snapshot(pid)
        _require(measured.uid == uid, "KERNEL_PEER_UID_CHANGED")
        return (st.st_dev, st.st_ino), measured, (pid, uid)
    except (OSError, ValueError, struct.error) as exc:
        if isinstance(exc, TransportBoundaryRefused):
            raise
        raise TransportBoundaryRefused("KERNEL_PEER_MEASUREMENT_FAILED") from exc


class LocalTransportWitness:
    """Ephemeral one-shot same-host witness, never a guest or replay authority.

    Two snapshots cannot exclude ABA, interim exec, FD swaps or a hostile host.
    The per-object used bit is NOT a persistent ledger across process restarts.
    """

    def __init__(self, conn: socket.socket, pins: LocalSessionPins):
        _require(type(pins) is LocalSessionPins, "INVALID_UNTRUSTED_PINS")
        self._pins = pins
        self._conn = conn
        self._lock = threading.Lock()
        self._spent = False
        self._first = self._checked_sample()

    def _checked_sample(self) -> tuple[tuple[int, int], ProcessSeal, tuple[int, int]]:
        result = _kernel_sample(self._conn)
        _require(
            result[0] == (self._pins.transport_dev, self._pins.transport_inode),
            "TRANSPORT_FD_IDENTITY_MISMATCH",
        )
        _require(result[1] == self._pins.process, "REMOTE_PROCESS_IDENTITY_MISMATCH")
        _require(
            result[2] == (self._pins.process.pid, self._pins.process.uid),
            "SO_PEERCRED_PROCESS_MISMATCH",
        )
        return result

    def finish(self, untrusted_claims: dict[str, Any]) -> dict[str, Any]:
        """Publish local observations only after the second sample; always deny."""
        with self._lock:
            _require(not self._spent, "SESSION_ALREADY_USED_LOCAL_ONLY")
            self._spent = True
            _require(
                type(untrusted_claims) is dict and set(untrusted_claims) == _CLAIMS,
                "UNTRUSTED_CLAIMS_MISSING_OR_EXTRA",
            )
            expected = {
                "sessionId": self._pins.session_id,
                "transactionId": self._pins.transaction_id,
                "hostVmId": self._pins.host_vm_id,
                "diskIdentitySha256": self._pins.disk_identity_sha256,
                "collectorSha256": self._pins.collector_sha256,
                "challenge": self._pins.challenge,
                "provenance": "CLAIMED",
            }
            _require(
                all(
                    type(untrusted_claims[key]) is str and untrusted_claims[key] == value
                    for key, value in expected.items()
                ),
                "UNTRUSTED_CONTEXT_MISMATCH",
            )
            after = self._checked_sample()
            _require(after == self._first, "TRANSPORT_OR_PEER_CHANGED_DURING_OBSERVATION")
            return {
                "status": "BLOCKED_TRUST_ROOT",
                "classification": "NOT_INDEPENDENT",
                "safetyAssessment": "DIAGNOSTIC_ONLY",
                "localKernelPeerObserved": True,
                "localKernelPeerMatchesSuppliedPins": True,
                "transportDescriptor": {
                    "dev": after[0][0],
                    "inode": after[0][1],
                    "assurance": "LOCALLY_MEASURED",
                },
                "peer": {
                    "pid": after[1].pid,
                    "uid": after[1].uid,
                    "startTicks": after[1].start_ticks,
                    "assurance": "LOCALLY_MEASURED",
                },
                "sessionContext": {
                    key: {"value": value, "assurance": "CLAIMED"}
                    for key, value in expected.items()
                },
                "guestChannelAuthenticated": False,
                "guestProcessAuthenticated": False,
                "anacondaProcessVerified": False,
                "collectorAuthenticated": False,
                "qemuVmIdentityAuthenticated": False,
                "diskBackendFdAssociationProven": False,
                "externallyAttested": False,
                "freshnessAuthenticated": False,
                "replayProtected": False,
                "persistentLedgerVerified": False,
                "operationalApprovalVerified": False,
                "inputAuthorized": False,
                "diskWritesAuthorized": False,
                "productionInstallationAuthorized": False,
                "productionWriteAuthorized": False,
                "installationAuthorized": False,
                "guestCommandChannelAuthorized": False,
                "windowsRecoveryVerified": False,
                "rollbackProven": False,
            }
