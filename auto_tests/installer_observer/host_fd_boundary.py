"""Minimal Observer HOST-only process/QMP primitives.

Extracted from experimental #259's lab_identity and executable hash reader.
No state machine, lab authority, QEMU startup, guest control or disk writer.
This module provides local measurements only; nothing it returns is an
externally authenticated permission, VM/FD binding or replay proof.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class HostBoundaryRefused(ValueError):
    """Fail closed for an unavailable or inconsistent local identity/QMP read."""


@dataclass(frozen=True)
class ProcessSeal:
    pid: int
    uid: int
    start_ticks: int
    command_sha256: str
    executable_dev: int
    executable_ino: int


def process_seal(pid: int) -> ProcessSeal:
    """Local QEMU executable fingerprint, NOT VM or operational authority."""
    if os.name != "posix" or type(pid) is not int or pid <= 1:
        raise HostBoundaryRefused("QEMU_PID_INVALID")
    root = Path("/proc") / str(pid)
    try:
        raw = (root / "stat").read_text(encoding="ascii")
        marker = raw.rfind(") ")
        fields = raw[marker + 2 :].split()
        if not raw.startswith(f"{pid} (") or marker < 0 or len(fields) < 20:
            raise HostBoundaryRefused("PROCESS_STAT_INVALID")
        command = (root / "cmdline").read_bytes()
        exe_path = Path(os.readlink(root / "exe"))
        executable = (root / "exe").stat()
        owner = root.stat().st_uid
        if not command or "qemu-system-" not in exe_path.name:
            raise HostBoundaryRefused("UNEXPECTED_QEMU_EXECUTABLE")
        ticks = int(fields[19])
        if ticks <= 0:
            raise HostBoundaryRefused("PROCESS_START_TICKS_INVALID")
        return ProcessSeal(
            pid,
            owner,
            ticks,
            hashlib.sha256(command).hexdigest(),
            executable.st_dev,
            executable.st_ino,
        )
    except (OSError, ValueError, UnicodeError, IndexError) as exc:
        raise HostBoundaryRefused("PROCESS_SEAL_UNAVAILABLE") from exc


def _read_response(stream: Any) -> dict:
    """Bounded QMP response parser, no authority from untrusted JSON."""
    for _ in range(20):
        raw = stream.readline(262145)
        if not raw or len(raw) > 262144:
            raise HostBoundaryRefused("QMP_RESPONSE_TRUNCATED_OR_OVERSIZED")
        try:
            obj = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise HostBoundaryRefused("QMP_RESPONSE_INVALID_JSON") from exc
        if not isinstance(obj, dict):
            raise HostBoundaryRefused("QMP_RESPONSE_NOT_OBJECT")
        if "event" in obj:
            continue
        return obj
    raise HostBoundaryRefused("QMP_UNBOUNDED_EVENTS")


def _execute(sock: socket.socket, stream: Any, name: str) -> Any:
    """Read-only query-block acquisition; never sends guest or QEMU control."""
    if name not in ("qmp_capabilities", "query-block"):
        raise HostBoundaryRefused("QMP_COMMAND_NOT_ALLOWLISTED")
    sock.sendall((json.dumps({"execute": name}) + "\r\n").encode("ascii"))
    reply = _read_response(stream)
    if set(reply) != {"return"}:
        raise HostBoundaryRefused("QMP_REPLY_REJECTED")
    return reply["return"]


def _qemu_executable_hash(pid: int) -> str:
    """SHA-256 genuine /proc/PID/exe content, not a signed executable attestation."""
    if type(pid) is not int or pid <= 1:
        raise HostBoundaryRefused("QEMU_PID_INVALID")
    try:
        fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            digest = hashlib.sha256()
            while True:
                value = os.read(fd, 1024 * 1024)
                if not value:
                    break
                digest.update(value)
            return digest.hexdigest()
        finally:
            os.close(fd)
    except OSError as exc:
        raise HostBoundaryRefused("QEMU_EXECUTABLE_READ_UNAVAILABLE") from exc
