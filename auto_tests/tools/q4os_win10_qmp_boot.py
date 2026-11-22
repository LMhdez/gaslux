#!/usr/bin/env python3
"""One-shot UEFI Windows DVD prompt controller for a disposable QEMU lab.

Reads OVMF's serial-console text and injects *one* key through QMP. It never
runs Calamares, changes boot settings, or claims Windows Setup without a guest
witness. All observations and output are bounded and redact free-form text.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import stat
import time
from pathlib import Path

PROMPT = b"press any key to boot from cd or dvd"
SHELL = (b"uefi interactive shell", b"shell> ", b'"efi internal shell"')
BOOT_TIMEOUT = b"bdsdxe: failed to start"
ANSI = re.compile(rb"\x1b\[[0-9;=?]*[ -/]*[@-~]")
MAX_SERIAL_BYTES = 512 * 1024
DISK_GROWTH_BYTES = 4 * 1024 * 1024
# Finite, disclosure-safe diagnostic output only. This CLI has NO authority
# to create a supervisor session or send keyboard input by itself.
BOOT_REASON_CODES = frozenset(
    {
        "qmp_supervisor_required",
        "qmp_socket_unavailable",
        "invalid_qmp_greeting",
        "invalid_qmp_version",
        "qmp_send_key_failed",
        "qmp_is_not_socket",
        "nonprivate_lab_directory",
        "unsafe_serial_path",
        "unsafe_disk_path",
        "dvd_prompt_not_detected",
        "uefi_shell_detected",
        "uefi_boot_timeout",
        "no_disk_progress_after_dvd_key",
        "QEMU_STARTUP_UNCLASSIFIED",
    }
)


def _safe_reason(exc: Exception) -> str:
    value = str(exc) if isinstance(exc, BootRefusal) else ""
    return value if value in BOOT_REASON_CODES else "QEMU_STARTUP_UNCLASSIFIED"


class BootRefusal(RuntimeError):
    """Safety refusal before/during guest Windows DVD boot."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise BootRefusal(reason)


def _private(path: Path, kind: str) -> None:
    require(path.is_absolute() and not path.is_symlink(), "unsafe_" + kind + "_path")
    st = path.lstat()
    require(st.st_uid == os.getuid(), "foreign_" + kind)
    if kind == "qmp":
        require(stat.S_ISSOCK(st.st_mode), "qmp_is_not_socket")
    else:
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "unsafe_" + kind)


class Qmp:
    def __init__(self, path: Path, *, negotiate: bool = False):
        """Connect-only. No public autonomous QMP negotiation or commands."""
        require(not negotiate, "qmp_supervisor_required")
        _private(path, "qmp")
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(2)
        self.stream = None
        self._bound_session = None
        try:
            self.socket.connect(str(path))
            self.stream = self.socket.makefile("rb")
        except (OSError, ValueError, KeyError, BootRefusal):
            self.close()
            raise

    def bind_verified_session(self, session) -> None:
        # This is a type-bound ownership witness, not an arbitrary callback.
        # Verification checks the kernel socket peer, pidfd-owning process
        # and original inode on every QMP operation.
        from q4os_win10_qmp_supervisor import _BoundQmpSession

        require(type(session) is _BoundQmpSession, "qmp_supervisor_required")
        require(session.channel is self, "qmp_supervisor_required")
        session.verify()
        self._bound_session = session

    def _require_authenticated(self) -> None:
        # Never trust a caller's injected verify() callback or mutated member.
        from q4os_win10_qmp_supervisor import _BoundQmpSession

        session = self._bound_session
        require(
            type(session) is _BoundQmpSession and session.channel is self,
            "qmp_supervisor_required",
        )
        session.verify()

    def negotiate_protocol(self) -> None:
        """Require a verified process-bound session before any QMP command."""
        self._require_authenticated()
        greeting = self._read()
        require(isinstance(greeting.get("QMP"), dict), "invalid_qmp_greeting")
        version = greeting["QMP"].get("version")
        require(isinstance(version, dict), "invalid_qmp_version")
        self.command("qmp_capabilities", "capabilities")
        status = self.command("query-status", "status")
        require(status.get("status") == "running", "qemu_is_not_running")

    def _read(self) -> dict:
        raw = self.stream.readline(128 * 1024)
        require(bool(raw) and len(raw) < 128 * 1024, "qmp_reply_missing_or_oversized")
        result = json.loads(raw)
        require(isinstance(result, dict), "invalid_qmp_message")
        return result

    def command(self, operation: str, identifier: str, arguments: dict | None = None) -> dict:
        self._require_authenticated()
        request: dict = {"execute": operation, "id": "gaslux-" + identifier}
        if arguments is not None:
            request["arguments"] = arguments
        self.socket.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\r\n")
        for _ in range(64):
            response = self._read()
            if "event" in response:
                continue
            require(response.get("id") == request["id"], "qmp_reply_id_mismatch")
            require("error" not in response, "qmp_command_refused_" + operation)
            result = response.get("return")
            require(isinstance(result, dict), "qmp_invalid_command_reply")
            return result
        raise BootRefusal("qmp_event_flood")

    def send_key_once(self) -> None:
        self.command(
            "send-key",
            "dvd-key",
            {"keys": [{"type": "qcode", "data": "ret"}], "hold-time": 120},
        )

    def close(self) -> None:
        try:
            if self.stream is not None:
                self.stream.close()
        finally:
            self.socket.close()


def _serial_text(path: Path) -> bytes:
    if not path.exists():
        return b""
    _private(path, "serial")
    with path.open("rb") as source:
        data = source.read(MAX_SERIAL_BYTES + 1)
    require(len(data) <= MAX_SERIAL_BYTES, "serial_log_too_large")
    return ANSI.sub(b"", data).lower()


def _boot_error(serial: bytes) -> str | None:
    if any(marker in serial for marker in SHELL):
        return "uefi_shell_detected"
    if BOOT_TIMEOUT in serial and b"time out" in serial:
        return "uefi_boot_timeout"
    return None


def supervise(
    socket_path: Path,
    serial_path: Path,
    disk_path: Path,
    *,
    connect_seconds: float = 15,
    prompt_seconds: float = 90,
    progress_seconds: float = 600,
    tick: float = 0.05,
    qmp_session=None,
    qmp_channel: Qmp | None = None,
    process_guard=None,
) -> dict:
    """Require prompt, exactly one QMP key acknowledgement, then QCOW2 activity.

    QCOW2 growth is an operational progress signal, NOT proof of Windows Setup.
    Only the later NTFS/ESP/first-logon verification can establish that result.
    """
    # Reject legacy clients, injected channels and untrusted callbacks
    # BEFORE touching disk or socket paths and without sending any QMP.
    from q4os_win10_qmp_supervisor import _BoundQmpSession

    require(
        qmp_channel is None and process_guard is None and type(qmp_session) is _BoundQmpSession,
        "qmp_supervisor_required",
    )
    qmp_session.verify()
    qmp = qmp_session.channel
    require(qmp._bound_session is qmp_session, "qmp_supervisor_required")
    parent = socket_path.parent
    require(
        parent == serial_path.parent == disk_path.parent
        and parent.is_absolute()
        and not parent.is_symlink()
        and parent.stat().st_uid == os.getuid()
        and parent.stat().st_mode & 0o077 == 0,
        "nonprivate_lab_directory",
    )
    _private(disk_path, "disk")
    # connect_seconds remains for API compatibility but no auto-connect occurs.
    _ = connect_seconds
    try:
        deadline = time.monotonic() + prompt_seconds
        while time.monotonic() < deadline:
            qmp_session.verify()
            serial = _serial_text(serial_path)
            error = _boot_error(serial)
            require(error is None, error or "unknown_boot_error")
            if PROMPT in serial:
                # Never issue another key during Windows Setup or later reboots.
                size_before_key = disk_path.stat().st_size
                qmp_session.verify()
                try:
                    qmp.send_key_once()
                except (OSError, ValueError, BootRefusal) as exc:
                    raise BootRefusal("qmp_send_key_failed") from exc
                deadline_progress = time.monotonic() + progress_seconds
                while time.monotonic() < deadline_progress:
                    qmp_session.verify()
                    serial = _serial_text(serial_path)
                    error = _boot_error(serial)
                    require(error is None, error or "unknown_boot_error")
                    if disk_path.stat().st_size >= size_before_key + DISK_GROWTH_BYTES:
                        return {
                            "decision": "dvd_key_sent_once",
                            "qmpGreetingVerified": True,
                            "qmpSendKeyAcknowledged": True,
                            "serialPromptObserved": True,
                            "qcow2GrowthObserved": True,
                            "windowsSetupVerified": False,
                            "calamaresExecuted": False,
                            "installationAuthorized": False,
                        }
                    time.sleep(max(tick, 0.01))
                raise BootRefusal("no_disk_progress_after_dvd_key")
            time.sleep(max(tick, 0.01))
        raise BootRefusal("dvd_prompt_not_detected")
    finally:
        qmp.close()




def _write_report_exclusive(path: Path, qmp_path: Path, report: dict) -> bool:
    """Write a bounded report only to a freshly created, owned regular inode.

    Pin every directory component without following symlinks. Never re-open
    the created file by pathname; never unlink foreign or partial reports.
    Any I/O or close failure is a fixed denial, not a traceback or success.
    """
    dirfd = None
    fd = None
    try:
        if not (
            path.is_absolute()
            and qmp_path.is_absolute()
            and path.parent == qmp_path.parent
            and path.name not in ("", ".", "..")
        ):
            return False
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        dirfd = os.open("/", flags)
        for part in path.parent.parts[1:]:
            if part in ("", ".", ".."):
                return False
            next_dirfd = os.open(part, flags, dir_fd=dirfd)
            os.close(dirfd)
            dirfd = next_dirfd
        directory = os.fstat(dirfd)
        observed = path.parent.lstat()
        if not (
            stat.S_ISDIR(directory.st_mode)
            and directory.st_uid == os.getuid()
            and not directory.st_mode & 0o077
            and (directory.st_dev, directory.st_ino)
            == (observed.st_dev, observed.st_ino)
            and stat.S_ISDIR(observed.st_mode)
        ):
            return False
        data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(data) > 4096:
            return False
        fd = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dirfd,
        )
        own = os.fstat(fd)
        named = os.stat(path.name, dir_fd=dirfd, follow_symlinks=False)
        if not (
            stat.S_ISREG(own.st_mode)
            and own.st_uid == os.getuid()
            and own.st_nlink == 1
            and own.st_size == 0
            and own.st_mode & 0o077 == 0
            and own.st_dev == directory.st_dev
            and (own.st_dev, own.st_ino) == (named.st_dev, named.st_ino)
        ):
            return False
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                return False
            offset += written
        os.fsync(fd)
        if os.fstat(fd).st_nlink != 1:
            return False
        # File/dir close failures are failures, not verified persistence.
        os.close(fd)
        fd = None
        os.close(dirfd)
        dirfd = None
        return True
    except Exception:
        # No str(exc), paths, traceback, or sensitive arguments are emitted.
        return False
    finally:
        for owned_fd in (fd, dirfd):
            if owned_fd is not None:
                try:
                    os.close(owned_fd)
                except OSError:
                    pass

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qmp", type=Path, required=True)
    parser.add_argument("--serial", type=Path, required=True)
    parser.add_argument("--disk", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--prompt-seconds", type=int, default=90)
    parser.add_argument("--progress-seconds", type=int, default=600)
    args = parser.parse_args()
    report: dict
    try:
        report = supervise(
            args.qmp,
            args.serial,
            args.disk,
            prompt_seconds=args.prompt_seconds,
            progress_seconds=args.progress_seconds,
        )
        exit_code = 0
    except Exception as exc:
        # No free-form exception text may reach reports or stdout.
        report = {
            "decision": "refuse",
            "reason": _safe_reason(exc),
            "qmpSendKeyAcknowledged": False,
            "windowsSetupVerified": False,
            "installationAuthorized": False,
        }
        exit_code = 1
    if not _write_report_exclusive(args.report, args.qmp, report):
        print("GASLUX_Q4OS_DVD_BOOT_DECISION=refuse")
        return 1
    decision = "dvd_key_sent_once" if exit_code == 0 and report["decision"] == "dvd_key_sent_once" else "refuse"
    print("GASLUX_Q4OS_DVD_BOOT_DECISION=" + decision)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
