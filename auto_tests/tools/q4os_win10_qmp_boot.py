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
    def __init__(self, path: Path, *, negotiate: bool = True):
        """Connect without commands when a process owner must be authenticated.

        Call negotiate_protocol() only AFTER SO_PEERCRED and inode checks.
        Legacy direct users retain their existing full-handshake behaviour.
        """
        _private(path, "qmp")
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(2)
        self.stream = None
        try:
            self.socket.connect(str(path))
            self.stream = self.socket.makefile("rb")
            if negotiate:
                self.negotiate_protocol()
        except (OSError, ValueError, KeyError, BootRefusal):
            self.close()
            raise

    def negotiate_protocol(self) -> None:
        """Handshake and application commands; never call before authenticating peer."""
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
    qmp_channel: Qmp | None = None,
    process_guard=None,
) -> dict:
    """Require prompt, exactly one QMP key acknowledgement, then QCOW2 activity.

    QCOW2 growth is an operational progress signal, NOT proof of Windows Setup.
    Only the later NTFS/ESP/first-logon verification can establish that result.
    """
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
    connect_deadline = time.monotonic() + connect_seconds
    qmp = qmp_channel
    if qmp is None:
        while time.monotonic() < connect_deadline:
            try:
                qmp = Qmp(socket_path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(tick)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise BootRefusal("qmp_unavailable_or_malformed") from exc
    require(qmp is not None, "qmp_socket_unavailable")
    try:
        deadline = time.monotonic() + prompt_seconds
        while time.monotonic() < deadline:
            if process_guard is not None:
                process_guard()
            serial = _serial_text(serial_path)
            error = _boot_error(serial)
            require(error is None, error or "unknown_boot_error")
            if PROMPT in serial:
                # Never issue another key during Windows Setup or later reboots.
                size_before_key = disk_path.stat().st_size
                if process_guard is not None:
                    process_guard()
                try:
                    qmp.send_key_once()
                except (OSError, ValueError, BootRefusal) as exc:
                    raise BootRefusal("qmp_send_key_failed") from exc
                deadline_progress = time.monotonic() + progress_seconds
                while time.monotonic() < deadline_progress:
                    if process_guard is not None:
                        process_guard()
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
    except (BootRefusal, OSError, ValueError, json.JSONDecodeError) as exc:
        report = {
            "decision": "refuse",
            "reason": str(exc) if isinstance(exc, BootRefusal) else "qmp_io_or_protocol_error",
            "qmpSendKeyAcknowledged": False,
            "windowsSetupVerified": False,
            "installationAuthorized": False,
        }
        exit_code = 1
    require(
        args.report.parent == args.qmp.parent and not args.report.exists(),
        "unsafe_report_destination",
    )
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print("GASLUX_Q4OS_DVD_BOOT_DECISION=" + report["decision"])
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
