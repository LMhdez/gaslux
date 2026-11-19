#!/usr/bin/env python3
"""Q4OS Windows 10 QCOW2-only OVMF CD prompt input. No physical devices.

Run exactly one disposable QEMU first-boot process, inject Space only when
the OVMF serial log proves the official Windows ISO asks for a key, and
fail within a bounded time if the prompt never appears.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

PROMPT = b"Press any key to boot from CD or DVD"
SHELL = b"UEFI Interactive Shell"
FAILED = b"failed to start Boot0001"
QEMU_BINARY = "qemu-system-x86_64"


class WindowsDvdRefusal(RuntimeError):
    """The isolated Windows install did not prove valid EFI CD boot."""


def _require(value: bool, reason: str) -> None:
    if not value:
        raise WindowsDvdRefusal(reason)


def _owned_private_file_path(path: Path, root: Path) -> None:
    _require(path.is_absolute() and path.parent == root, "Foreign file destination")
    _require(
        path.name
        in {
            "windows10-qemu-serial.log",
            "windows10-qemu-process.log",
            "windows10-qemu-qmp.sock",
        },
        "Unexpected Windows QEMU evidence path",
    )
    _require(not path.is_symlink(), "Symlink in Windows QEMU evidence path")


def inspect_serial_for_boot_prompt(raw: bytes) -> str:
    """A prompt is meaningful only while firmware has not entered EFI shell."""
    if SHELL in raw or FAILED in raw:
        raise WindowsDvdRefusal("OVMF skipped Windows DVD and entered EFI shell")
    if PROMPT in raw:
        return "prompt"
    return "pending"


def _read_qmp_reply(stream, expected_id: str) -> dict:
    """Read newline-delimited QMP messages until the matching reply arrives."""
    while True:
        line = stream.readline()
        _require(bool(line), "QEMU QMP channel closed without acknowledgement")
        _require(len(line) <= 8192, "Oversized QEMU QMP response")
        try:
            message = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WindowsDvdRefusal("Malformed QEMU QMP response") from exc
        _require(isinstance(message, dict), "Unexpected QEMU QMP response")
        if "event" in message:
            continue
        if message.get("id") != expected_id:
            continue
        _require("error" not in message, "QEMU QMP rejected optical boot key")
        _require("return" in message, "QEMU QMP response has no return value")
        return message


def _send_key_events(stream, *, sleep=time.sleep) -> None:
    """Hold Space long enough for OVMF USB HID polling, with QMP acknowledgements."""
    key_down = {
        "execute": "input-send-event",
        "arguments": {
            "events": [
                {
                    "type": "key",
                    "data": {
                        "key": {"type": "qcode", "data": "spc"},
                        "down": True,
                    },
                }
            ]
        },
        "id": "gaslux-ovmf-space-down",
    }
    stream.write((json.dumps(key_down, separators=(",", ":")) + "\r\n").encode())
    _read_qmp_reply(stream, "gaslux-ovmf-space-down")
    sleep(0.25)
    key_up = {
        "execute": "input-send-event",
        "arguments": {
            "events": [
                {
                    "type": "key",
                    "data": {
                        "key": {"type": "qcode", "data": "spc"},
                        "down": False,
                    },
                }
            ]
        },
        "id": "gaslux-ovmf-space-up",
    }
    stream.write((json.dumps(key_up, separators=(",", ":")) + "\r\n").encode())
    _read_qmp_reply(stream, "gaslux-ovmf-space-up")


def _send_key(sock: Path, pid: int) -> None:
    st = sock.lstat()
    _require(stat.S_ISSOCK(st.st_mode), "QEMU QMP endpoint is not a socket")
    _require(st.st_uid == os.getuid(), "Foreign QEMU QMP socket owner")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(3)
        channel.connect(str(sock))
        _require(hasattr(socket, "SO_PEERCRED"), "Unix peer credentials unavailable")
        peer_pid, peer_uid, _ = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        _require(
            peer_pid == pid and peer_uid == os.getuid(),
            "QEMU QMP peer does not match the exact launched process",
        )
        with channel.makefile("rwb", buffering=0) as stream:
            greeting = stream.readline()
            _require(bool(greeting) and len(greeting) <= 8192, "Missing QEMU QMP greeting")
            try:
                greeting_data = json.loads(greeting)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise WindowsDvdRefusal("Malformed QEMU QMP greeting") from exc
            _require(
                isinstance(greeting_data, dict) and isinstance(greeting_data.get("QMP"), dict),
                "QEMU endpoint is not a QMP monitor",
            )
            stream.write(b'{"execute":"qmp_capabilities","id":"gaslux-capabilities"}\r\n')
            _read_qmp_reply(stream, "gaslux-capabilities")
            # Separate acknowledged key-down and key-up let OVMF poll USB HID.
            _send_key_events(stream)


def _validate_lab(root: Path, serial: Path, monitor: Path, log: Path, args: list[str]) -> None:
    _require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GASLUX_WIN10_UEFI_OPTICAL_INPUT_LAB_ONLY") == "yes",
        "Official Windows DVD key injection is lab-only",
    )
    _require(root.is_absolute() and root.is_dir() and not root.is_symlink(), "Invalid workspace")
    root_stat = root.stat()
    _require(
        root_stat.st_uid == os.getuid() and root_stat.st_mode & 0o077 == 0,
        "Windows QEMU workspace must be private and owned",
    )
    for item in (serial, monitor, log):
        _owned_private_file_path(item, root)
    _require(len(str(monitor).encode("utf-8")) < 100, "QEMU QMP socket path too long")
    _require(args and args[0] == QEMU_BINARY, "Only the known QEMU binary is allowed")
    _require("-no-reboot" in args, "Expected non-rebooting Windows setup cycle")
    _require(
        args.count("-net") == 1
        and args[args.index("-net") + 1] == "none"
        and "-netdev" not in args
        and "-nic" not in args,
        "QEMU networking must be disabled",
    )
    _require(args.count("-qmp") == 1, "Exactly one private QEMU monitor required")
    _require(
        "-qmp" in args and "unix:" + str(monitor) + ",server=on,wait=off" in args,
        "QEMU QMP must be a private Unix socket",
    )
    _require(
        any(
            "id=system,file=" + str(root / "windows10-enterprise-eval-22h2-uefi-gpt.qcow2") in a
            and "format=qcow2" in a
            for a in args
        ),
        "Unrecognized Windows QCOW2 target",
    )
    _require(
        any(
            "id=install,file=" + str(root / "Windows10_Enterprise_22H2_Eval_EN-US_x64.iso") in a
            and "readonly=on" in a
            for a in args
        ),
        "Missing verified Windows ISO attached read-only",
    )
    _require(
        any(
            "id=answer,file=" + str(root / "unattend.iso") in a and "readonly=on" in a for a in args
        ),
        "Unattend medium must be read-only",
    )
    _require(args.count("-drive") == 5, "Unexpected QEMU disk attachment count")
    _require(
        args.count("qemu-xhci,id=usbctrl") == 1 and args.count("usb-kbd,bus=usbctrl.0") == 1,
        "No explicitly routed USB keyboard for OVMF",
    )
    for index, item in enumerate(args):
        _require(
            not item.startswith("/dev/")
            and "file=/dev/" not in item
            and "file=host_device" not in item,
            "Physical host device forbidden",
        )
        if item == "-device":
            _require(index + 1 < len(args), "Truncated QEMU device declaration")
            device_kind = args[index + 1].split(",", 1)[0]
            _require(
                device_kind in {"ich9-ahci", "ide-hd", "ide-cd", "qemu-xhci", "usb-kbd"},
                "Foreign or host-passthrough QEMU device forbidden",
            )
        if item == "-drive":
            _require(index + 1 < len(args), "Truncated QEMU drive declaration")
            declaration = args[index + 1]
            is_owned_disk = (
                "id=system,file=" + str(root / "windows10-enterprise-eval-22h2-uefi-gpt.qcow2")
                in declaration
            )
            is_owned_iso = (
                "id=install,file=" + str(root / "Windows10_Enterprise_22H2_Eval_EN-US_x64.iso")
                in declaration
            )
            is_owned_unattend = "id=answer,file=" + str(root / "unattend.iso") in declaration
            is_ovmf_code = (
                "if=pflash" in declaration
                and "unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd" in declaration
            )
            is_ovmf_vars = (
                "if=pflash" in declaration
                and "unit=1,file=" + str(root / "OVMF_VARS.fd") in declaration
            )
            _require(
                is_owned_disk or is_owned_iso or is_owned_unattend or is_ovmf_code or is_ovmf_vars,
                "Foreign QEMU drive attached",
            )


def run(
    root: Path,
    serial: Path,
    monitor: Path,
    log: Path,
    command: list[str],
    *,
    prompt_seconds: int = 45,
    cycle_seconds: int = 1500,
) -> None:
    _validate_lab(root, serial, monitor, log, command)
    _require(
        type(prompt_seconds) is int
        and 5 <= prompt_seconds <= 90
        and type(cycle_seconds) is int
        and 30 <= cycle_seconds <= 1800,
        "Unbounded Windows setup boot budget",
    )
    _require(
        not log.exists() and not serial.exists() and not monitor.exists(),
        "Refusing to overwrite previous Windows QEMU evidence",
    )
    started = time.monotonic()
    sent = False
    proc = None
    try:
        with log.open("xb") as log_file:
            proc = subprocess.Popen(
                command,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            prompt_deadline = time.monotonic() + prompt_seconds
            while time.monotonic() < prompt_deadline:
                if proc.poll() is not None:
                    raise WindowsDvdRefusal("QEMU exited before Windows EFI DVD prompt")
                if serial.is_file() and not serial.is_symlink():
                    with serial.open("rb") as capture:
                        raw = capture.read(64 * 1024)
                    if inspect_serial_for_boot_prompt(raw) == "prompt":
                        _require(monitor.is_socket(), "QEMU QMP not ready at EFI prompt")
                        time.sleep(0.5)
                        _send_key(monitor, proc.pid)
                        sent = True
                        print("GASLUX_WIN10_OVMF_DVD_KEY_SENT=PASS", flush=True)
                        break
                time.sleep(0.075)
            _require(sent, "OVMF did not show its Windows DVD boot prompt")
            # No Windows Setup serial output is required. We only reject
            # observable EFI failure without waiting 1500s in a shell.
            failure_deadline = time.monotonic() + 20
            while time.monotonic() < failure_deadline and proc.poll() is None:
                with serial.open("rb") as capture:
                    recent = capture.read(128 * 1024)
                _require(
                    SHELL not in recent and FAILED not in recent,
                    "USB keyboard injection did not boot the Windows ISO",
                )
                time.sleep(0.25)
            remaining = cycle_seconds - (time.monotonic() - started)
            _require(remaining > 0, "No Windows first-boot budget remains")
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise WindowsDvdRefusal(
                    "QEMU Windows first-boot cycle exceeded bounded budget"
                ) from exc
            _require(proc.returncode == 0, "Windows QEMU cycle did not reset/shut down cleanly")
            with serial.open("rb") as capture:
                raw = capture.read(4 * 1024 * 1024)
            _require(
                FAILED not in raw and SHELL not in raw,
                "Windows ISO was skipped despite DVD key injection",
            )
            print("GASLUX_WIN10_OVMF_DVD_HANDOFF=PASS", flush=True)
    finally:
        if proc is not None and proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        if monitor.exists() and monitor.is_socket():
            monitor.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("serial_log", type=Path)
    parser.add_argument("monitor_socket", type=Path)
    parser.add_argument("qemu_log", type=Path)
    parser.add_argument("--prompt-seconds", type=int, default=45)
    parser.add_argument("--cycle-seconds", type=int, default=1500)
    argv = sys.argv[1:]
    if "--" not in argv:
        print("GASLUX_WIN10_OVMF_DVD_REFUSED=Missing explicit QEMU argv separator", file=sys.stderr)
        return 2
    separator = argv.index("--")
    args = parser.parse_args(argv[:separator])
    command = argv[separator + 1 :]
    try:
        run(
            args.workspace,
            args.serial_log,
            args.monitor_socket,
            args.qemu_log,
            command,
            prompt_seconds=args.prompt_seconds,
            cycle_seconds=args.cycle_seconds,
        )
    except (WindowsDvdRefusal, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"GASLUX_WIN10_OVMF_DVD_REFUSED={exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
