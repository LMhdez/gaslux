#!/usr/bin/env python3
"""Authenticated QMP ACPI request for disposable Zorin QCOW2 guest.

Require both QMP response and POWERDOWN event: HMP fire-and-forget is not
proof QEMU accepted the ACPI power-button request. Neither an ACK nor a
POWERDOWN event is proof that Linux shut down; caller still requires QEMU
normal exit AND systemd/kernel serial shutdown witnesses.
"""
from __future__ import annotations

import json
from pathlib import Path
import socket
import stat
import time


class ZorinQmpError(RuntimeError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ZorinQmpError(why)


def request_guest_acpi_powerdown(
    path: Path, *, timeout_seconds: int = 20,
) -> dict[str, bool]:
    require(type(timeout_seconds) is int and 1 <= timeout_seconds <= 30,
            "invalid bounded QMP timeout")
    require(path.parent.is_dir() and not path.parent.is_symlink()
            and path.exists() and not path.is_symlink()
            and stat.S_ISSOCK(path.lstat().st_mode),
            "missing private QEMU QMP monitor socket")
    deadline = time.monotonic() + timeout_seconds

    def read_response(reader) -> dict:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "QMP timed out awaiting response")
        conn.settimeout(min(remaining, 5))
        line = reader.readline(65537)
        require(0 < len(line) <= 65536 and line.endswith(b"\n"),
                "QMP response missing, truncated or oversized")
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ZorinQmpError("QMP returned malformed JSON") from exc
        require(type(record) is dict, "invalid QMP response structure")
        return record

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(path))
        with conn.makefile("rb", buffering=0) as reader:
            greeting = read_response(reader)
            require(type(greeting.get("QMP")) is dict,
                    "QEMU did not provide QMP handshake")

            def execute(command: str, identifier: str) -> bool:
                conn.sendall((json.dumps({
                    "execute": command, "id": identifier,
                }, sort_keys=True) + "\n").encode("ascii"))
                saw_powerdown = False
                while time.monotonic() < deadline:
                    record = read_response(reader)
                    if record.get("event") == "POWERDOWN":
                        saw_powerdown = True
                    if record.get("id") == identifier:
                        require(record.get("return") == {} and "error" not in record,
                                "QMP refused ACPI command " + identifier)
                        return saw_powerdown
                raise ZorinQmpError("QMP command acknowledgement absent")

            execute("qmp_capabilities", "gaslux-qmp-capabilities")
            saw_powerdown = execute("system_powerdown", "gaslux-acpi-request")
            while not saw_powerdown and time.monotonic() < deadline:
                record = read_response(reader)
                if record.get("event") == "POWERDOWN":
                    saw_powerdown = True
            require(saw_powerdown,
                    "QEMU did not emit POWERDOWN event after acknowledged ACPI request")
    return {
        "qmpCommandAcknowledged": True,
        "qmpPowerdownEventObserved": True,
    }
