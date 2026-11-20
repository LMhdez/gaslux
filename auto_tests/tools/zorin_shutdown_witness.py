#!/usr/bin/env python3
"""Strict Zorin serial shutdown witness for disposable KVM/Windows COW labs.

Powerdown is accepted only after a Zorin serial login, ordered systemd
shutdown/poweroff targets and the terminal kernel powerdown record.
QMP ACK, POWERDOWN event and QEMU exit status are independent required gates.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

MAX_SERIAL = 1024 * 1024
ANSI_CSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
POWERDOWN = re.compile(rb"\[\s*\d+\.\d+\]\s+reboot: Power down")
STEPS = (
    ("gettyStopped", re.compile(
        rb"\[\s*OK\s*\]\s+Stopped serial-getty@ttyS0\.service - Serial Getty on ttyS0\.")),
    ("shutdownTarget", re.compile(
        rb"\[\s*OK\s*\]\s+Reached target shutdown\.target - System Shutdown\.")),
    ("systemdPoweroffService", re.compile(
        rb"\[\s*OK\s*\]\s+Finished systemd-poweroff\.service - System Power Off\.")),
    ("poweroffTarget", re.compile(
        rb"\[\s*OK\s*\]\s+Reached target poweroff\.target - System Power Off\.")),
    ("kernelPowerDown", POWERDOWN),
)


class ZorinShutdownWitnessError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ZorinShutdownWitnessError(reason)


def normalized_lines(raw: bytes) -> list[bytes]:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_SERIAL,
            "Zorin serial is missing or truncated/oversized")
    return [line.strip() for line in ANSI_CSI.sub(b"", raw).replace(b"\r", b"").split(b"\n")]


def verify_zorin_shutdown_serial(raw: bytes) -> dict[str, object]:
    """Require ordered, anchored witnesses and terminal in-kernel poweroff."""
    lines = normalized_lines(raw)
    while lines and not lines[-1]:
        lines.pop()
    require(bool(lines), "Zorin serial has no terminal powerdown witness")
    boot = [i for i, line in enumerate(lines)
            if re.fullmatch(
                rb"\[\s*\d+\.\d+\]\s+Linux version [^\n]{1,512}", line)]
    login = [i for i, line in enumerate(lines)
             if line.startswith(b"GASLUXZORIN login:")]
    require(len(boot) == 1 and len(login) >= 1 and boot[0] < login[-1],
            "Zorin boot and serial login do not belong to one session")
    indices: dict[str, int] = {}
    cursor = login[-1]
    for name, pattern in STEPS:
        matching = [i for i in range(cursor + 1, len(lines))
                    if pattern.fullmatch(lines[i])]
        require(len(matching) == 1,
                "Zorin orderly shutdown missing or reordered: " + name)
        indices[name] = matching[0]
        cursor = matching[0]
    require(indices["kernelPowerDown"] == len(lines) - 1,
            "Zorin kernel powerdown is not the terminal serial record")
    return {
        "witnessLineIndices": indices,
        "terminalKernelPowerDown": lines[-1].decode("ascii"),
        "serialSha256": hashlib.sha256(raw).hexdigest(),
    }


def save_zorin_shutdown_diagnostic(
    dest: Path, *, raw: bytes, qmp_proof: dict,
    qemu_pid: int, qmp_socket_inode: int, cow_path: Path,
    root_uuid: str, return_code: int | None,
    failure: str | None, witness: dict | None,
) -> None:
    """Write bounded diagnostic even on failed shutdown; never mark P4/P5."""
    require(dest.parent.is_dir() and not dest.parent.is_symlink()
            and not dest.exists() and not dest.is_symlink(),
            "unsafe or reused Zorin diagnostic evidence destination")
    lines = normalized_lines(raw)
    tail = [line.decode("utf-8", "replace")[:250] for line in lines[-24:]]
    record = {
        "vmSessionQemuPid": qemu_pid,
        "vmSessionQmpSocketInode": qmp_socket_inode,
        "vmSessionCowPathSha256": hashlib.sha256(os.fsencode(cow_path)).hexdigest(),
        "vmSessionRootUuid": root_uuid,
        "qmpCommandAcknowledged": qmp_proof.get("qmpCommandAcknowledged") is True,
        "qmpPowerdownEventObserved": qmp_proof.get("qmpPowerdownEventObserved") is True,
        "qmpPidFdBindingIndependentlyAuthenticated": False,
        "qemuExitCode": return_code,
        "serialSha256": hashlib.sha256(raw).hexdigest(),
        "lastSerialLines": tail,
        "linuxOrderlyShutdownWitness": witness is not None,
        "shutdownWitnessLines": (witness or {}).get("witnessLineIndices", {}),
        "failure": failure,
        "nativeBootloaderVerified": False,
        "sameDiskDualBootVerified": False,
    }
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(record, output, sort_keys=True, indent=2)
        output.write("\n")
