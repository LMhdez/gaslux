#!/usr/bin/env python3
"""Prove one HMP Enter reaches a disposable EFI GRUB guest, not Windows.

No host storage or guest OS is inspected. Only bounded CI-owned serial data
and the one local HMP socket are read. This is NOT Windows firstboot evidence.
"""
from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path

from windows_x64_tcg_firstboot import LabError, send_first_iso_boot_key

WAIT = b"GASLUX_EFI_GUEST_WAITING_FOR_ENTER=1"
ACCEPT = b"GASLUX_EFI_GUEST_ENTER_RECEIVED=1"
FAIL = b"GASLUX_EFI_GUEST_ENTER_REJECTED=1"


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise LabError(reason)


def inspect_owned_guest_serial(path: Path) -> bytes:
    parent = path.parent
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and path.is_absolute()
        and path.name == "only-disposable-grub-serial.log"
        and parent.parent == Path("/home/runner/work/_temp")
        and parent.name.startswith("gaslux-win-x64-")
        and parent.is_dir() and not parent.is_symlink()
        and parent.resolve() == parent
        and parent.stat().st_uid == os.getuid()
        and stat.S_IMODE(parent.stat().st_mode) == 0o700
        and path.is_file() and not path.is_symlink()
        and path.stat().st_uid == os.getuid()
        and stat.S_ISREG(path.stat().st_mode)
        and path.stat().st_size <= 256_000,
        "refusing unowned or unbounded synthetic EFI serial",
    )
    return path.read_bytes()


def prove_guest_received_key(serial: Path, hmp: Path) -> None:
    require(hmp.parent == serial.parent and
            hmp.name == "initial-installer-hmp.sock",
            "EFI HMP socket does not belong to the same disposable VM")
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        if serial.is_file():
            data = inspect_owned_guest_serial(serial)
            require(ACCEPT not in data, "guest falsely accepted key before HMP")
            require(FAIL not in data, "guest rejected console input before HMP")
            if WAIT in data:
                break
        time.sleep(.25)
    else:
        raise LabError("synthetic EFI guest did not reach keyboard wait")

    # Do not race the GRUB read prompt: it must remain blocked without input.
    time.sleep(2)
    data = inspect_owned_guest_serial(serial)
    require(ACCEPT not in data and WAIT in data and FAIL not in data,
            "EFI guest read completed without any injected key")

    # Same 6000 ms key duration used by Windows two-stage DVD Setup.
    # Complete HMP acknowledgment is necessary but insufficient for guest proof.
    send_first_iso_boot_key(hmp, hold_ms=6000)
    print("GASLUX_EFI_HMP_6000MS_ACKNOWLEDGED=1", flush=True)

    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        data = inspect_owned_guest_serial(serial)
        if ACCEPT in data:
            print("GASLUX_EFI_GUEST_ACTUALLY_RECEIVED_ENTER=1", flush=True)
            print("GASLUX_WINDOWS_CLIENT_BOOT_VERIFIED=0", flush=True)
            return
        require(FAIL not in data, "EFI guest explicitly rejected injected Enter")
        time.sleep(.25)
    raise LabError("HMP acknowledged the key but EFI guest did not receive Enter")


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3, "expected owned synthetic EFI serial and HMP")
        prove_guest_received_key(Path(sys.argv[1]), Path(sys.argv[2]))
    except (LabError, OSError, ValueError) as exc:
        print(f"GASLUX_EFI_KEY_PROBE_FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
