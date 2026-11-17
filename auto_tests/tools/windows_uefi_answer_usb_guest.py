#!/usr/bin/env python3
"""Require an actual disposable UEFI GRUB guest to see the FAT32 answer USB.

The guest emits one static serial witness only after GRUB finds both expected
FAT files on the same read-only USB device model used by Windows lab QEMU.
This test does NOT prove Windows PE consumes Autounattend or Windows boots.
"""
from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path

SUCCESS = b"GASLUX_EFI_ANSWER_USB_FILES_VISIBLE=1"
FAILURE = b"GASLUX_EFI_ANSWER_USB_FILES_MISSING=1"
READY = b"GASLUX_EFI_ANSWER_USB_SCAN_STARTED=1"
MAX_SERIAL = 256 * 1024


class GuestUSBError(ValueError):
    pass


def require(ok: bool, explanation: str) -> None:
    if not ok:
        raise GuestUSBError(explanation)


def read_private_serial(path: Path) -> bytes:
    root = path.parent
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
        and path.is_absolute()
        and path.name == "only-disposable-answer-guest-serial.log"
        and root.parent == Path("/home/runner/work/_temp")
        and root.name.startswith("gaslux-win-x64-")
        and root.is_dir() and not root.is_symlink()
        and root.resolve() == root
        and root.stat().st_uid == os.getuid()
        and stat.S_IMODE(root.stat().st_mode) == 0o700
        and path.is_file() and not path.is_symlink()
        and path.stat().st_uid == os.getuid()
        and stat.S_ISREG(path.stat().st_mode)
        and path.stat().st_size <= MAX_SERIAL,
        "refusing nonprivate, oversized or foreign UEFI guest serial evidence",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and info.st_size <= MAX_SERIAL,
                "UEFI serial changed identity during read")
        with os.fdopen(os.dup(fd), "rb") as serial:
            result = serial.read(MAX_SERIAL + 1)
        require(len(result) == info.st_size,
                "UEFI serial grew or truncated during read")
        return result
    finally:
        os.close(fd)


def validate_witness(serial: bytes) -> bool:
    """Only whole, unique guest lines count; not arbitrary console substrings."""
    lines = [x.strip() for x in serial.splitlines()]
    require(lines.count(READY) <= 1, "ambiguous UEFI answer USB scan")
    require(lines.count(SUCCESS) <= 1, "duplicate UEFI guest visibility witness")
    require(FAILURE not in lines, "UEFI guest could not see answer USB files")
    require(not any(
        b"GASLUX_EFI_ANSWER_USB_" in line
        and line not in (READY, SUCCESS, FAILURE)
        for line in lines
    ), "unrecognized or prefixed UEFI answer USB witness")
    if SUCCESS in lines:
        require(READY in lines and lines.index(READY) < lines.index(SUCCESS),
                "UEFI answer visibility was claimed before guest scan")
        return True
    return False


def wait_for_guest(serial: Path, seconds: int = 120) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if serial.exists():
            if validate_witness(read_private_serial(serial)):
                print("GASLUX_EFI_GUEST_SAW_WINDOWS_ANSWER_USB_FILES=1", flush=True)
                print("GASLUX_WINDOWS_CLIENT_BOOT_VERIFIED=0", flush=True)
                return
        time.sleep(.5)
    raise GuestUSBError("UEFI guest never confirmed the FAT32 answer files")


def main() -> int:
    try:
        require(len(sys.argv) == 2, "expected isolated UEFI GRUB serial path")
        wait_for_guest(Path(sys.argv[1]))
        return 0
    except (GuestUSBError, OSError, ValueError) as error:
        print(f"GASLUX_EFI_ANSWER_USB_GUEST_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
