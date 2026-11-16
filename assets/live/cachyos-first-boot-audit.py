#!/usr/bin/env python3
"""Read-only post-reboot audit for a CachyOS UEFI laboratory installation.

This never repairs boot files or changes disks, NVRAM or Windows. A successful
result attests to the *running Linux* filesystem, not Windows rollback.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "gaslux_cachyos_config", HERE / "cachyos-uefi-config.py")
assert SPEC and SPEC.loader
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)

Runner = Callable[..., subprocess.CompletedProcess[str]]


class AuditError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def safe_file(root: Path, relative: str) -> Path:
    candidate = root / relative
    require(candidate.resolve().is_relative_to(root.resolve()),
            "target path escapes root: " + relative)
    require(candidate.is_file() and not candidate.is_symlink(),
            "required file missing/symlink: " + relative)
    return candidate


def invoke(runner: Runner, *args: str) -> str:
    try:
        result = runner(list(args), capture_output=True, text=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AuditError("cannot execute " + args[0]) from error
    require(result.returncode == 0, "command failed: " + args[0])
    require(len(result.stdout) < 100_000, "command returned excessive data")
    return result.stdout.strip()


def read_only_boot_audit(
    plan: dict[str, object], *,
    root: Path = Path("/"),
    runner: Runner = subprocess.run,
) -> dict[str, object]:
    """Verify the running Linux identity and mounts; offline fixtures are untrusted."""
    CONFIG.render(plan)
    require(root.is_dir() and not root.is_symlink(), "system root is not a directory")
    root = root.resolve()
    # The same code can be exercised with synthetic filesystem fixtures, but
    # fixture runs can NEVER report booted Linux proof or Windows recovery.
    live = root == Path("/")
    if live:
        require(os.geteuid() == 0, "post-boot audit requires root privileges")
    os_release = safe_file(root, "etc/os-release").read_text(encoding="utf-8")
    require(re.search(r'(?m)^ID=cachyos$', os_release) is not None,
            "booted OS is not installed CachyOS")
    run_id = plan["runId"]
    require(safe_file(root, ".libertix-stage-owner").read_text().strip() == run_id,
            "running root does not match the transaction")

    def check_mount(mount: str, expected_fs: str, expected_uuid: str) -> None:
        # findmnt -M requires an exact mount, unlike -T which accepts parents.
        mountpoint = str(root if mount == "/" else root / mount.lstrip("/"))
        device_info = invoke(runner, "findmnt", "-rn", "-M", mountpoint, "-o", "SOURCE,FSTYPE")
        parts = device_info.split()
        require(len(parts) == 2, "ambiguous mount at " + mount)
        device, filesystem = parts
        require(filesystem == expected_fs, "wrong filesystem at " + mount)
        require(device.startswith("/dev/") and ".." not in device,
                "mount source is not a block device at " + mount)
        if live:
            require(Path(device).is_block_device(), "mount source not a block device")
        observed_uuid = invoke(runner, "blkid", "-s", "UUID", "-o", "value", device)
        require(observed_uuid.casefold() == expected_uuid.casefold(),
                "UUID mismatch at " + mount)

    check_mount("/", "ext4", str(plan["rootUuid"]))
    check_mount("/boot/efi", "vfat", str(plan["espUuid"]))
    kernel = invoke(runner, "uname", "-r")
    require(bool(re.fullmatch(r"[0-9A-Za-z.+_-]{5,120}", kernel))
            and "cachyos" in kernel, "running kernel does not identify as CachyOS")
    require(invoke(runner, "pacman", "-Qq", "linux-cachyos") == "linux-cachyos",
            "CachyOS kernel package not installed")
    kernel_disk = safe_file(root, "boot/vmlinuz-linux-cachyos")
    initramfs = safe_file(root, "boot/initramfs-linux-cachyos.img")
    require(kernel_disk.stat().st_size > 0 and initramfs.stat().st_size > 0,
            "kernel or initramfs is empty")

    efi_base = "boot/efi/EFI/Gaslux-CachyOS/"
    require(safe_file(root, efi_base + ".gaslux-owner").read_text().strip() == run_id,
            "EFI ownership marker mismatch")
    with safe_file(root, efi_base + "grubx64.efi").open("rb") as loader:
        require(loader.read(2) == b"MZ", "EFI loader is not a PE binary")
    windows = safe_file(root, "boot/efi/EFI/Microsoft/Boot/bootmgfw.efi")
    require(hashlib.sha256(windows.read_bytes()).hexdigest() ==
            plan["windowsBootManagerSha256"], "Windows Boot Manager has changed")
    grub = safe_file(root, "boot/grub/grub.cfg").read_text(encoding="utf-8")
    require("gaslux-windows" in grub and
            "Windows Boot Manager" in grub and
            "vmlinuz-linux-cachyos" in grub,
            "GRUB menu is missing Windows or CachyOS")

    # No BootCurrent/BootOrder, Windows BCD or WinRE assertion is made here.
    # Evidence from a fixture cannot be used as boot or rollback proof.
    return {
        "ok": True,
        "status": "linux-runtime-audited" if live else "offline-fixture-audited",
        "runId": run_id,
        "runningKernel": kernel,
        "runningLinuxRootVerified": live,
        "windowsBootManagerHashVerified": True,
        "firmwareBootOrderVerified": False,
        "windowsRollbackVerified": False,
        "installationStable": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", help="Trusted lab JSON plan from the installation transaction")
    args = parser.parse_args(argv)
    try:
        with open(args.plan, encoding="utf-8") as stream:
            result = read_only_boot_audit(json.load(stream))
    except (AuditError, ValueError, TypeError, KeyError, OSError, UnicodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
