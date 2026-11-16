#!/usr/bin/env python3
"""VM-only UEFI laboratory finishing stage for a prepared CachyOS target.

This is NOT integrated into the Windows Libertix installation flow. It can
write to the ESP of a disposable QEMU/KVM guest ONLY with an explicit sentinel.
It intentionally does not change firmware NVRAM or Windows bootloader files.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

LIB = Path(__file__).with_name("cachyos-uefi-config.py")
SPEC = importlib.util.spec_from_file_location("gaslux_cachyos_uefi", LIB)
assert SPEC is not None and SPEC.loader is not None
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)

TARGET = Path("/mnt/target")
VM_SENTINEL = "I_ACCEPT_DISPOSABLE_VM_ONLY"


class LabError(RuntimeError):
    pass


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise LabError(message)


def run(*argv: str) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=240)
    if result.returncode != 0:
        raise LabError(f"command failed: {argv[0]} (exit {result.returncode}): {result.stderr[-300:]}")
    return result.stdout.strip()


def mount_info(path: Path) -> tuple[str, str]:
    raw = run("findmnt", "-rn", "-M", str(path), "-o", "SOURCE,FSTYPE")
    fields = raw.split()
    ensure(len(fields) == 2, f"ambiguous mount at {path}")
    return fields[0], fields[1]


def check_host() -> None:
    ensure(os.geteuid() == 0, "VM-only stage must be run by root")
    ensure(os.environ.get("GASLUX_DISPOSABLE_VM") == VM_SENTINEL,
           "VM-only consent sentinel is missing")
    ensure(run("systemd-detect-virt", "--vm") in {"kvm", "qemu"},
           "refusing non-QEMU/KVM hardware")
    ensure(Path("/sys/firmware/efi/efivars").is_dir(), "UEFI firmware required")
    secureboot = list(Path("/sys/firmware/efi/efivars").glob(
        "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"))
    ensure(len(secureboot) == 1, "cannot inspect Secure Boot state")
    state = secureboot[0].read_bytes()
    ensure(len(state) == 5 and state[4] == 0, "Secure Boot must be disabled")


def safe_file(root: Path, relative: str) -> Path:
    base = root.resolve()
    destination = root / relative
    ensure(destination.resolve().is_relative_to(base),
           f"symlink escape in {relative}")
    ensure(destination.is_file() and not destination.is_symlink(),
           f"required regular file missing: {relative}")
    return destination


def verify_mounts(plan: dict[str, Any]) -> None:
    ensure(TARGET.is_dir() and not TARGET.is_symlink(), "root target is missing")
    root_dev, root_fs = mount_info(TARGET)
    ensure(root_fs == "ext4" and root_dev.startswith("/dev/"), "target must be ext4 block device")
    root_uuid = run("blkid", "-s", "UUID", "-o", "value", root_dev).lower()
    ensure(root_uuid == plan["rootUuid"], "target UUID differs from plan")
    owner = safe_file(TARGET, ".libertix-stage-owner")
    ensure(owner.read_text().strip() == plan["runId"], "target transaction ownership mismatch")

    esp = TARGET / "boot/efi"
    ensure(esp.is_dir() and not esp.is_symlink(), "ESP mount missing")
    esp_dev, esp_fs = mount_info(esp)
    ensure(esp_fs == "vfat" and esp_dev.startswith("/dev/"), "ESP must be vfat block device")
    esp_uuid = run("blkid", "-s", "UUID", "-o", "value", esp_dev).upper()
    ensure(esp_uuid == plan["espUuid"] == plan["windowsBootUuid"],
           "ESP UUID differs from Windows boot partition in plan")
    windows = safe_file(esp, "EFI/Microsoft/Boot/bootmgfw.efi")
    digest = hashlib.sha256(windows.read_bytes()).hexdigest()
    ensure(digest == plan["windowsBootManagerSha256"],
           "Windows Boot Manager hash mismatch")
    ensure(not (esp / "EFI/Gaslux-CachyOS").exists(), "refusing existing Gaslux EFI ownership")
    ensure(not (TARGET / "etc/grub.d/45_gaslux_windows").exists(), "refusing existing GRUB generator")
    ensure(not (TARGET / "etc/fstab").exists(), "refusing pre-existing fstab")
    ensure(not (TARGET / "etc/default/grub.d/99-gaslux.cfg").exists(),
           "refusing pre-existing GRUB defaults")


def write_new(path: Path, value: str, mode: int) -> None:
    ensure(not path.exists() and not path.is_symlink(), f"refusing overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def apply_vm_lab(plan: dict[str, Any]) -> dict[str, str]:
    files = CONFIG.render(plan)  # pure preflight, before any disk writes
    check_host()
    verify_mounts(plan)
    # The bootable artifact verification only covers files; firmware/NVRAM and
    # Windows recovery still require separate end-to-end testing.
    target_os = safe_file(TARGET, "etc/os-release").read_text()
    ensure(re.search(r"^ID=cachyos$", target_os, re.MULTILINE) is not None,
           "target does not identify as installed CachyOS")
    safe_file(TARGET, "boot/vmlinuz-linux-cachyos")
    safe_file(TARGET, "boot/initramfs-linux-cachyos.img")
    esp = TARGET / "boot/efi"
    efi_dir = esp / "EFI/Gaslux-CachyOS"
    generator = TARGET / "etc/grub.d/45_gaslux_windows"
    fstab = TARGET / "etc/fstab"
    defaults = TARGET / "etc/default/grub.d/99-gaslux.cfg"
    tracked = [generator, fstab, defaults]
    try:
        write_new(fstab, files["fstab"], 0o644)
        write_new(defaults, files["grubDefaults"], 0o644)
        script = '#!/bin/sh\nexec tail -n +3 "$0"\n' + files["windowsGrubEntry"]
        write_new(generator, script, 0o755)
        efi_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        write_new(efi_dir / ".gaslux-owner", plan["runId"] + "\n", 0o600)
        run("arch-chroot", str(TARGET), "grub-install", "--target=x86_64-efi",
            "--efi-directory=/boot/efi", "--bootloader-id=Gaslux-CachyOS",
            "--no-nvram", "--no-extra-removable", "--recheck")
        run("arch-chroot", str(TARGET), "grub-mkconfig", "-o", "/boot/grub/grub.cfg")
        run("arch-chroot", str(TARGET), "grub-script-check", "/boot/grub/grub.cfg")
        ensure(safe_file(efi_dir, "grubx64.efi").read_bytes()[:2] == b"MZ",
               "GRUB EFI binary is absent/invalid")
        grub_text = safe_file(TARGET, "boot/grub/grub.cfg").read_text()
        ensure("Windows Boot Manager" in grub_text and "Gaslux-CachyOS" in str(efi_dir),
               "generated boot menu is incomplete")
    except Exception:
        # Fail closed: only remove files created by this transaction. Do NOT
        # touch EFI/Microsoft or BootOrder, and do not claim Windows recovery.
        for path in tracked:
            if path.exists() and not path.is_symlink():
                path.unlink()
        marker = efi_dir / ".gaslux-owner"
        if marker.is_file() and not marker.is_symlink() and marker.read_text().strip() == plan["runId"]:
            # Remove only our own one-off EFI directory in the disposable VM.
            import shutil
            shutil.rmtree(efi_dir)
        raise
    return {
        "status": "vm-lab-efi-files-installed",
        "firmwareNVRAMModified": "false",
        "windowsBootManagerModified": "false",
        "bootsVerified": "false",
        "windowsRecoveryVerified": "false",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan")
    parser.add_argument("--apply-vm-lab", action="store_true",
                        help="MUTATES DISPOSABLE KVM/QEMU GUEST TARGET/ESP ONLY")
    args = parser.parse_args(argv)
    try:
        with open(args.plan, encoding="utf-8") as stream:
            plan = json.load(stream)
        rendered = CONFIG.render(plan)
        result = apply_vm_lab(plan) if args.apply_vm_lab else {
            "status": "read-only-dry-run", **rendered
        }
    except (OSError, ValueError, TypeError, KeyError, LabError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
