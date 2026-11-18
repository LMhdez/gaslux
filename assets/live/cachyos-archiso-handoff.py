#!/usr/bin/env python3
"""Read-only CachyOS Archiso loopback handoff preparation (experimental).

Validates a *locally mounted* official CachyOS ISO and a separate on-disk ISO
source against an explicit expected SHA-256, then renders GRUB EFI instructions.
This does not install Linux, arm Windows recovery, or modify a boot entry.
Do not pass user-supplied unsigned plan data in production.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

_PREFLIGHT = Path(__file__).with_name("libertix-cachyos-preflight.py")
_SPEC = importlib.util.spec_from_file_location("gaslux_cachyos_preflight", _PREFLIGHT)
assert _SPEC and _SPEC.loader
_PREFLIGHT_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_PREFLIGHT_MODULE)

_REQUIRED = frozenset({
    "schemaVersion", "firmware", "secureBootEnabled", "runId",
    "isoStorageFilesystem", "isoStorageUuid", "isoRelativePath",
    "isoSha256", "isoSizeBytes",
})
_RUN_ID = re.compile(r"[A-Za-z0-9_-]{12,100}")
_NTFS_UUID = re.compile(r"[0-9A-F]{16}")
_EXT4_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
_ISO_PATH = re.compile(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*[.]iso")
_HASH = re.compile(r"[0-9a-f]{64}")
_ROOTFS = "arch/x86_64/airootfs.sfs"
# Official CachyOS Archiso GRUB loopback.cfg uses linux-cachyos-lts.
# Keep the non-LTS variant for independently verified builds. Prefer the
# official LTS pair when both complete pairs are present.
_BOOT_PAIRS = (
    ("arch/boot/x86_64/vmlinuz-linux-cachyos-lts",
     "arch/boot/x86_64/initramfs-linux-cachyos-lts.img"),
    ("arch/boot/x86_64/vmlinuz-linux-cachyos",
     "arch/boot/x86_64/initramfs-linux-cachyos.img"),
)


class HandoffError(ValueError):
    """Unsafe or incomplete ISO or handoff plan."""


def _require(condition: bool, error: str) -> None:
    if not condition:
        raise HandoffError(error)


def _validate(plan: dict[str, Any]) -> tuple[str, str, str]:
    _require(isinstance(plan, dict) and set(plan) == _REQUIRED,
             "missing or unexpected handoff fields")
    _require(type(plan["schemaVersion"]) is int and plan["schemaVersion"] == 1,
             "unsupported handoff schema")
    _require(plan["firmware"] == "uefi" and plan["secureBootEnabled"] is False,
             "only UEFI with Secure Boot disabled is supported")
    _require(isinstance(plan["runId"], str) and
             _RUN_ID.fullmatch(plan["runId"]) is not None, "invalid transaction identifier")
    fs = plan["isoStorageFilesystem"]
    _require(fs in ("ntfs", "ext4"), "unsupported ISO storage filesystem")
    uuid = plan["isoStorageUuid"]
    pattern = _NTFS_UUID if fs == "ntfs" else _EXT4_UUID
    _require(isinstance(uuid, str) and pattern.fullmatch(uuid) is not None,
             "ISO storage UUID has invalid syntax")
    path = plan["isoRelativePath"]
    _require(isinstance(path, str) and _ISO_PATH.fullmatch(path) is not None and
             not any(part in (".", "..") for part in path.split("/")),
             "ISO path must be absolute, ASCII and traversal-free")
    _require(isinstance(plan["isoSha256"], str) and
             _HASH.fullmatch(plan["isoSha256"]) is not None,
             "invalid ISO SHA-256")
    _require(type(plan["isoSizeBytes"]) is int and
             plan["isoSizeBytes"] > 0, "invalid ISO file size")
    return fs, uuid, path


def _regular_file(path: Path, base: Path) -> Path:
    _require(not path.is_symlink() and path.is_file(), "file missing/symlink: " + str(path))
    _require(path.resolve().is_relative_to(base.resolve()),
             "path escapes its verified root: " + str(path))
    return path


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _command(runner: Any, argv: list[str]) -> str:
    try:
        response = runner(argv, capture_output=True, text=True, check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HandoffError("mount verification cannot execute: " + argv[0]) from error
    _require(response.returncode == 0, "mount verification failed: " + argv[0])
    _require(len(response.stdout) < 16_384, "excessive mount verification output")
    return response.stdout.strip()


def verify_live_iso_mount(
    *,
    iso_path: Path,
    storage_root: Path,
    iso_root: Path,
    storage_fs: str,
    storage_uuid: str,
    runner: Any = subprocess.run,
) -> None:
    """Reject a mount that is not a read-only loop of the hashed source ISO."""
    store = _command(runner, [
        "findmnt", "-rn", "-M", str(storage_root), "-o", "SOURCE,FSTYPE"
    ]).split()
    _require(len(store) == 2 and store[0].startswith("/dev/"),
             "ISO storage is not an exact block-device mountpoint")
    observed_fs = store[1]
    valid_fs = ("ntfs", "ntfs3", "fuseblk") if storage_fs == "ntfs" else ("ext4",)
    _require(observed_fs in valid_fs, "unexpected ISO storage filesystem")
    # Linux loop numbers are recycled between temporary mounts. A cached
    # libblkid result may refer to the preceding filesystem on /dev/loopN;
    # probe the *currently mounted block device* without consulting the cache.
    # The check is read-only and a mismatch still fails closed.
    observed_uuid = _command(runner, [
        "blkid", "-p", "-c", "/dev/null", "-s", "UUID", "-o", "value", store[0]
    ])
    _require(observed_uuid.upper() == storage_uuid.upper(), "ISO storage UUID mismatch")

    mounted = _command(runner, [
        "findmnt", "-rn", "-M", str(iso_root), "-o", "SOURCE,FSTYPE,OPTIONS"
    ]).split()
    _require(len(mounted) == 3 and mounted[1] == "iso9660",
             "ISO root is not an exact ISO9660 mountpoint")
    _require("ro" in mounted[2].split(","), "ISO must be mounted read-only")
    loop_device = mounted[0]
    _require(re.fullmatch(r"/dev/loop[0-9]+", loop_device) is not None,
             "mounted ISO is not backed by a loop device")
    backing = _command(runner, [
        "losetup", "--noheadings", "--output", "BACK-FILE", loop_device
    ])
    _require(backing == str(iso_path.resolve()),
             "loop-mounted ISO is different from the hashed source file")


def _select_archiso_boot_pair(iso_root: Path) -> tuple[str, str]:
    """Select a complete official Archiso kernel/initramfs pair; never mix versions."""
    options: list[tuple[str, str]] = []
    for kernel, initramfs in _BOOT_PAIRS:
        kernel_path = iso_root / kernel
        initrd_path = iso_root / initramfs
        kernel_exists = kernel_path.exists() or kernel_path.is_symlink()
        initrd_exists = initrd_path.exists() or initrd_path.is_symlink()
        _require(kernel_exists == initrd_exists,
                 "CachyOS kernel/initramfs pairing mismatch")
        if not kernel_exists:
            continue
        for relative_path in (kernel, initramfs):
            observed = _regular_file(iso_root / relative_path, iso_root)
            _require(observed.stat().st_size > 0,
                     "empty ISO component: " + relative_path)
        options.append((kernel, initramfs))
    _require(bool(options),
             "CachyOS live kernel and matching initramfs are missing")
    return options[0]


def prepare(
    plan: dict[str, Any],
    *,
    storage_root: Path,
    iso_root: Path,
    runner: Any = subprocess.run,
    require_mounted_iso: bool = False,
    mount_runner: Any = subprocess.run,
) -> dict[str, object]:
    """Verify a detached ISO source and the mounted ISO tree, render only."""
    fs, uuid, relative = _validate(plan)
    _require(storage_root.is_dir() and not storage_root.is_symlink(),
             "ISO storage root must be a normal directory")
    _require(iso_root.is_dir() and not iso_root.is_symlink(),
             "mounted ISO root must be a normal directory")
    _require(storage_root.resolve() != iso_root.resolve(),
             "ISO storage and ISO mount cannot be the same")
    iso_path = _regular_file(storage_root / relative.lstrip("/"), storage_root)
    _require(iso_path.stat().st_size == plan["isoSizeBytes"], "ISO file size mismatch")
    _require(_digest(iso_path) == plan["isoSha256"], "ISO SHA-256 mismatch")
    if require_mounted_iso:
        verify_live_iso_mount(
            iso_path=iso_path, storage_root=storage_root, iso_root=iso_root,
            storage_fs=fs, storage_uuid=uuid, runner=mount_runner
        )

    # The caller must establish that iso_root is a read-only loop mount of the
    # *same* file; a directory fixture alone is not such evidence.
    rootfs = _regular_file(iso_root / _ROOTFS, iso_root)
    _require(rootfs.stat().st_size > 0, "empty ISO component: " + _ROOTFS)
    kernel_path, initrd_path = _select_archiso_boot_pair(iso_root)
    try:
        identity = _PREFLIGHT_MODULE.inspect_cachyos_iso_root(iso_root, runner=runner)
    except _PREFLIGHT_MODULE.PreflightError as error:
        raise HandoffError("CachyOS live identity preflight failed: " + str(error)) from error

    disk_module = "ntfs" if fs == "ntfs" else "ext2"
    # All inserted values were syntax-restricted; never accept extra GRUB
    # commands, kernel flags or an arbitrary file path.
    script = (
        "# Gaslux CachyOS Archiso handoff — lab-only, not a production installer\n"
        + "# Transaction " + plan["runId"] + "\n"
        + "menuentry 'CachyOS Archiso (experimental)' --id gaslux-cachyos-archiso {\n"
        + "    insmod part_gpt\n"
        + "    insmod " + disk_module + "\n"
        + "    insmod iso9660\n"
        + "    search --no-floppy --fs-uuid --set=gaslux_iso_dev " + uuid + "\n"
        + "    set gaslux_iso_path='" + relative + "'\n"
        + "    if [ ! -f ($gaslux_iso_dev)$gaslux_iso_path ]; then\n"
        + "        echo 'Verified CachyOS ISO location is missing'\n"
        + "        sleep 10\n"
        + "        reboot\n"
        + "    fi\n"
        + "    loopback gaslux_iso ($gaslux_iso_dev)$gaslux_iso_path\n"
        + "    if [ ! -f (gaslux_iso)/" + kernel_path + " ]; then\n"
        + "        echo 'CachyOS ISO kernel is missing'\n"
        + "        sleep 10\n"
        + "        reboot\n"
        + "    fi\n"
        + "    linux (gaslux_iso)/" + kernel_path
        + " archisobasedir=arch img_dev=UUID=" + uuid
        + " img_loop=" + relative
        + " cow_spacesize=10G copytoram=auto\n"
        + "    initrd (gaslux_iso)/" + initrd_path + "\n"
        + "}\n"
    )
    return {
        "ok": True,
        "distribution": "cachyos",
        "runId": plan["runId"],
        "isoSha256Verified": True,
        "isoLayoutVerified": True,
        "liveKernelPath": kernel_path,
        "liveInitramfsPath": initrd_path,
        "expectedHostFilesystem": fs,
        "expectedHostFilesystemUuid": uuid,
        "grubEntry": script,
        "isoMountedFromVerifiedSource": require_mounted_iso,
        "productionInstallSupported": False,
        "writesStorage": False,
        "writesFirmware": False,
        "windowsRecoveryVerified": False,
        "identity": identity,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="pre-verified laboratory JSON plan")
    parser.add_argument("--storage-root", type=Path, required=True)
    parser.add_argument("--iso-root", type=Path, required=True)
    parser.add_argument("--require-mounted-iso", action="store_true",
                        help="validate exact block-device UUID and read-only ISO loop mount")
    args = parser.parse_args(argv)
    try:
        with args.plan.open(encoding="utf-8") as file:
            plan = json.load(file)
        result = prepare(plan, storage_root=args.storage_root, iso_root=args.iso_root,
                         require_mounted_iso=args.require_mounted_iso)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
