#!/usr/bin/env python3
"""Read-only GPT/EFI/Windows inspection after a verified disposable KVM firstboot.

The installed QCOW2 remains exclusively on the GitHub-hosted runner. This does
not prove recovery after Linux installation, a second independent Windows boot,
guest identity authentication, dual boot, or rollback.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
MSR = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
BASIC = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
RECOVERY = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
TYPES = (ESP, MSR, BASIC, RECOVERY)
GUID = re.compile(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\Z")

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\\Z")

class DiskAuditError(ValueError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise DiskAuditError(reason)


def require_owned_qcow2(path: Path) -> None:
    parent = path.parent
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
        and path.is_absolute()
        and path.name == "only-disposable-windows-target.qcow2"
        and parent.parent == Path("/home/runner/work/_temp")
        and parent.name.startswith("gaslux-win-x64-")
        and parent.is_dir() and not parent.is_symlink()
        and parent.resolve() == parent
        and parent.stat().st_uid == os.getuid()
        and stat.S_IMODE(parent.stat().st_mode) == 0o700
        and path.is_file() and not path.is_symlink()
        and path.stat().st_uid == os.getuid()
        and stat.S_ISREG(path.stat().st_mode),
        "read-only GPT audit requires exact privately owned disposable QCOW2",
    )


def inspect_layout(g) -> dict:
    """Only libguestfs read methods; strict four-role Windows 10 GPT layout."""
    disks = g.list_devices()
    require(disks == ["/dev/sda"], "unexpected disk count or device identity")
    device = disks[0]
    require(g.part_get_parttype(device) == "gpt", "not a GPT Windows disk")
    total = g.blockdev_getsize64(device)
    require(type(total) is int and total == 128 * 1024**3,
            "unexpected disposable Windows disk geometry")
    partitions = g.part_list(device)
    require(type(partitions) is list and len(partitions) == 4,
            "expected exactly four Windows GPT partitions")
    found = []
    last_end = 0
    for number, partition in enumerate(partitions, 1):
        require(type(partition) is dict, "invalid partition metadata")
        n = partition["part_num"]
        offset = partition["part_start"]
        size = partition["part_size"]
        kind = g.part_get_gpt_type(device, n).lower()
        guid = g.part_get_gpt_guid(device, n).lower()
        require(type(n) is int and n == number and kind == TYPES[number - 1],
                "unexpected ESP/MSR/Windows/Recovery partition sequence")
        require(type(offset) is int and type(size) is int
                and offset >= 1024 * 1024 and size > 0
                and offset % 512 == 0 and size % 512 == 0
                and offset >= last_end and offset + size <= total,
                "invalid or overlapping Windows GPT geometry")
        require(GUID.fullmatch(guid) is not None
                and guid != "00000000-0000-0000-0000-000000000000",
                "invalid Windows partition GUID")
        found.append({"number": n, "offsetBytes": offset, "sizeBytes": size,
                      "typeGuid": kind, "partitionGuid": guid})
        last_end = offset + size
    require(len(set(x["partitionGuid"] for x in found)) == 4,
            "duplicate GPT partition GUIDs")
    require(g.vfs_type("/dev/sda1").lower() in {"vfat", "fat"},
            "ESP is not FAT")
    require(g.vfs_type("/dev/sda3").lower() == "ntfs",
            "Windows volume is not NTFS")
    require(g.vfs_type("/dev/sda4").lower() == "ntfs",
            "Recovery volume is not NTFS")
    # Mount read-only and require actual EFI/BCD/Windows files rather than
    # trusting guest-emitted COM1 markers. Do not print or archive file bytes.
    g.mount_ro("/dev/sda1", "/")
    try:
        require(g.is_file("/EFI/Microsoft/Boot/bootmgfw.efi"),
                "Windows EFI Boot Manager file absent from ESP")
        require(g.is_file("/EFI/Microsoft/Boot/BCD"),
                "Windows boot configuration BCD absent from ESP")
        esp_efi_sha = g.checksum("sha256", "/EFI/Microsoft/Boot/bootmgfw.efi")
        esp_bcd_sha = g.checksum("sha256", "/EFI/Microsoft/Boot/BCD")
    finally:
        g.umount_all()
    g.mount_ro("/dev/sda3", "/")
    try:
        require(g.is_file("/Windows/System32/winload.efi"),
                "Windows loader missing from NTFS operating system")
        require(g.is_file("/Windows/System32/config/SYSTEM"),
                "installed Windows registry system hive absent")
        windows_loader_sha = g.checksum("sha256", "/Windows/System32/winload.efi")
    finally:
        g.umount_all()
    g.mount_ro("/dev/sda4", "/")
    try:
        paths = ("/Recovery/WindowsRE/Winre.wim",
                 "/Recovery/WindowsRE/winre.wim",
                 "/WindowsRE/Winre.wim")
        image = next((p for p in paths if g.is_file(p)), None)
        require(image is not None,
                "WinRE image missing from Windows Recovery partition")
        winre_sha = g.checksum("sha256", image)
    finally:
        g.umount_all()
    require(all(SHA256_PATTERN.fullmatch(value) for value in
                (esp_efi_sha, esp_bcd_sha, windows_loader_sha, winre_sha)),
            "invalid offline EFI/BCD/WinRE digest")
    return {
        "schemaVersion": 1,
        "source": "gaslux-host-libguestfs-readonly-after-verified-firstboot",
        "profile": "win10_22h2_en_us_x64",
        "diskVirtualSizeBytes": total,
        "partitionCount": 4,
        "partitions": found,
        "espBootManagerPresent": True,
        "espBcdPresent": True,
        "ntfsWindowsLoaderPresent": True,
        "ntfsWindowsSystemHivePresent": True,
        "recoveryGptPartitionPresent": True,
        "espBootManagerSha256": esp_efi_sha,
        "espBcdSha256": esp_bcd_sha,
        "windowsLoaderSha256": windows_loader_sha,
        "winreImageSha256": winre_sha,
        "winreImageOnRecoveryPresent": True,
        "winReRecoveryAfterLinuxVerified": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "stable": False,
    }


def inspect_owned_disk(path: Path) -> dict:
    require_owned_qcow2(path)
    # Lazy import: no dependency on libguestfs for pure no-ISO unit tests.
    try:
        import guestfs
    except ImportError:
        raise DiskAuditError("read-only libguestfs Python binding unavailable") from None
    before = path.stat()
    try:
        g = guestfs.GuestFS(python_return_dict=True)
        try:
            # No block device or backing file accepted, explicitly pin format.
            g.add_drive_opts(str(path), readonly=1, format="qcow2")
            g.launch()
            report = inspect_layout(g)
        finally:
            g.close()
    except RuntimeError:
        raise DiskAuditError("read-only guestfs appliance could not inspect the disposable disk") from None
    after = path.stat()
    require(before.st_size == after.st_size and
            before.st_mtime_ns == after.st_mtime_ns and
            before.st_blocks == after.st_blocks,
            "installed Windows QCOW2 changed during offline read-only inspection")
    return report


def encode_report(report: dict) -> str:
    require(report.get("sameDiskDualBootVerified") is False
            and report.get("storageWritesAuthorized") is False
            and report.get("stable") is False,
            "offline disk audit may not authorize release or modification")
    return json.dumps(report, sort_keys=True, indent=2) + "\n"
