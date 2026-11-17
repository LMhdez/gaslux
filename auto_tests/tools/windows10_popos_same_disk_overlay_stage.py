#!/usr/bin/env python3
"""Stage one unformatted Pop root in an isolated overlay of a *real* Windows 10 CI disk.

Runs only after Windows 10 firstboot and independent GPT/BCD/NTFS audit.
The original QCOW2 is the backing file, never writable through this module.
It does NOT install Linux, boot Windows after staging, or authorize production.
"""
from __future__ import annotations

from contextlib import closing

import json
import os
import re
import stat
import subprocess
from pathlib import Path

from windows10_popos_gpt_mirror_gate import (
    capture_owned_qcow2,
    reconcile_windows_and_root,
)
from windows_x64_installed_gpt_ro_audit import (
    BASIC,
    ESP,
    MSR,
    RECOVERY,
    DiskAuditError,
    inspect_layout,
    require,
    require_owned_qcow2,
)

GIB = 1024 ** 3
MIB = 1024 ** 2
SECTOR = 512
POP_ROOT_SIZE = 24 * GIB
LINUX_GPT = "0fc63daf-8483-4772-8e79-3d69d8477de4"
ROOT_LABEL = "GASLUX-LAB-POP-ROOT"
CONSENT = "I_ACCEPT_GITHUB_ONLY_QCOW2_COPY_ON_WRITE_LINUX_ROOT_STAGE"
WINDOWS_TYPES = (ESP, MSR, BASIC, RECOVERY)
WINDOWS_FILES = {
    "/dev/sda1": (
        "/EFI/Microsoft/Boot/bootmgfw.efi",
        "/EFI/Microsoft/Boot/BCD",
    ),
    "/dev/sda3": (
        "/Windows/System32/winload.efi",
        "/Windows/System32/config/SYSTEM",
    ),
}


def require_lab_owned(base: Path, overlay: Path, evidence: Path) -> None:
    require_owned_qcow2(base)
    require(
        os.environ.get("GASLUX_WIN10_POP_OVERLAY_CONSENT") == CONSENT
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "separate GitHub-only COW overlay staging consent missing",
    )
    require(
        overlay.parent == base.parent
        and overlay.name == "gaslux-pop-stage.qcow2"
        and not overlay.exists()
        and not overlay.is_symlink(),
        "unowned or preexisting writable overlay",
    )
    require(
        evidence.is_dir()
        and not evidence.is_symlink()
        and evidence.name == "windows-x64-tcg-evidence"
        and evidence.resolve() == evidence
        and evidence.parent == Path(os.environ["GITHUB_WORKSPACE"]),
        "unowned output evidence directory",
    )


def candidate_plan(windows: dict) -> dict:
    require(windows.get("schemaVersion") == 1
            and windows.get("profile") == "win10_22h2_en_us_x64"
            and windows.get("partitionCount") == 4
            and windows.get("storageWritesAuthorized") is False,
            "Windows baseline must be authentic offline audit with no writes allowed")
    parts = windows.get("partitions")
    require(type(parts) is list and len(parts) == 4,
            "Windows four-partition geometry not proven")
    last = 0
    for number, part in enumerate(parts, 1):
        require(
            type(part) is dict
            and part.get("number") == number
            and part.get("typeGuid") == WINDOWS_TYPES[number - 1]
            and type(part.get("offsetBytes")) is int
            and type(part.get("sizeBytes")) is int
            and part["offsetBytes"] >= last
            and part["sizeBytes"] > 0
            and part["offsetBytes"] % SECTOR == 0
            and part["sizeBytes"] % SECTOR == 0,
            "invalid Windows partition topology",
        )
        last = part["offsetBytes"] + part["sizeBytes"]
    size = windows["diskVirtualSizeBytes"]
    require(type(size) is int and size == 128 * GIB,
            "unexpected target geometry")
    # Leave >=2 MiB after Recovery, align root to 1 MiB and leave >=2 MiB
    # before GPT backup. Never shrink/move Windows; refuse if insufficient.
    start = ((last + 3 * MIB - 1) // MIB) * MIB
    end = start + POP_ROOT_SIZE
    require(
        end + 2 * MIB <= size
        and start > last
        and (start // SECTOR) > (last // SECTOR)
        and (end // SECTOR) - 1 < size // SECTOR - 34,
        "insufficient strictly unallocated tail for isolated Pop root",
    )
    return {
        "index": 5,
        "startSector": start // SECTOR,
        "endSector": (end // SECTOR) - 1,
        "sizeBytes": POP_ROOT_SIZE,
        "typeGuid": LINUX_GPT,
        "name": ROOT_LABEL,
        "sharedWindowsEspUntouched": True,
        "formatLinuxFilesystem": False,
    }


def _windows_witness(g, partition_count: int) -> dict:
    """Read-only evidence from the selected guestfs disk, not guest serial."""
    require(g.list_devices() == ["/dev/sda"]
            and g.part_get_parttype("/dev/sda") == "gpt",
            "unexpected disk or partition style")
    require(g.blockdev_getsize64("/dev/sda") == 128 * GIB,
            "unexpected virtual disk size")
    require(g.blockdev_getss("/dev/sda") == SECTOR,
            "unsupported logical sector size")
    layout = g.part_list("/dev/sda")
    require(len(layout) == partition_count,
            "unexpected partitions during read-only witness")
    guid = str(g.part_get_disk_guid("/dev/sda")).lower()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", guid)
            and guid != "00000000-0000-0000-0000-000000000000",
            "unverified GPT disk GUID")
    preserved = []
    last_end = 0
    for number, p in enumerate(layout[:4], 1):
        typ = str(g.part_get_gpt_type("/dev/sda", number)).lower()
        part_guid = str(g.part_get_gpt_guid("/dev/sda", number)).lower()
        start, count = p["part_start"], p["part_size"]
        require(
            p["part_num"] == number
            and typ == WINDOWS_TYPES[number - 1]
            and type(start) is int and type(count) is int
            and start >= last_end and count > 0
            and start % SECTOR == 0 and count % SECTOR == 0
            and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", part_guid),
            "Windows GPT partition changed or was replaced",
        )
        preserved.append((number, start, count, typ, part_guid))
        last_end = start + count
    require(
        [g.vfs_type(f"/dev/sda{i}").lower() for i in (1, 3, 4)]
        == ["vfat", "ntfs", "ntfs"],
        "Windows ESP/NTFS or Recovery filesystems changed",
    )
    hashes = {}
    for device, filenames in WINDOWS_FILES.items():
        g.mount_ro(device, "/")
        try:
            for filename in filenames:
                require(g.is_file(filename), f"Windows EFI/NTFS witness missing: {filename}")
                digest = str(g.checksum("sha256", filename)).lower()
                require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                        "invalid Windows witness checksum")
                hashes[filename] = digest
        finally:
            g.umount_all()
    return {"diskGuid": guid, "windowsPartitions": preserved, "windowsFilesSha256": hashes}


def validate_after(g, before: dict, plan: dict) -> dict:
    after = _windows_witness(g, 5)
    require(after == before,
            "Windows partition GUIDs, geometry, EFI/BCD or NTFS witness changed")
    partitions = g.part_list("/dev/sda")
    linux = partitions[4]
    require(
        linux["part_num"] == 5
        and linux["part_start"] == plan["startSector"] * SECTOR
        and linux["part_size"] == POP_ROOT_SIZE
        and g.part_get_gpt_type("/dev/sda", 5).lower() == LINUX_GPT
        and g.part_get_name("/dev/sda", 5) == ROOT_LABEL
        and linux["part_start"] >= (
            partitions[3]["part_start"] + partitions[3]["part_size"] + MIB
        ),
        "staged Linux partition identity or geometry mismatch",
    )
    # No mkfs, mounted Linux filesystem or root deployment in this phase.
    return {
        "schemaVersion": 1,
        "scenario": "win10_real_installed_postfirstboot_pop_unformatted_root_overlay_only",
        "windowsOfflineGptEspBcdNtfsReconciled": True,
        "sameDiskLinuxPartitionCreatedInCOWOverlay": True,
        "linuxRootSizeBytes": plan["sizeBytes"],
        "linuxRootStartSector": plan["startSector"],
        "linuxRootEndSector": plan["endSector"],
        "windowsPartitionCountBefore": 4,
        "totalPartitionCountAfter": 5,
        "backingWindowsQcOW2RemainedUnmodified": True,
        "sharedWindowsEspWasNotWritten": True,
        "linuxSystemInstalled": False,
        "windowsBootAfterPartitionStageVerified": False,
        "popFirstbootOnWindowsDiskVerified": False,
        "dualBootVerified": False,
        "winReAndBcdRecovered": False,
        "productionInstallationAuthorized": False,
        "stable": False,
    }


def stage_owned_overlay(base: Path, evidence: Path) -> dict:
    overlay = base.parent / "gaslux-pop-stage.qcow2"
    require_lab_owned(base, overlay, evidence)
    original_stat = base.stat()
    try:
        import guestfs
    except ImportError:
        raise DiskAuditError("host libguestfs binding unavailable") from None

    # BEFORE ANY COW write: independently verify both GPT header/array CRCs,
    # mirrored entries, protective MBR and partition identity in the base.
    crc_before = capture_owned_qcow2(base, expected_count=4)
    # PRECONDITION: host already ran inspect_owned_disk() on the shut-down
    # genuine Windows 10 VM. Independently repeat exact baseline here.
    with closing(guestfs.GuestFS(python_return_dict=True)) as g:
        g.add_drive_opts(str(base), readonly=1, format="qcow2")
        g.launch()
        layout = inspect_layout(g)
        before = _windows_witness(g, 4)
    plan = candidate_plan(layout)
    # An explicit same-directory QCOW2 COW child; no raw disk/loop/nbd target.
    subprocess.run([
        "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
        "-b", str(base), str(overlay),
    ], check=True, stdout=subprocess.DEVNULL, timeout=30)
    info = json.loads(subprocess.check_output(
        ["qemu-img", "info", "--output=json", str(overlay)], timeout=30,
    ))
    require(
        overlay.is_file() and not overlay.is_symlink()
        and overlay.stat().st_uid == os.getuid()
        and stat.S_ISREG(overlay.stat().st_mode)
        and overlay.stat().st_nlink == 1
        and info.get("format") == "qcow2"
        and info.get("virtual-size") == 128 * GIB
        and info.get("backing-filename") == str(base)
        and info.get("backing-filename-format") == "qcow2",
        "unsafe overlay backing chain or invalid owned QCOW2",
    )
    try:
        with closing(guestfs.GuestFS(python_return_dict=True)) as g:
            # Only the COW overlay is writable. Its base is a format-pinned
            # read-only backing file, and remains outside the guest's writers.
            g.add_drive_opts(str(overlay), readonly=0, format="qcow2")
            g.launch()
            require(_windows_witness(g, 4) == before,
                    "guest overlay did not match verified Windows baseline")
            g.part_add("/dev/sda", "p", plan["startSector"], plan["endSector"])
            g.part_set_gpt_type("/dev/sda", 5, LINUX_GPT)
            g.part_set_name("/dev/sda", 5, ROOT_LABEL)
            g.sync()
        # Independent host-level GPT CRC reconciliation AFTER changing only
        # overlay GPT. This must pass in addition to guestfs Windows witnesses.
        crc_after = capture_owned_qcow2(overlay, expected_count=5)
        reconcile_windows_and_root(crc_before, crc_after, plan)
        with closing(guestfs.GuestFS(python_return_dict=True)) as g:
            g.add_drive_opts(str(overlay), readonly=1, format="qcow2")
            g.launch()
            result = validate_after(g, before, plan)
        result["primaryAndBackupGptCrcVerifiedAfterStage"] = True
        result["windowsProtectiveMbrCanonical"] = crc_before["protectiveMbrCanonical"]
        result["windowsOversizedProtectiveMbrLabOnly"] = crc_before[
            "oversizedWindowsPmbrLabOnly"
        ]
        stat_after = base.stat()
        require(
            original_stat.st_size == stat_after.st_size
            and original_stat.st_mtime_ns == stat_after.st_mtime_ns
            and original_stat.st_blocks == stat_after.st_blocks,
            "original installed Windows QCOW2 changed during COW staging",
        )
        (evidence / "win10-pop-overlay-stage.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
        print("GASLUX_WINDOWS_POP_SAME_DISK_COW_GPT_STAGE_VERIFIED=1", flush=True)
        return result
    finally:
        # Never archive an overlay with actual Microsoft Windows bytes.
        overlay.unlink(missing_ok=True)
