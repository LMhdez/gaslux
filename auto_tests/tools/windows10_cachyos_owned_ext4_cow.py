#!/usr/bin/env python3
"""CI ONLY: format ONLY the transaction-owned fifth Linux GPT partition in COW.

This helper deliberately CANNOT install CachyOS. Do not use it with the empty
disk installer of PR #36: that installer clears a whole disk and its ESP.
No physical disk, ISO, Windows/EFI loader or host device is opened here.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import uuid

from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, sha256_file,
    validate_workspace,
)
from windows_cachyos_overlay_gpt_stage import (
    LINUX_TYPE, LINUX_NAME, LINUX_SIZE_BYTES,
)
from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, WINDOW_BYTES, SECTOR, qcow2_file_identity,
)
from windows_x64_installed_gpt_ro_audit import inspect_owned_disk

LAB_CONSENT = "I_ACCEPT_ONLY_OWNED_FIFTH_EXT4_IN_THROWAWAY_QCOW2"
LABEL = "GASLUXROOTLAB"
UUID = re.compile(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\Z")


class OwnedExt4Rejected(ValueError):
    """The guest filesystem operation did not pass a strict ownership gate."""


def require(yes: bool, why: str) -> None:
    if not yes:
        raise OwnedExt4Rejected(why)


def validate_partition_records(
    geometry: dict, linux: dict, parts: list[dict],
    linux_type_guid: str, linux_unique_guid: str,
) -> None:
    """Pure exact partition table contract; no guestfs/device activity."""
    require(type(geometry) is dict and type(linux) is dict
            and type(parts) is list and len(parts) == 5,
            "unexpected disk/partition inventory")
    windows = geometry.get("windowsPartitions")
    require(type(windows) is list and len(windows) == 4,
            "invalid four-partition Windows baseline")
    for index, candidate in enumerate(windows, 1):
        entry = parts[index - 1]
        require(type(entry) is dict and
                type(candidate) is dict and
                type(entry.get("part_num")) is int and
                type(entry.get("part_start")) is int and
                type(entry.get("part_size")) is int and
                entry["part_num"] == index and
                entry["part_start"] == candidate["firstLba"] * SECTOR and
                entry["part_size"] ==
                    (candidate["lastLba"] - candidate["firstLba"] + 1) * SECTOR,
                "Windows partition identity, order or geometry changed")
    root = parts[4]
    require(type(root) is dict and root.get("part_num") == 5
            and type(root.get("part_start")) is int
            and type(root.get("part_size")) is int,
            "fifth Linux partition missing or altered")
    require(root["part_start"] == linux.get("firstLba", -1) * SECTOR
            and root["part_size"] == LINUX_SIZE_BYTES
            and linux.get("lengthBytes") == LINUX_SIZE_BYTES
            and linux.get("index") == 5
            and linux.get("typeGuid") == LINUX_TYPE
            and linux.get("name") == LINUX_NAME
            and linux_type_guid.lower() == LINUX_TYPE,
            "Linux partition not bound to the staged, 24 GiB fifth entry")
    require(isinstance(linux.get("uniqueGuid"), str) and
            linux_unique_guid.lower() == linux["uniqueGuid"]
            and uuid.UUID(linux_unique_guid).int != 0,
            "Linux GPT unique GUID differs from transaction ownership")
    require(root["part_start"] >=
            (windows[-1]["lastLba"] + 1) * SECTOR
            and root["part_start"] + root["part_size"] <
            VIRTUAL_BYTES - 33 * SECTOR,
            "owned root overlaps Windows, backup GPT or disk boundary")


def format_fifth_ext4_only_in_cow(
    disk: Path, nvram: Path, geometry: dict, stage: dict,
    windows_hashes: dict,
) -> dict:
    """Real ext4 mkfs confined to exact fifth partition of a disposable COW.

    The pre-existing Windows 1..4 partitions are NEVER mounted RW, formatted,
    modified or given to a subprocess; no bootloader is installed.
    """
    validate_workspace(disk, nvram)
    require(os.environ.get("GASLUX_CACHYOS_ROOT_EXT4_COW_CONSENT") ==
            LAB_CONSENT and
            os.environ.get("GASLUX_CACHYOS_OVERLAY_GPT_CONSENT") ==
            "I_ACCEPT_DISPOSABLE_QCOW2_OVERLAY_GPT_ONLY",
            "separate hosted-lab-only root-ext4 consent required")
    require(type(geometry) is dict and
            geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True
            and geometry.get("storageWritesAuthorized") is False
            and geometry.get("releaseEligible") is False,
            "Windows GPT evidence cannot authorize an ext4 operation")
    require(type(stage) is dict and all(stage.get(k) is True for k in (
        "overlayGptLinuxRootEntryPrepared", "onlyDisposableOverlayModified",
        "windowsPartitionEntriesUnchanged", "windowsPartitionBoundarySamplesUnchanged",
        "bothGptMirrorsAfterStageVerified", "windowsBackingQcow2Unchanged",
        "windowsUefiVariablesUnchanged",
    )) and all(stage.get(k) is False for k in (
        "linuxRootFilesystemFormatted", "cachyosInstalled",
        "storageWritesAuthorized", "releaseEligible", "sameDiskDualBootVerified",
    )), "unverified or reused Linux GPT stage")
    require(type(windows_hashes) is dict and
            windows_hashes.get("partitionCount") == 4 and
            windows_hashes.get("espBcdPresent") is True and
            windows_hashes.get("winreImageOnRecoveryPresent") is True,
            "Windows EFI/BCD/WinRE read-only baseline missing")
    checkpoint = disk.parent / CHECKPOINT_DIR
    require(checkpoint.is_dir() and not checkpoint.is_symlink()
            and stat.S_IMODE(checkpoint.stat().st_mode) == 0o700
            and checkpoint.stat().st_uid == os.getuid(),
            "unowned or public COW checkpoint")
    overlay = checkpoint / OVERLAY_NAME
    owned_regular(overlay, checkpoint, OVERLAY_NAME)
    require(stat.S_IMODE(overlay.stat().st_mode) == 0o600
            and stat.S_IMODE(disk.stat().st_mode) == 0o400,
            "Windows backing is not frozen or COW is not private")
    baseline_id = qcow2_file_identity(disk)
    baseline_sha = sha256_file(disk)
    vars_sha = sha256_file(nvram)
    require(sha256_file(checkpoint / "windows-ovmf-baseline.fd") == vars_sha,
            "original OVMF variable checkpoint changed")
    require(sha256_file(checkpoint / "trial-ovmf-variables.fd") == vars_sha,
            "trial OVMF variables changed")
    linux = stage.get("linuxRoot")
    require(type(linux) is dict, "missing staged Linux root ownership")

    # Guestfs is invoked only after all host path, identity, size and
    # transaction gates have passed. The SINGLE attached disk is COW only.
    import guestfs
    guest = guestfs.GuestFS(python_return_dict=True)
    root_uuid = None
    try:
        guest.add_drive_opts(str(overlay), format="qcow2", readonly=0)
        guest.launch()
        devices = guest.list_devices()
        require(len(devices) == 1 and devices[0] == "/dev/sda"
                and guest.blockdev_getsize64(devices[0]) == VIRTUAL_BYTES,
                "unexpected guestfs disk count or virtual geometry")
        dev = devices[0]
        require(guest.part_get_parttype(dev) == "gpt",
                "missing Windows GPT")
        parts = guest.part_list(dev)
        require(len(parts) == 5 and
                not guest.mountpoints(),
                "unexpected partition count or mounted foreign filesystems")
        root = dev + "5"
        validate_partition_records(
            geometry, linux, parts,
            guest.part_get_gpt_type(dev, 5),
            guest.part_get_gpt_guid(dev, 5),
        )
        first = linux["firstLba"] * SECTOR
        # A reused filesystem or stale data in the unallocated target
        # must fail before the first ext4 sector is written.
        require(guest.vfs_type(root) in ("", "unknown")
                and guest.pread_device(dev, 4096, first) == bytes(4096)
                and guest.pread_device(dev, 4096,
                                       first + LINUX_SIZE_BYTES - 4096)
                    == bytes(4096),
                "nonempty or previously formatted Linux target")
        front = guest.pread_device(dev, WINDOW_BYTES, 0)
        back = guest.pread_device(dev, WINDOW_BYTES,
                                  VIRTUAL_BYTES - WINDOW_BYTES)
        before = []
        for win in geometry["windowsPartitions"]:
            for lba in (win["firstLba"], win["lastLba"] - 7):
                before.append((lba * SECTOR, guest.pread_device(
                    dev, 4096, lba * SECTOR)))
        # No host mkfs, no whole-disk format, no Windows ESP mount.
        # libguestfs mkfs is restricted to /dev/sda5 on this single COW.
        guest.mkfs("ext4", root, label=LABEL)
        guest.sync()
        root_uuid = guest.vfs_uuid(root)
        require(guest.vfs_type(root) == "ext4"
                and guest.vfs_label(root) == LABEL
                and isinstance(root_uuid, str)
                and UUID.fullmatch(root_uuid.lower()) is not None,
                "new ext4 metadata/UUID not verified")
        guest.mount_ro(root, "/")
        try:
            require(guest.is_dir("/lost+found"),
                    "new ext4 root is not mountable read-only")
        finally:
            guest.umount_all()
        require(guest.pread_device(dev, WINDOW_BYTES, 0) == front
                and guest.pread_device(dev, WINDOW_BYTES,
                                       VIRTUAL_BYTES-WINDOW_BYTES) == back
                and guest.part_list(dev) == parts,
                "formatting unexpectedly changed primary/backup GPT")
        for offset, data in before:
            require(guest.pread_device(dev, len(data), offset) == data,
                    "formatting wrote inside an existing Windows partition")
        # Independently hash actual Windows ESP BCD + Boot Manager on the
        # modified overlay before releasing the GuestFS appliance.
        guest.mount_ro(dev + "1", "/")
        try:
            require(guest.checksum(
                "sha256", "/EFI/Microsoft/Boot/bootmgfw.efi"
            ) == windows_hashes["espBootManagerSha256"] and
                guest.checksum(
                    "sha256", "/EFI/Microsoft/Boot/BCD"
                ) == windows_hashes["espBcdSha256"],
                "Windows EFI or BCD changed inside Linux trial overlay")
        finally:
            guest.umount_all()
    finally:
        try:
            guest.shutdown()
        finally:
            guest.close()
    require(qcow2_file_identity(disk) == baseline_id
            and sha256_file(disk) == baseline_sha
            and sha256_file(nvram) == vars_sha
            and inspect_owned_disk(disk) == windows_hashes,
            "Windows backing, OVMF or real EFI/BCD/WinRE changed after mkfs")
    print("GASLUX_WINDOWS10_OWNED_FIFTH_EXT4_FORMATTED_ONLY_IN_COW=1",
          flush=True)
    return {
        "linuxRootExt4FormattedInDiscardableCOW": True,
        "linuxPartitionGuid": linux["uniqueGuid"],
        "rootUuid": root_uuid,
        "linuxPartitionCount": 5,
        "onlyOwnedFifthPartitionFormatted": True,
        "windowsGptAndBoundarySamplesUnchanged": True,
        "windowsEfiBcdUnchangedInsideOverlay": True,
        "windowsBaseEfiBcdWinreHashesUnchanged": True,
        "windowsBackingQcow2Unchanged": True,
        "cachyosInstalled": False,
        "linuxBootVerified": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "windowsBcdWinreRestorationVerified": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("CI helper only; never invoke on physical disks or Windows")
