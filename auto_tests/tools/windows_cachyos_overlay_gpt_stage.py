#!/usr/bin/env python3
"""Experimental Windows 10 -> CachyOS partition-entry staging, disposable COW ONLY.

This writes FOUR tightly bounded GPT regions in a private QCOW2 external overlay:
backup entries/header, primary entries/header. The Windows backing QCOW2 is
read-only and every pre-existing Windows GPT partition byte is unchanged.
NO filesystem formatting, Linux installation, ESP/BCD/WinRE/NVRAM modification,
guest boot, physical disk access, or production-storage write authorization.
"""
from __future__ import annotations

import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import uuid

from windows_cachyos_cow_checkpoint import (
    BASE_NAME, CHECKPOINT_DIR, OVERLAY_NAME, VARS_NAME,
    CheckpointError, owned_regular, sha256_file, validate_workspace,
)
from windows_cachyos_qcow2_gpt_readonly import (
    SECTOR, VIRTUAL_BYTES, WINDOW_BYTES, TYPES, inspect_gpt_windows,
    inspect_owned_qcow2, header_at, part_array, qcow2_file_identity,
)

LINUX_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
LINUX_NAME = "GASLUX-CACHYOS-ROOT"
LINUX_SIZE_BYTES = 24 * 1024**3
MIN_REMAINING_BYTES = 16 * 1024**3
SECTOR_ALIGN = 2048
PART_ENTRY_BYTES = 128
PART_ARRAY_BYTES = 128 * PART_ENTRY_BYTES
LAB_CONSENT = "I_ACCEPT_DISPOSABLE_QCOW2_OVERLAY_GPT_ONLY"


class OverlayLayoutError(ValueError):
    pass


def require(check: bool, message: str) -> None:
    if not check:
        raise OverlayLayoutError(message)


def align_lba(lba: int) -> int:
    return ((lba + SECTOR_ALIGN - 1) // SECTOR_ALIGN) * SECTOR_ALIGN


def update_crc(header: bytes, entry_crc: int) -> bytes:
    result = bytearray(header)
    require(len(result) == SECTOR and result[:8] == b"EFI PART",
            "unrecognized GPT header before modification")
    struct.pack_into("<I", result, 88, entry_crc)
    struct.pack_into("<I", result, 16, 0)
    struct.pack_into("<I", result, 16,
                     binascii.crc32(result[:92]) & 0xffffffff)
    return bytes(result)


def build_linux_root_entry(
    original_front: bytes, original_back: bytes, partition_guid: uuid.UUID,
) -> tuple[bytes, bytes, dict[str, object]]:
    """Produce exact expected 1MiB windows with a fifth *unformatted* entry."""
    require(type(partition_guid) is uuid.UUID and partition_guid.int != 0,
            "nonempty explicit transaction-owned Linux partition GUID required")
    before = inspect_gpt_windows(original_front, original_back)
    require(before["candidateWindowsGptPrimaryAndBackupConsistent"] is True and
            before["storageWritesAuthorized"] is False,
            "original Windows-only GPT audit must be fail-closed")
    primary = original_front[SECTOR:2*SECTOR]
    backup = original_back[-SECTOR:]
    total = VIRTUAL_BYTES // SECTOR
    entries = bytearray(original_front[2*SECTOR:2*SECTOR+PART_ARRAY_BYTES])
    require(len(entries) == PART_ARRAY_BYTES and
            not any(entries[4*PART_ENTRY_BYTES:]),
            "foreign or reused Linux GPT slot is forbidden")
    win_records = entries[:4*PART_ENTRY_BYTES]
    require(all(
        bytes(partition_guid.bytes_le) != win_records[
            i*PART_ENTRY_BYTES+16:i*PART_ENTRY_BYTES+32]
        for i in range(4)
    ), "Linux GUID collides with a Windows partition")
    windows = before["windowsPartitions"]
    require(len(windows) == 4 and
            [p["type"] for p in windows] == list(TYPES),
            "Windows partition order changed before Linux staging")
    recovery_end = windows[-1]["lastLba"]
    first_usable, last_usable = struct.unpack_from("<QQ", primary, 40)
    start = align_lba(recovery_end + 1)
    sectors = LINUX_SIZE_BYTES // SECTOR
    end = start + sectors - 1
    remaining = (last_usable - end) * SECTOR
    require(first_usable <= start <= end <= last_usable and
            start > recovery_end and
            (start % SECTOR_ALIGN) == 0 and
            remaining >= MIN_REMAINING_BYTES,
            "CachyOS 24GiB root cannot fit inside verified post-Windows free GPT")
    offset = 4 * PART_ENTRY_BYTES
    entries[offset:offset+16] = uuid.UUID(LINUX_TYPE).bytes_le
    entries[offset+16:offset+32] = partition_guid.bytes_le
    struct.pack_into("<QQQ", entries, offset+32, start, end, 0)
    label = LINUX_NAME.encode("utf-16le")
    require(len(label) <= 72, "Linux GPT name exceeds UTF16 field")
    entries[offset+56:offset+56+len(label)] = label
    require(entries[:4*PART_ENTRY_BYTES] == win_records,
            "Linux partition staging changed a Windows GPT entry")
    entry_crc = binascii.crc32(entries) & 0xffffffff
    front = bytearray(original_front)
    back = bytearray(original_back)
    front[2*SECTOR:2*SECTOR+PART_ARRAY_BYTES] = entries
    back[WINDOW_BYTES-33*SECTOR:WINDOW_BYTES-SECTOR] = entries
    front[SECTOR:2*SECTOR] = update_crc(primary, entry_crc)
    back[-SECTOR:] = update_crc(backup, entry_crc)
    verify_linux_root_layout(original_front, original_back, bytes(front),
                             bytes(back), start, end, partition_guid)
    return bytes(front), bytes(back), {
        "index": 5,
        "typeGuid": LINUX_TYPE,
        "uniqueGuid": str(partition_guid),
        "name": LINUX_NAME,
        "firstLba": start,
        "lastLba": end,
        "lengthBytes": LINUX_SIZE_BYTES,
        "remainingUnallocatedAfterLinuxBytes": remaining,
    }


def verify_linux_root_layout(
    initial_front: bytes, initial_back: bytes,
    final_front: bytes, final_back: bytes,
    expected_start: int, expected_end: int, partition_guid: uuid.UUID,
) -> None:
    """Verify each modified byte stays inside GPT headers/entry arrays."""
    require(all(len(region) == WINDOW_BYTES for region in (
        initial_front, initial_back, final_front, final_back,
    )), "invalid bounded source or destination GPT regions")
    # Build allowed changed intervals: GPT header and entry arrays ONLY.
    def mask(region: bytes, windows: tuple[tuple[int, int], ...]) -> bytes:
        copy = bytearray(region)
        for start, length in windows:
            copy[start:start+length] = b"\x00" * length
        return bytes(copy)
    primary_intervals = ((SECTOR, SECTOR), (2*SECTOR, PART_ARRAY_BYTES))
    backup_intervals = ((WINDOW_BYTES-33*SECTOR, PART_ARRAY_BYTES),
                        (WINDOW_BYTES-SECTOR, SECTOR))
    require(mask(final_front, primary_intervals) ==
            mask(initial_front, primary_intervals) and
            mask(final_back, backup_intervals) ==
            mask(initial_back, backup_intervals),
            "overlay touched MBR or any byte outside GPT metadata windows")
    total = VIRTUAL_BYTES // SECTOR
    p = header_at(final_front, SECTOR, 1, total-1, total)
    b = header_at(final_back, WINDOW_BYTES-SECTOR, total-1, 1, total)
    pe = part_array(p, final_front, final_back, total)
    be = part_array(b, final_front, final_back, total)
    require(pe == be and pe[0:4*PART_ENTRY_BYTES] ==
            initial_front[2*SECTOR:2*SECTOR+4*PART_ENTRY_BYTES],
            "Windows GPT identities or mirrored Linux entry changed")
    require(p[56:72] == b[56:72] and
            p[56:72] == initial_front[SECTOR+56:SECTOR+72] and
            p[40:56] == b[40:56] and p[40:56] ==
            initial_front[SECTOR+40:SECTOR+56],
            "GPT disk identity or usable extent changed")
    rec = pe[4*PART_ENTRY_BYTES:5*PART_ENTRY_BYTES]
    start, end, attributes = struct.unpack_from("<QQQ", rec, 32)
    require(rec[:16] == uuid.UUID(LINUX_TYPE).bytes_le and
            rec[16:32] == partition_guid.bytes_le and
            start == expected_start and end == expected_end and
            attributes == 0 and
            rec[56:128].decode("utf-16le").rstrip("\x00") == LINUX_NAME and
            not any(pe[5*PART_ENTRY_BYTES:]),
            "unexpected CachyOS root partition identity, attributes or extras")


def stage_overlay_gpt(
    disk: Path, nvram: Path, geometry: dict[str, object],
    checkpoint_proof: dict[str, object],
    transaction_guid: uuid.UUID,
) -> dict[str, object]:
    """Exactly four bounded GPT device writes, only in a hosted VM QCOW2 overlay."""
    require(os.environ.get("GASLUX_CACHYOS_OVERLAY_GPT_CONSENT") == LAB_CONSENT,
            "separate explicit disposable overlay GPT-only consent required")
    require(type(geometry) is dict and
            geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True and
            geometry.get("storageWritesAuthorized") is False and
            geometry.get("releaseEligible") is False,
            "refusing Linux GPT staging without read-only Windows disk geometry")
    require(type(checkpoint_proof) is dict and
            checkpoint_proof.get("candidateWindowsCowCheckpointPrepared") is True and
            checkpoint_proof.get("trialOverlayInitiallyMatchesWindows") is True and
            checkpoint_proof.get("windowsBaselineUnchangedDuringCheckpoint") is True and
            checkpoint_proof.get("snapshotIndependentlyRestorable") is False and
            checkpoint_proof.get("storageWritesAuthorized") is False,
            "refusing staging without candidate private Windows COW checkpoint")
    validate_workspace(disk, nvram)
    checkpoint = disk.parent / CHECKPOINT_DIR
    require(checkpoint.is_dir() and not checkpoint.is_symlink() and
            checkpoint.stat().st_uid == os.getuid() and
            stat.S_IMODE(checkpoint.stat().st_mode) == 0o700,
            "unsafe external COW checkpoint directory")
    overlay = checkpoint / OVERLAY_NAME
    owned_regular(overlay, checkpoint, OVERLAY_NAME)
    require(stat.S_IMODE(overlay.stat().st_mode) == 0o600,
            "writable COW overlay must be private mode 0600")
    baseline_vars = checkpoint / "windows-ovmf-baseline.fd"
    trial_vars = checkpoint / "trial-ovmf-variables.fd"
    owned_regular(baseline_vars, checkpoint, baseline_vars.name)
    owned_regular(trial_vars, checkpoint, trial_vars.name)
    require(stat.S_IMODE(disk.stat().st_mode) == 0o400 and
            stat.S_IMODE(baseline_vars.stat().st_mode) == 0o400,
            "Windows baseline disk/UEFI variables not protected")
    vars_hash = sha256_file(nvram)
    require(vars_hash == checkpoint_proof["uefiVarsCopySha256"] and
            sha256_file(baseline_vars) == vars_hash and
            sha256_file(trial_vars) == vars_hash,
            "Windows UEFI variables or their copies changed before staging")
    # Confirm backing and base ownership again immediately before opening
    # the *overlay only* RW in a private appliance.
    info = json.loads(subprocess.run([
        "qemu-img", "info", "-f", "qcow2", "--output=json", str(overlay),
    ], check=True, capture_output=True, text=True, timeout=30).stdout)
    require(info.get("format") == "qcow2" and
            info.get("virtual-size") == VIRTUAL_BYTES and
            info.get("backing-filename") == str(disk) and
            info.get("backing-filename-format") == "qcow2" and
            not info.get("encrypted", False),
            "overlay not bound to exact protected Windows base")
    # The fresh overlay MUST still be byte-for-byte identical to the
    # protected Windows base BEFORE any GPT write. A previous/stale guest
    # mutation elsewhere on NTFS/ESP cannot be detected by GPT checks alone.
    # Use QEMU's full logical compare; it reads files, not host block devices.
    comparison = subprocess.run([
        "qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
        str(disk), str(overlay),
    ], check=False, capture_output=True, text=True, timeout=180)
    require(comparison.returncode == 0,
            "overlay already contains foreign or unexpected Windows disk writes")
    original_identity = qcow2_file_identity(disk)
    reread = inspect_owned_qcow2(disk)
    require(reread["windowsPartitions"] == geometry["windowsPartitions"] and
            reread["diskGuidSha256"] == geometry["diskGuidSha256"],
            "Windows disk identity/geometry changed since GPT checkpoint")
    # Guestfs is imported ONLY in this expressly authorized disposable mode.
    # No host /dev device is opened, and there is exactly one attached file.
    import guestfs
    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.add_drive_opts(str(overlay), format="qcow2", readonly=0)
        guest.launch()
        devices = guest.list_devices()
        require(len(devices) == 1 and
                guest.blockdev_getsize64(devices[0]) == VIRTUAL_BYTES,
                "libguestfs opened an unexpected device/size")
        device = devices[0]
        front = guest.pread_device(device, WINDOW_BYTES, 0)
        back = guest.pread_device(device, WINDOW_BYTES,
                                  VIRTUAL_BYTES-WINDOW_BYTES)
        require(inspect_gpt_windows(front, back)["windowsPartitions"] ==
                geometry["windowsPartitions"],
                "overlay no longer matches Windows-only GPT baseline")
        # GPT is the only writable surface. No Windows partition is mounted.
        windows_samples = []
        for partition in geometry["windowsPartitions"]:
            for lba in (partition["firstLba"],
                        partition["lastLba"] - 7):
                windows_samples.append((
                    lba*SECTOR, guest.pread_device(device, 4096, lba*SECTOR),
                ))
        updated_front, updated_back, linux = build_linux_root_entry(
            front, back, transaction_guid,
        )
        writes = (
            ((VIRTUAL_BYTES - 33*SECTOR),
             updated_back[WINDOW_BYTES-33*SECTOR:WINDOW_BYTES-SECTOR]),
            ((VIRTUAL_BYTES - SECTOR), updated_back[-SECTOR:]),
            (2*SECTOR,
             updated_front[2*SECTOR:2*SECTOR+PART_ARRAY_BYTES]),
            (SECTOR, updated_front[SECTOR:2*SECTOR]),
        )
        require(len(writes) == 4 and
                [len(data) for _, data in writes] ==
                [PART_ARRAY_BYTES, SECTOR, PART_ARRAY_BYTES, SECTOR],
                "write whitelist escaped the GPT header/array regions")
        for offset, data in writes:
            written = guest.pwrite_device(device, data, offset)
            require(written == len(data), "short GPT write; discard overlay")
        guest.sync()
        seen_front = guest.pread_device(device, WINDOW_BYTES, 0)
        seen_back = guest.pread_device(device, WINDOW_BYTES,
                                       VIRTUAL_BYTES-WINDOW_BYTES)
        require(seen_front == updated_front and
                seen_back == updated_back,
                "overlay GPT byte-for-byte postwrite check failed")
        verify_linux_root_layout(front, back, seen_front, seen_back,
                                 linux["firstLba"], linux["lastLba"],
                                 transaction_guid)
        for offset, sample in windows_samples:
            require(guest.pread_device(device, len(sample), offset) == sample,
                    "Windows partition content changed during GPT staging")
    finally:
        try:
            guest.shutdown()
        finally:
            guest.close()
    require(qcow2_file_identity(disk) == original_identity and
            sha256_file(nvram) == vars_hash and
            sha256_file(baseline_vars) == vars_hash and
            sha256_file(trial_vars) == vars_hash,
            "Windows backing QCOW2 or OVMF variables changed")
    # This is only an overlay partition table entry. Never claim that an
    # installed Linux system exists or that any production writes are safe.
    return {
        "overlayGptLinuxRootEntryPrepared": True,
        "onlyDisposableOverlayModified": True,
        "windowsPartitionEntriesUnchanged": True,
        "windowsPartitionBoundarySamplesUnchanged": True,
        "protectiveMbrAndGptOutsideWhitelistUnchanged": True,
        "bothGptMirrorsAfterStageVerified": True,
        "windowsBackingQcow2Unchanged": True,
        "windowsUefiVariablesUnchanged": True,
        "linuxRoot": linux,
        "linuxRootFilesystemFormatted": False,
        "cachyosInstalled": False,
        "cachyosFirstBootVerified": False,
        "windowsBootAfterOverlayMutationVerified": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "rollbackProven": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit(
        "Library only: no physical disks, Linux install, ESP writes or boot proof")
