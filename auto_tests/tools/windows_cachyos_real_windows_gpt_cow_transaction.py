#!/usr/bin/env python3
"""Hosted GitHub CI only: add/delete Linux GPT entry on Windows 10 COW disk.

A real installed Windows base is ALWAYS opened read-only, never modified.
All modifications are confined to new, uniquely owned QCOW2 overlays.
This is not the CachyOS installer nor a production disk-write authorization.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import uuid

from windows_cachyos_qcow2_gpt_readonly import (
    WINDOW_BYTES, VIRTUAL_BYTES, SECTOR, GeometryError,
    inspect_owned_qcow2, inspect_gpt_windows, qcow2_file_identity,
    require_unchanged_qcow2, header_at, part_array,
)
from windows_cachyos_qcow2_overlay_discard import (
    owned_base, read_windows,
)
from windows_x64_installed_gpt_ro_audit import inspect_owned_disk

LINUX_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
LINUX_GUID = str(uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-win10-cow-only-gpt-lab"))


def require(ok: bool, message: str) -> None:
    if not ok:
        raise GeometryError(message)


def command(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True,
                          timeout=60).stdout


def verify_overlay(base: Path, overlay: Path) -> None:
    require(overlay.parent.parent == base.parent
            and overlay.parent.name.startswith("gaslux-windows-linux-gpt-")
            and not overlay.parent.is_symlink()
            and stat.S_IMODE(overlay.parent.stat().st_mode) == 0o700
            and overlay.parent.stat().st_uid == os.getuid()
            and overlay.name == "fresh-transaction-only.qcow2"
            and overlay.is_file() and not overlay.is_symlink()
            and overlay.stat().st_uid == os.getuid()
            and overlay.stat().st_nlink == 1,
            "unowned transaction COW image")
    info = json.loads(command("qemu-img", "info", "--output=json", str(overlay)))
    require(info.get("format") == "qcow2"
            and info.get("virtual-size") == VIRTUAL_BYTES
            and info.get("full-backing-filename") == str(base),
            "wrong Windows backing chain or virtual geometry")


def allocate_overlay(base: Path, overlay: Path) -> None:
    require(not overlay.exists() and not overlay.is_symlink(),
            "refuse reused COW transaction")
    command("qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
            "-b", str(base), str(overlay))
    verify_overlay(base, overlay)


def entry_arrays(front: bytes, back: bytes) -> tuple[bytes, bytes]:
    sectors = VIRTUAL_BYTES // SECTOR
    primary = header_at(front, SECTOR, 1, sectors - 1, sectors)
    backup = header_at(back, WINDOW_BYTES-SECTOR, sectors-1, 1, sectors)
    p = part_array(primary, front, back, sectors)
    b = part_array(backup, front, back, sectors)
    require(p == b, "primary/backup GPT entry arrays disagree")
    return p, b


def verify_fifth_entry(
    overlay: Path, scratch: Path, baseline: tuple[bytes, bytes],
    first: int, last: int, expected_present: bool,
) -> None:
    front, back = read_windows(overlay, scratch)
    original, _ = entry_arrays(*baseline)
    actual, _ = entry_arrays(front, back)
    require(actual[:512] == original[:512],
            "Windows GPT entries 1-4 changed")
    require(not any(actual[5*128:]), "foreign GPT entry after slot 5")
    fifth = actual[512:640]
    if expected_present:
        require(str(uuid.UUID(bytes_le=fifth[:16])) == LINUX_TYPE
                and str(uuid.UUID(bytes_le=fifth[16:32])) == LINUX_GUID
                and struct.unpack_from("<QQ", fifth, 32) == (first, last),
                "transaction Linux GPT entry has wrong type/identity/extent")
        require(first % 2048 == 0 and (last + 1) % 2048 == 0,
                "unbounded or unaligned GPT new partition")
    else:
        require(not any(fifth) and actual == original,
                "Linux GPT record not removed exactly")
        # The existing Windows-only strict reader must accept both GPT copies.
        report = inspect_gpt_windows(front, back)
        require(report["candidateWindowsGptPrimaryAndBackupConsistent"] is True
                and report["storageWritesAuthorized"] is False,
                "Windows geometry invalid after deleting Linux entry")


def guestfs_add_delete(
    overlay: Path, base: Path, baseline: tuple[bytes, bytes],
    extent: dict, scratch: Path, *, delete: bool,
) -> None:
    import guestfs

    first = extent["firstLba"]
    last = first + 10 * (1024**3 // SECTOR) - 1
    require(first > 0 and last <= extent["lastLba"]
            and first % 2048 == 0 and (last + 1) % 2048 == 0,
            "Linux partition proposed outside aligned recovery-safe extent")
    verify_overlay(base, overlay)
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        # The ONLY writable guestfs target is the explicitly new COW overlay.
        g.add_drive_opts(str(overlay), readonly=0, format="qcow2")
        g.launch()
        require(g.list_devices() == ["/dev/sda"]
                and g.part_get_parttype("/dev/sda") == "gpt"
                and g.blockdev_getsize64("/dev/sda") == VIRTUAL_BYTES,
                "unexpected disposable virtual disk geometry")
        found = g.part_list("/dev/sda")
        require(len(found) == 4 and
                [p["part_num"] for p in found] == [1,2,3,4],
                "foreign existing partitions in Windows disk")
        g.part_add("/dev/sda", "p", first, last)
        g.part_set_gpt_type("/dev/sda", 5, LINUX_TYPE)
        g.part_set_gpt_guid("/dev/sda", 5, LINUX_GUID)
        g.sync()
    finally:
        g.close()

    verify_fifth_entry(overlay, scratch, baseline, first, last, True)
    print("GASLUX_WINDOWS_COW_LINUX_GPT_ENTRY_5_ADDED=1", flush=True)
    if delete:
        g = guestfs.GuestFS(python_return_dict=True)
        try:
            g.add_drive_opts(str(overlay), readonly=0, format="qcow2")
            g.launch()
            require(g.part_get_gpt_guid("/dev/sda", 5).lower() == LINUX_GUID
                    and g.part_get_gpt_type("/dev/sda", 5).lower() == LINUX_TYPE,
                    "refusing deletion of non-owned Linux GPT partition")
            g.part_del("/dev/sda", 5)
            g.sync()
        finally:
            g.close()
        verify_fifth_entry(overlay, scratch, baseline, first, last, False)
        print("GASLUX_WINDOWS_COW_LINUX_GPT_ENTRY_5_DELETED=1", flush=True)


def trial(base: Path) -> dict:
    owned_base(base)
    require(os.environ.get("GASLUX_WINDOWS_LINUX_GPT_COW_CONSENT")
            == "I_ACCEPT_FRESH_COW_GPT_PARTITION_ONLY"
            and os.environ.get("GASLUX_WINDOWS_GUESTFS_TEST")
                == "I_ACCEPT_READONLY_FILESYSTEM_AUDIT",
            "missing explicit GPT COW experiment consent")
    identity = qcow2_file_identity(base)
    before_report = inspect_owned_qcow2(base)
    fs_before = inspect_owned_disk(base)
    require(before_report["candidateWindowsGptPrimaryAndBackupConsistent"] is True
            and before_report["storageWritesAuthorized"] is False
            and before_report["observedPostWindowsFreeExtent"]["readOnlyObservation"] is True
            and len(before_report["windowsPartitions"]) == 4
            and fs_before["winreImageOnRecoveryPresent"] is True,
            "real Windows read-only prerequisite not met")
    require_unchanged_qcow2(base, identity)

    with tempfile.TemporaryDirectory(
        prefix="gaslux-windows-linux-gpt-", dir=base.parent
    ) as temp:
        scratch = Path(temp)
        baseline = read_windows(base, scratch)
        require_unchanged_qcow2(base, identity)
        extent = before_report["observedPostWindowsFreeExtent"]
        # First exercise a successful add/delete on an owned disposable COW.
        overlay = scratch / "fresh-transaction-only.qcow2"
        allocate_overlay(base, overlay)
        guestfs_add_delete(overlay, base, baseline, extent, scratch, delete=True)
        require_unchanged_qcow2(base, identity)
        overlay.unlink()
        require(not overlay.exists(), "transaction overlay was not discarded")
        # Second exercise an interrupted transaction (add, no delete).
        allocate_overlay(base, overlay)
        guestfs_add_delete(overlay, base, baseline, extent, scratch, delete=False)
        require_unchanged_qcow2(base, identity)
        # Recovery is COW DISCARD. Do not call a Windows production writer.
        overlay.unlink()
        require(not overlay.exists(), "faulted overlay survived rollback")
        require(read_windows(base, scratch) == baseline,
                "original Windows GPT windows changed after rollback")
        require(inspect_owned_qcow2(base) == before_report,
                "Windows GPT read-only report changed after COW rollback")
        require(inspect_owned_disk(base) == fs_before,
                "Windows ESP/BCD/WinRE/NTFS evidence changed after COW rollback")
        require_unchanged_qcow2(base, identity)

    print("GASLUX_WINDOWS_COW_LINUX_GPT_INTERRUPTED_ADD_ROLLBACK_VERIFIED=1",
          flush=True)
    print("GASLUX_WINDOWS_COW_BACKING_GPT_ESP_BCD_WINRE_UNCHANGED=1",
          flush=True)
    return {
        "linuxGptEntry5AddedInsideOverlay": True,
        "linuxGptEntry5DeletedInsideOverlay": True,
        "interruptedGptAdditionRolledBackByDiscard": True,
        "windowsBaseGptEspBcdWinreUnchanged": True,
        "linuxSystemInstalled": False,
        "linuxBootVerified": False,
        "inPlaceWindowsRollbackVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
        "sameDiskDualBootVerified": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only: invoked solely after verified real Windows shutdown")
