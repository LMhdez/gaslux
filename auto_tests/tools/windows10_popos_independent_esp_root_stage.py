#!/usr/bin/env python3
"""Windows 10 + Pop-owned ESP/root GPT stage in disposable QCOW2 only.

No format, Linux install, EFI write, bootloader, Windows shrink or host disk I/O.
On any error the private COW overlay is discarded; Windows backing is read-only.
"""
from __future__ import annotations

from contextlib import closing
from typing import Callable
import hashlib
import json
import os
import stat
import subprocess
import uuid
from pathlib import Path

from windows_x64_installed_gpt_ro_audit import (
    DiskAuditError, inspect_layout, require,
)
from windows10_popos_gpt_mirror_gate import (
    capture_owned_qcow2, ESP, LINUX_TYPE,
)
from windows10_popos_same_disk_overlay_stage import (
    GIB, SECTOR, _compensate_normalized_pmbr, _windows_witness,
    require_lab_owned,
)
from windows10_popos_independent_esp_plan import propose_owned_esp_root

PAIR_CONSENT = "I_ACCEPT_ONLY_DISPOSABLE_WIN10_POP_ESP_ROOT_QCOW2"
WINDOWS_VIRTUAL_BYTES = 128 * GIB


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def reconcile_owned_pair(before: dict, after: dict, plan: dict) -> None:
    """Reject all foreign GPT/MBR and unowned-partition mutations."""
    require(
        before["primaryAndBackupCrcVerified"] is True
        and after["primaryAndBackupCrcVerified"] is True
        and before["popEsp"] is None and before["linuxRoot"] is None
        and after["popEsp"] is not None and after["linuxRoot"] is not None,
        "Windows/Pop GPT mirror evidence missing",
    )
    for key in (
        "diskGuid", "windowsEntryHex", "windowsPartitions", "mbrSha256",
        "protectiveMbrCanonical", "oversizedWindowsPmbrLabOnly",
        "firstUsableLba", "lastUsableLba",
    ):
        require(before[key] == after[key], "foreign GPT or MBR changed: " + key)
    require(
        plan["windowsDiskGuid"] == before["diskGuid"]
        and plan["windowsProtectiveMbrSha256"] == before["mbrSha256"],
        "signed-input-shaped proposal differs from measured Windows GPT",
    )
    for part, seen, expected_type in zip(
        plan["partitions"], (after["popEsp"], after["linuxRoot"]), (ESP, LINUX_TYPE)
    ):
        require(
            part["typeGuid"] == expected_type
            and seen["number"] == part["index"]
            and seen["type"] == expected_type
            and seen["guid"] == part["uniqueGuid"]
            and seen["startLba"] == part["startSector"]
            and seen["endLba"] == part["endSector"]
            and seen["attrs"] == 0
            and (seen["endLba"] - seen["startLba"] + 1) * SECTOR == part["sizeBytes"]
            and part["formatRequested"] is False,
            "owned ESP/root GPT partition does not match proposal",
        )


def _write_exact_owned_partition(g, p: dict) -> None:
    """Write only the explicitly planned VM partition and bind its PARTUUID.

    libguestfs/sgdisk otherwise generates a new random partition GUID; that
    must never be mistaken for the transaction-owned GUID in the plan.
    """
    require(
        type(p) is dict and p.get("index") in (5, 6)
        and p.get("formatRequested") is False
        and isinstance(p.get("uniqueGuid"), str)
        and isinstance(p.get("name"), str)
        and isinstance(p.get("typeGuid"), str)
        and type(p.get("startSector")) is int
        and type(p.get("endSector")) is int
        and p["endSector"] > p["startSector"],
        "untrusted Pop-owned GPT entry before VM write",
    )
    n = p["index"]
    g.part_add("/dev/sda", "p", p["startSector"], p["endSector"])
    g.part_set_gpt_type("/dev/sda", n, p["typeGuid"])
    g.part_set_gpt_guid("/dev/sda", n, p["uniqueGuid"])
    g.part_set_name("/dev/sda", n, p["name"])
    require(
        str(g.part_get_gpt_type("/dev/sda", n)).lower() == p["typeGuid"]
        and str(g.part_get_gpt_guid("/dev/sda", n)).lower() == p["uniqueGuid"]
        and str(g.part_get_name("/dev/sda", n)) == p["name"],
        "native guestfs failed to apply exact transaction-owned Pop GUID/type/name",
    )


def stage_owned_esp_root(
    base: Path, evidence: Path,
    *, post_boot_callback: Callable[[Path, dict], dict] | None = None,
) -> dict:
    """Stage ONLY two unformatted owned GPT entries after genuine Windows boot."""
    overlay = base.parent / "gaslux-pop-stage.qcow2"
    require_lab_owned(base, overlay, evidence)
    require(
        os.environ.get("GASLUX_WIN10_POP_PAIR_COW_CONSENT") == PAIR_CONSENT,
        "distinct Pop ESP/root hosted-COW consent missing",
    )
    original_stat = base.stat()
    try:
        import guestfs
    except ImportError:
        raise DiskAuditError("host libguestfs binding unavailable") from None

    # Capture BOTH Windows GPT mirrors and the whole Windows backing hash
    # before any COW mutation. The source QCOW2 is never attached writable.
    crc_before = capture_owned_qcow2(base, expected_count=4)
    original_hash = _sha256(base)
    with closing(guestfs.GuestFS(python_return_dict=True)) as g:
        g.add_drive_opts(str(base), readonly=1, format="qcow2")
        g.launch()
        layout = inspect_layout(g)
        windows_before = _windows_witness(g, 4)
        original_pmbr = g.pread_device("/dev/sda", SECTOR, 0)
        require(
            isinstance(original_pmbr, bytes)
            and hashlib.sha256(original_pmbr).hexdigest() == crc_before["mbrSha256"],
            "Windows protective MBR disagrees with independent GPT evidence",
        )
    plan = propose_owned_esp_root(layout, crc_before, uuid.uuid4(), uuid.uuid4())
    require(
        plan["productionInstallationAuthorized"] is False
        and plan["windowsEspToRemainUntouched"] is True
        and len(plan["partitions"]) == 2,
        "unexpected Pop pair-stage proposal",
    )
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base),
         str(overlay)],
        check=True, stdout=subprocess.DEVNULL, timeout=30,
    )
    info = json.loads(subprocess.check_output(
        ["qemu-img", "info", "--output=json", str(overlay)], timeout=30,
    ))
    require(
        overlay.is_file() and not overlay.is_symlink()
        and overlay.stat().st_uid == os.getuid()
        and stat.S_ISREG(overlay.stat().st_mode)
        and overlay.stat().st_nlink == 1
        and info.get("format") == "qcow2"
        and info.get("virtual-size") == WINDOWS_VIRTUAL_BYTES
        and info.get("backing-filename") == str(base)
        and info.get("backing-filename-format") == "qcow2",
        "unsafe pair-stage Windows COW backing chain",
    )
    try:
        with closing(guestfs.GuestFS(python_return_dict=True)) as g:
            g.add_drive_opts(str(overlay), readonly=0, format="qcow2")
            g.launch()
            require(_windows_witness(g, 4) == windows_before,
                    "new Pop COW did not match genuine Windows baseline")
            for proposed in plan["partitions"]:
                _write_exact_owned_partition(g, proposed)
            g.sync()
            # libguestfs normalizes observed Microsoft PMBR CHS/count.
            # Restore only the previously proven allowlisted 4 or 7 bytes,
            # never a general MBR "repair" and never on Windows backing.
            repaired = _compensate_normalized_pmbr(g, original_pmbr, crc_before)

        crc_after = capture_owned_qcow2(overlay, expected_count=6)
        reconcile_owned_pair(crc_before, crc_after, plan)
        with closing(guestfs.GuestFS(python_return_dict=True)) as g:
            g.add_drive_opts(str(overlay), readonly=1, format="qcow2")
            g.launch()
            require(_windows_witness(g, 6) == windows_before,
                    "Windows ESP/BCD/WinRE/NTFS or GPT changed after pair stage")
            layout_after = g.part_list("/dev/sda")
            require(len(layout_after) == 6, "unexpected postwrite partitions")
            for proposed in plan["partitions"]:
                n = proposed["index"]
                p = layout_after[n-1]
                require(
                    p["part_num"] == n
                    and p["part_start"] == proposed["startSector"] * SECTOR
                    and p["part_size"] == proposed["sizeBytes"]
                    and g.part_get_gpt_type("/dev/sda", n).lower()
                    == proposed["typeGuid"]
                    and g.part_get_gpt_guid("/dev/sda", n).lower()
                    == proposed["uniqueGuid"]
                    and g.part_get_name("/dev/sda", n) == proposed["name"],
                    "guestfs Pop owned partition reconciliation failed",
                )
                require(
                    (g.vfs_type(f"/dev/sda{n}") or "").lower()
                    in ("", "unknown"),
                    "staged Pop ESP/root must remain UNFORMATTED",
                )
        now = base.stat()
        require(
            now.st_size == original_stat.st_size
            and now.st_mtime_ns == original_stat.st_mtime_ns
            and now.st_ino == original_stat.st_ino
            and _sha256(base) == original_hash,
            "genuine Windows QCOW2 backing modified",
        )
        result = {
            "schemaVersion": 1,
            "scenario": "windows10_real_installed_pop_separate_esp_root_gpt_only",
            "originalWindowsGptCrcVerified": True,
            "afterPopGptCrcVerified": True,
            "windowsFourPartitionEntriesUnchanged": True,
            "windowsEspBcdWinreNtfsWitnessUnchanged": True,
            "windowsBackingQcow2Sha256Unchanged": True,
            "windowsOriginalProtectiveMbrUnchanged": True,
            "windowsPmbrCompensationBytes": repaired,
            "ownedPopEspAndRootGptEntriesStagedInCOW": True,
            "popEspFormatted": False,
            "popRootFormatted": False,
            "independentWindowsPostStageBootVerified": False,
            "popSystemInstalled": False,
            "popSystemFirstbootVerified": False,
            "sameDiskDualBootVerified": False,
            "winReAndBcdRecovered": False,
            "productionInstallationAuthorized": False,
            "stable": False,
            "ownedPartitionGuids": [
                p["uniqueGuid"] for p in plan["partitions"]
            ],
        }
        if post_boot_callback is not None:
            require(
                callable(post_boot_callback)
                and os.environ.get("GASLUX_WIN10_POP_PAIR_POSTBOOT_CONSENT")
                == "I_ACCEPT_DISPOSABLE_POP_PAIR_WINDOWS_THIRD_BOOT",
                "missing isolated Windows third-boot consent or callback",
            )
            # Caller boots ONLY the pre-verified child overlay with a distinct
            # OVMF VARS copy and no installer media. Never write the backing.
            witness = post_boot_callback(overlay, plan)
            require(
                type(witness) is dict
                and witness.get("windowsGuestPostPairBootVerified") is True
                and witness.get("originalWindowsOvmfVarsUnchanged") is True
                and isinstance(witness.get("windowsGuestPostPairSerialSha256"), str)
                and len(witness["windowsGuestPostPairSerialSha256"]) == 64,
                "genuine Windows post-pair guest proof missing",
            )
            post_crc = capture_owned_qcow2(overlay, expected_count=6)
            reconcile_owned_pair(crc_before, post_crc, plan)
            with closing(guestfs.GuestFS(python_return_dict=True)) as g:
                g.add_drive_opts(str(overlay), readonly=1, format="qcow2")
                g.launch()
                require(_windows_witness(g, 6) == windows_before,
                        "postboot Windows EFI/BCD/WinRE/NTFS witness changed")
            require(_sha256(base) == original_hash,
                    "postboot Windows QCOW2 backing changed")
            result["independentWindowsPostStageBootVerified"] = True
            result["windowsGuestPostPairSerialSha256"] = witness[
                "windowsGuestPostPairSerialSha256"]
            result["windowsGuestPostPairBootAndGptReconciled"] = True
            print("GASLUX_WIN10_POP_PAIR_WINDOWS_THIRD_BOOT_RECONCILED=1",
                  flush=True)
        dest = evidence / "win10-pop-independent-esp-root-stage.json"
        with dest.open("x", encoding="utf-8") as out:
            out.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print("GASLUX_WIN10_POP_ESP_ROOT_GPT_COW_STAGE_VERIFIED=1", flush=True)
        return result
    finally:
        # The only disposable COW trial is deleted, never the Windows baseline.
        overlay.unlink(missing_ok=True)
