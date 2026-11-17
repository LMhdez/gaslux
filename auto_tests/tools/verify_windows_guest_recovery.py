#!/usr/bin/env python3
"""Validate two real, independent Windows guest observations (read-only).

This proves selected Windows disk/boot invariants but never asserts that
Linux booted, Proxmox snapshots were restored, or a release is stable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

GUID = re.compile(r"^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,99}$")
FIELDS = {
    "schemaVersion",
    "source",
    "phase",
    "runId",
    "capturedAt",
    "computerName",
    "windowsVersion",
    "windowsProductType",
    "windowsBootTime",
    "windowsDiskId",
    "windowsPartitionGuid",
    "espPartitionGuid",
    "windowsEfiSha256",
    "espFilesystemUuid",
    "winreWimSha256",
    "secureBootEnabled",
    "winreEnabled",
    "winreRaw",
    "bcdCurrentRaw",
    "bcdAllRaw",
    "firmwareRaw",
    "bitlocker",
    "disks",
}
PART_FIELDS = {"guid", "number", "offset", "size", "gptType", "isBoot", "isSystem"}
DISK_FIELDS = {"id", "size", "logicalSectorSize", "partitionStyle", "partitions"}
BITLOCKER_FIELDS = {"protectionStatus", "volumeStatus", "encryptionPercentage"}


class EvidenceError(ValueError):
    """Recovery evidence is missing, malformed, or contradictory."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def instant(value: object) -> datetime:
    require(isinstance(value, str), "invalid timestamp type")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("invalid timestamp format") from exc
    require(
        dt.tzinfo is not None and dt.utcoffset().total_seconds() == 0,
        "timestamp must be timezone-aware UTC",
    )
    return dt


def disk_map(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {disk["id"]: disk for disk in doc["disks"]}


def partition_map(disk: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {part["guid"]: part for part in disk["partitions"]}


def validate(doc: Any, phase: str) -> None:
    require(type(doc) is dict and set(doc) == FIELDS, "unexpected evidence fields")
    require(
        type(doc["schemaVersion"]) is int and doc["schemaVersion"] == 1,
        "invalid recovery evidence version",
    )
    require(
        doc["source"] == "gaslux-windows-guest-readonly-v1",
        "evidence is not from the expected Windows guest collector",
    )
    require(doc["phase"] == phase, "unexpected evidence phase")
    require(
        isinstance(doc["runId"], str) and RUN_ID.fullmatch(doc["runId"]) is not None,
        "invalid transaction/run ID",
    )
    require(
        type(doc["windowsProductType"]) is int and doc["windowsProductType"] == 1
        and re.fullmatch(r"10\.0\.\d{4,5}(?:\.\d+)?", doc["windowsVersion"]) is not None,
        "only a verified Windows 10/11 client version can supply evidence",
    )
    for k in ("computerName", "windowsVersion", "windowsDiskId"):
        require(isinstance(doc[k], str) and bool(doc[k].strip()), f"missing {k}")
    require(
        instant(doc["capturedAt"]) >= instant(doc["windowsBootTime"]),
        "observation precedes Windows boot",
    )
    require(
        isinstance(doc["espFilesystemUuid"], str)
        and re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", doc["espFilesystemUuid"]) is not None
        and doc["espFilesystemUuid"] != "0000-0000",
        "missing verified FAT32 serial for the Windows ESP",
    )
    for k in ("windowsPartitionGuid", "espPartitionGuid"):
        require(isinstance(doc[k], str) and GUID.fullmatch(doc[k]) is not None, f"invalid {k}")
    require(
        doc["windowsPartitionGuid"] != doc["espPartitionGuid"],
        "Windows and ESP must be distinct partitions",
    )
    require(
        isinstance(doc["windowsEfiSha256"], str)
        and SHA256.fullmatch(doc["windowsEfiSha256"]) is not None,
        "missing SHA-256 of Windows Boot Manager",
    )
    require(
        isinstance(doc["winreWimSha256"], str)
        and SHA256.fullmatch(doc["winreWimSha256"]) is not None,
        "missing SHA-256 of WinRE image",
    )
    require(type(doc["secureBootEnabled"]) is bool, "Secure Boot status is unknown")
    require(doc["winreEnabled"] is True, "WinRE must be enabled and observable")
    require(
        isinstance(doc["winreRaw"], str)
        and re.search(
            r"(?im)(Windows\s+RE\s+status|Estado\s+(?:do|de)\s+Windows\s+RE)"
            r"\s*:\s*(Enabled|Ativado|Activado)\b",
            doc["winreRaw"],
        )
        is not None,
        "Windows WinRE raw status is not enabled",
    )
    for k, needle in (
        ("winreRaw", None),
        ("bcdCurrentRaw", "winload.efi"),
        ("bcdAllRaw", "winload.efi"),
        ("firmwareRaw", "bootmgfw.efi"),
    ):
        raw = doc[k]
        require(isinstance(raw, str) and 0 < len(raw) <= 120_000, f"empty or excessive {k}")
        if needle is not None:
            require(needle in raw.lower(), f"Windows loader absent from {k}")
    bl = doc["bitlocker"]
    require(
        type(bl) is dict and set(bl) == BITLOCKER_FIELDS,
        "missing BitLocker/Device Encryption state",
    )
    require(
        all(isinstance(bl[k], str) and bl[k].strip() for k in ("protectionStatus", "volumeStatus")),
        "incomplete BitLocker state",
    )
    percentage = bl["encryptionPercentage"]
    require(type(percentage) is int and 0 <= percentage <= 100, "invalid encryption percentage")
    disks = doc["disks"]
    require(isinstance(disks, list) and len(disks) > 0, "missing disk inventory")
    seen: set[str] = set()
    for disk in disks:
        require(type(disk) is dict and set(disk) == DISK_FIELDS, "invalid disk object")
        disk_id = disk["id"]
        require(
            isinstance(disk_id, str) and disk_id.strip() and disk_id not in seen,
            "duplicate or missing physical disk identity",
        )
        seen.add(disk_id)
        size, sector = disk["size"], disk["logicalSectorSize"]
        require(
            type(size) is int
            and size > 0
            and type(sector) is int
            and sector in (512, 4096)
            and size % sector == 0,
            "disk geometry or sector size invalid",
        )
        require(disk["partitionStyle"] in {"GPT", "MBR", "RAW"}, "unknown partition style")
        parts = disk["partitions"]
        require(isinstance(parts, list), "invalid partition array")
        require(
            disk["partitionStyle"] != "RAW" or not parts,
            "RAW disk cannot contain declared partitions",
        )
        partition_guids: set[str] = set()
        regions: list[tuple[int, int]] = []
        for part in parts:
            require(type(part) is dict and set(part) == PART_FIELDS, "invalid partition object")
            guid = part["guid"]
            require(
                isinstance(guid, str) and guid not in partition_guids,
                "duplicate partition identity",
            )
            partition_guids.add(guid)
            if disk["partitionStyle"] == "GPT":
                require(GUID.fullmatch(guid) is not None, "missing GPT partition GUID")
            require(
                type(part["number"]) is int
                and part["number"] > 0
                and type(part["offset"]) is int
                and type(part["size"]) is int,
                "invalid partition geometry type",
            )
            offset, length = part["offset"], part["size"]
            require(
                offset >= sector
                and length > 0
                and offset % sector == 0
                and length % sector == 0
                and offset + length <= size,
                "partition geometry out of bounds",
            )
            require(
                type(part["isBoot"]) is bool
                and type(part["isSystem"]) is bool
                and isinstance(part["gptType"], str),
                "invalid partition metadata",
            )
            regions.append((offset, offset + length))
        regions.sort()
        require(
            all(regions[i][1] <= regions[i + 1][0] for i in range(len(regions) - 1)),
            "overlapping partitions",
        )
    target = disk_map(doc).get(doc["windowsDiskId"])
    require(
        target is not None and target["partitionStyle"] == "GPT",
        "Windows source GPT disk is not observed",
    )
    target_partitions = partition_map(target)
    require(
        doc["windowsPartitionGuid"] in target_partitions
        and doc["espPartitionGuid"] in target_partitions,
        "Windows and EFI partitions are not on the expected disk",
    )
    require(
        target_partitions[doc["espPartitionGuid"]]["gptType"]
        == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "ESP partition has unexpected GPT type",
    )


def compare(before: dict[str, Any], after: dict[str, Any], mode: str) -> dict[str, Any]:
    require(mode in {"postinstall", "rollback"}, "unknown comparison mode")
    validate(before, "baseline")
    validate(after, mode)
    for k in (
        "runId",
        "computerName",
        "windowsVersion",
        "windowsDiskId",
        "windowsPartitionGuid",
        "espPartitionGuid",
        "windowsEfiSha256",
        "espFilesystemUuid",
        "windowsProductType",
        "winreWimSha256",
        "bitlocker",
        "bcdCurrentRaw",
        "bcdAllRaw",
        "winreRaw",
    ):
        require(before[k] == after[k], f"Windows recovery state changed: {k}")
    require(
        instant(after["capturedAt"]) > instant(before["capturedAt"]),
        "after observation is not later than baseline",
    )
    require(
        instant(after["windowsBootTime"]) > instant(before["windowsBootTime"]),
        "no actual subsequent Windows boot was observed",
    )
    if mode == "rollback":
        for k in ("bcdAllRaw", "firmwareRaw", "winreRaw", "secureBootEnabled"):
            require(before[k] == after[k], f"rollback did not restore {k}")
    else:
        require(
            not before["secureBootEnabled"] and not after["secureBootEnabled"],
            "CachyOS UEFI/GPT must reject Secure Boot enabled",
        )
        for observation in (before, after):
            encrypted = observation["bitlocker"]
            require(
                encrypted["protectionStatus"] == "Off"
                and encrypted["volumeStatus"] == "FullyDecrypted"
                and encrypted["encryptionPercentage"] == 0,
                "CachyOS installation must reject encrypted or protected Windows",
            )
    old_disks, new_disks = disk_map(before), disk_map(after)
    require(set(old_disks) == set(new_disks), "physical disk inventory changed")
    created = 0
    for disk_id, old in old_disks.items():
        new = new_disks[disk_id]
        for k in ("size", "logicalSectorSize", "partitionStyle"):
            require(old[k] == new[k], f"disk geometry changed: {disk_id}")
        prior, current = partition_map(old), partition_map(new)
        target = disk_id == before["windowsDiskId"]
        if mode == "rollback" or not target:
            require(prior == current, f"foreign/rollback partition map changed: {disk_id}")
            continue
        require(set(prior) <= set(current), "Windows/OEM/Recovery partition was removed")
        win_guid = before["windowsPartitionGuid"]
        win_old, win_new = prior[win_guid], current[win_guid]
        require(
            win_old["offset"] == win_new["offset"] and 0 < win_new["size"] <= win_old["size"],
            "Windows partition moved or enlarged",
        )
        for guid, original in prior.items():
            observed = current[guid]
            if guid == win_guid:
                require(
                    all(original[k] == observed[k] for k in PART_FIELDS - {"size"}),
                    "Windows GPT partition identity/type changed",
                )
            else:
                require(original == observed, f"ESP/Recovery/OEM partition was modified: {guid}")
        freed_start = win_new["offset"] + win_new["size"]
        freed_end = win_old["offset"] + win_old["size"]
        for guid in set(current) - set(prior):
            part = current[guid]
            require(
                freed_start <= part["offset"] and part["offset"] + part["size"] <= freed_end,
                "Linux partition is outside the authorized Windows shrink region",
            )
            created += 1
    if mode == "postinstall":
        require(created > 0, "no Linux installation partition found")
    return {
        "checked": True,
        "mode": mode,
        "windowsRebootObserved": True,
        "windowsBootManagerHashPreserved": True,
        "bcdCurrentPreserved": True,
        "winreEnabled": True,
        "diskGeometryChecked": True,
        "bitlockerPreserved": True,
        "newPartitionCount": created,
        "linuxBootVerified": False,
        "proxmoxSnapshotVerified": False,
        "reviewerSigned": False,
        "stable": False,
    }


def read(path: Path) -> dict[str, Any]:
    require(
        path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 2_000_000,
        "missing/unsafe evidence file",
    )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise EvidenceError("invalid Windows guest evidence JSON") from exc
    require(isinstance(value, dict), "Windows evidence JSON must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--mode", choices=("postinstall", "rollback"), required=True)
    args = parser.parse_args(argv)
    try:
        result = compare(read(args.before), read(args.after), args.mode)
    except EvidenceError as exc:
        print(json.dumps({"checked": False, "stable": False, "error": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
