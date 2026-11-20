#!/usr/bin/env python3
"""Read-only candidate GPT write-set for Bazzite's *legacy* native installer.

This module never invokes partition creation, formatting, mount, bootloader or
Anaconda. Its report is a laboratory proposal, not permission to write. The
legacy 42 media is not independently authenticated; keep all gates closed.
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from pathlib import Path

from bazzite_gpt_fixture import (
    IMAGE_NAME,
    PARTITIONS,
    Refusal,
    _inspect,
    _root,
    _run,
)

SECTOR_BYTES = 512
ALIGN_SECTORS = 2048
ESP_SECTORS = 300 * 1024 * 1024 // SECTOR_BYTES
BOOT_SECTORS = 2 * 1024**3 // SECTOR_BYTES
LAB_MIN_ROOT_SECTORS = 20 * 1024**3 // SECTOR_BYTES
DISK_GUID_PATTERN = re.compile(r"^Disk identifier \(GUID\): ([a-fA-F0-9-]{36})$", re.M)
SECTOR_PATTERN = re.compile(r"^Sector size \(logical\): (\d+) bytes$", re.M)
PARTITION_ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+\d", re.M)


def _guid(value: object) -> str:
    if not isinstance(value, str):
        raise Refusal("Missing GPT UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise Refusal("Invalid GPT UUID") from exc
    if parsed.int == 0 or str(parsed) != value.lower():
        raise Refusal("Noncanonical or null GPT UUID")
    return str(parsed)


def _integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise Refusal(f"Invalid {label}")
    return value


def _align_up(sector: int) -> int:
    return (sector + ALIGN_SECTORS - 1) // ALIGN_SECTORS * ALIGN_SECTORS


def _align_end(sector: int) -> int:
    return (sector + 1) // ALIGN_SECTORS * ALIGN_SECTORS - 1


def read_synthetic_gpt(image: Path) -> dict:
    """Use sgdisk read-only operations on the already validated fixture base."""
    printed = _run("sgdisk", "--print", str(image))
    disk_match = DISK_GUID_PATTERN.search(printed)
    sector_match = SECTOR_PATTERN.search(printed)
    rows = [(int(n), int(first), int(last)) for n, first, last in PARTITION_ROW.findall(printed)]
    if disk_match is None or sector_match is None or int(sector_match.group(1)) != SECTOR_BYTES:
        raise Refusal("GPT disk GUID or logical sector size cannot be authenticated")
    if rows != [(n, first, last) for n, _, _, first, last in PARTITIONS]:
        raise Refusal("Unexpected GPT partitions, missing entry or foreign partition")
    partitions = []
    for number, type_guid, label, first, last in PARTITIONS:
        detail = _run("sgdisk", f"--info={number}", str(image))
        unique_match = re.search(r"^Partition unique GUID: ([A-Fa-f0-9-]{36})$", detail, re.M)
        if unique_match is None:
            raise Refusal("Missing partition UUID from GPT")
        if type_guid not in detail.upper() or label.upper() not in detail.upper():
            raise Refusal("GPT partition identity differs from fixture")
        partitions.append(
            {
                "number": number,
                "typeGuid": type_guid,
                "partuuid": _guid(unique_match.group(1)),
                "name": label,
                "firstSector": first,
                "lastSector": last,
            }
        )
    first_free = int(_run("sgdisk", "-F", str(image)).strip())
    last_free = int(_run("sgdisk", "-E", str(image)).strip())
    return {
        "diskGuid": _guid(disk_match.group(1)),
        "sectorBytes": SECTOR_BYTES,
        "partitions": partitions,
        "largestFreeFirstSector": first_free,
        "largestFreeLastSector": last_free,
    }


def propose(manifest: dict, snapshot: dict) -> dict:
    """Reject ambiguity, then describe only *candidate* future operations."""
    if not isinstance(manifest, dict) or not isinstance(snapshot, dict):
        raise Refusal("Expected GPT fixture and read-only GPT evidence")
    expected = {
        "labOnly": True,
        "firmware": "uefi",
        "partitionTable": "gpt",
        "fixtureOnly": True,
        "containsWindowsInstallation": False,
        "containsFilesystems": False,
        "storageInspectionOnly": True,
        "installationAuthorized": False,
    }
    if any(
        manifest.get(key) is not value if isinstance(value, bool) else manifest.get(key) != value
        for key, value in expected.items()
    ):
        raise Refusal("Not an isolated synthetic UEFI/GPT read-only fixture")
    total = _integer(manifest.get("virtualSizeBytes"), "disk size")
    if total == 0 or total % SECTOR_BYTES:
        raise Refusal("Invalid GPT byte geometry")
    if snapshot.get("sectorBytes") != SECTOR_BYTES:
        raise Refusal("Unsupported logical sector geometry")
    disk_guid = _guid(snapshot.get("diskGuid"))
    partitions = snapshot.get("partitions")
    if not isinstance(partitions, list) or len(partitions) != len(PARTITIONS):
        raise Refusal("Unexpected existing partition count")
    seen = {disk_guid}
    for index, (n, typ, label, first, last) in enumerate(PARTITIONS):
        part = partitions[index]
        manifest_parts = manifest.get("partitions")
        if not isinstance(part, dict) or not isinstance(manifest_parts, list):
            raise Refusal("Missing partition evidence")
        if len(manifest_parts) != len(PARTITIONS):
            raise Refusal("Incorrect fixture partition count")
        if not isinstance(manifest_parts[index], dict):
            raise Refusal("Invalid protected partition identity")
        exact = {
            "number": n,
            "typeGuid": typ,
            "name": label,
            "firstSector": first,
            "lastSector": last,
        }
        if any(part.get(k) != v or manifest_parts[index].get(k) != v for k, v in exact.items()):
            raise Refusal("Protected GPT identity or geometry mismatch")
        unique = _guid(part.get("partuuid"))
        if unique in seen:
            raise Refusal("Duplicate GPT partition or disk GUID")
        seen.add(unique)
    free_first = _integer(snapshot.get("largestFreeFirstSector"), "free-space start")
    free_last = _integer(snapshot.get("largestFreeLastSector"), "free-space end")
    if free_first <= PARTITIONS[-1][4] or free_last >= total // SECTOR_BYTES - 33:
        raise Refusal("Largest free extent is not the expected trailing GPT region")
    if free_last <= free_first or free_last - free_first < LAB_MIN_ROOT_SECTORS:
        raise Refusal("Insufficient isolated free space")
    esp_start = _align_up(free_first)
    esp_end = esp_start + ESP_SECTORS - 1
    boot_start = _align_up(esp_end + 1)
    boot_end = boot_start + BOOT_SECTORS - 1
    root_start = _align_up(boot_end + 1)
    root_end = _align_end(free_last)
    if root_end - root_start + 1 < LAB_MIN_ROOT_SECTORS:
        raise Refusal("Insufficient free Btrfs root region")
    candidate = [
        {
            "number": 4,
            "firstSector": esp_start,
            "lastSector": esp_end,
            "filesystem": "vfat",
            "mountPoint": "/boot/efi",
            "role": "new-linux-esp",
        },
        {
            "number": 5,
            "firstSector": boot_start,
            "lastSector": boot_end,
            "filesystem": "ext4",
            "mountPoint": "/boot",
            "role": "linux-boot",
        },
        {
            "number": 6,
            "firstSector": root_start,
            "lastSector": root_end,
            "filesystem": "btrfs",
            "mountPoint": "/",
            "role": "atomic-root",
        },
    ]
    previous_end = PARTITIONS[-1][4]
    for entry in candidate:
        start, end = entry["firstSector"], entry["lastSector"]
        if start <= previous_end or start < free_first or end > free_last or start > end:
            raise Refusal("Candidate overlaps protected geometry or GPT metadata")
        previous_end = end
    return {
        "distributionId": "bazzite",
        "phase": "synthetic-native-atomic-target-proposal",
        "diskGuid": disk_guid,
        "logicalSectorBytes": SECTOR_BYTES,
        "protectedExistingPartitions": partitions,
        "candidateNewPartitions": candidate,
        "btrfsSubvolumesProposed": ["/", "/var", "/var/home"],
        "windowsEspReuseProposed": False,
        "windowsEspFormatProposed": False,
        "gptHeadersAndPartitionTablesWouldChange": True,
        "protectiveMbrWouldRequirePrePostEvidence": True,
        "requiresAnacondaBlivetExactActionDiff": True,
        "requiresIndependentIsoAndPayloadAttestation": True,
        "requiresRecoverySnapshotAndWindowsBootProof": True,
        "requiresGptMetadataBackupAndPostwriteVerification": True,
        "legacyIso42IndependentSignatureVerified": False,
        "nativeInstallerWriteSetObserved": False,
        "atomicDeploymentVerified": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "gptMetadataWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "nvramWriteAuthorized": False,
        "secureBootEnrollmentAuthorized": False,
        "stableCatalogAuthorized": False,
    }


def inspect(root: Path, runner_temp: Path) -> dict:
    """Bind the proposal to a checked, immutable synthetic GPT base and QCOW2."""
    root = _root(root, runner_temp, exists=True)
    manifest_file = root / "manifest.json"
    if manifest_file.is_symlink():
        raise Refusal("Symlink manifest refused")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    _inspect(root, manifest)
    return propose(manifest, read_synthetic_gpt(root / IMAGE_NAME))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--runner-temp", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = inspect(args.root, args.runner_temp)
    except (Refusal, OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
