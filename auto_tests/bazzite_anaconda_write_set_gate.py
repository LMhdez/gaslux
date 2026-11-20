#!/usr/bin/env python3
"""Deny-by-default comparison of an Anaconda action export with the Bazzite lab plan.

No disk parser or writer. Anaconda GetActions() is the intended read-only
upstream observation API, but no authenticated guest action export exists yet.
Synthetic replay can validate this contract; it never grants installation.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from bazzite_atomic_destination_plan import _guid
from bazzite_gpt_fixture import PARTITIONS, Refusal

LEGACY_URL = "https://download.bazzite.gg/bazzite-stable-amd64.iso"
LEGACY_LAB_SHA256 = "9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7"
LEGACY_LAB_BYTES = 7907770368
SERIAL = "GLXBAZRO001"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFI_GRUB_CANDIDATE = "/EFI/fedora/grubx64.efi"

OBSERVATION_KEYS = frozenset(
    {
        "schemaVersion",
        "origin",
        "firmware",
        "partitionTable",
        "secureBootEnabled",
        "diskGuid",
        "logicalSectorBytes",
        "diskSerial",
        "protectedExistingPartitions",
        "storageActions",
        "metadataWrites",
        "efiWrites",
        "nvramOperations",
        "installer",
        "atomicDeployment",
    }
)
INSTALLER_KEYS = frozenset(
    {
        "isoUrl",
        "isoSha256",
        "isoSizeBytes",
        "locallyCalculatedSha256",
        "independentIsoSignatureVerified",
        "payloadDigest",
        "payloadBoundToIso",
        "anacondaVersion",
        "blivetVersion",
    }
)


def _exact(value: object, keys: frozenset[str], title: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise Refusal(f"Missing, unknown or ambiguous {title} fields")
    return value


def assess_legacy_media(record: dict) -> dict:
    """A same-CDN checksum cannot establish independent source authenticity."""
    info = _exact(record, INSTALLER_KEYS, "legacy media")
    if (
        info["isoUrl"] != LEGACY_URL
        or type(info["isoSizeBytes"]) is not int
        or info["isoSizeBytes"] != LEGACY_LAB_BYTES
        or not isinstance(info["isoSha256"], str)
        or not SHA256.fullmatch(info["isoSha256"])
        or info["isoSha256"] != LEGACY_LAB_SHA256
    ):
        raise Refusal("Historical legacy ISO identity differs from laboratory pin")
    if (
        not isinstance(info["locallyCalculatedSha256"], str)
        or info["locallyCalculatedSha256"] != info["isoSha256"]
    ):
        raise Refusal("Legacy ISO byte hash not verified")
    if info["independentIsoSignatureVerified"] is not False:
        raise Refusal("Historical legacy ISO has no verified independent signature")
    if info["payloadDigest"] is not None or info["payloadBoundToIso"] is not False:
        raise Refusal("Atomic payload has no verified ISO-to-deployment binding")
    for name in ("anacondaVersion", "blivetVersion"):
        value = info[name]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise Refusal(f"Untrusted installer version field: {name}")
    return {
        "reportedLocalHashMatchesHistoricalPin": True,
        "historicalChecksumIndependentlyAuthenticated": False,
        "payloadBoundToIso": False,
        "installationAuthorized": False,
    }


def expected_actions(plan: dict) -> dict:
    if not isinstance(plan, dict) or plan.get("distributionId") != "bazzite":
        raise Refusal("Not a Bazzite proposal")
    if (
        plan.get("phase") != "synthetic-native-atomic-target-proposal"
        or plan.get("installationAuthorized") is not False
        or plan.get("partitionWriteAuthorized") is not False
        or plan.get("gptMetadataWriteAuthorized") is not False
        or plan.get("windowsEspWriteAuthorized") is not False
    ):
        raise Refusal("Proposal is missing explicit no-write authority")
    candidates = plan.get("candidateNewPartitions")
    protected = plan.get("protectedExistingPartitions")
    size = plan.get("virtualSizeBytes")
    if (
        not isinstance(candidates, list)
        or len(candidates) != 3
        or not isinstance(protected, list)
        or len(protected) != 3
        or type(size) is not int
        or size <= 0
        or size % 512
        or plan.get("logicalSectorBytes") != 512
        or not isinstance(plan.get("diskGuid"), str)
    ):
        raise Refusal("Incomplete candidate GPT geometry or identity")
    if [p.get("number") for p in candidates if isinstance(p, dict)] != [4, 5, 6]:
        raise Refusal("Expected only three newly owned partition slots")
    disk_guid = _guid(plan["diskGuid"])
    if disk_guid != plan["diskGuid"]:
        raise Refusal("Uncanonical disk GUID")
    if size != 70 * 1024**3:
        raise Refusal("Not the known 70 GiB laboratory GPT fixture")
    existing_ids = {disk_guid}
    for existing, (number, part_type, name, first, last) in zip(
        protected, PARTITIONS, strict=True
    ):
        if not isinstance(existing, dict) or set(existing) != {
            "number", "typeGuid", "partuuid", "name", "firstSector", "lastSector"
        }:
            raise Refusal("Invalid protected GPT partition identity")
        if any((
            existing["number"] != number,
            existing["typeGuid"] != part_type,
            existing["name"] != name,
            existing["firstSector"] != first,
            existing["lastSector"] != last,
        )):
            raise Refusal("Foreign or changed protected partition")
        part_id = _guid(existing["partuuid"])
        if part_id in existing_ids:
            raise Refusal("Duplicate protected partition GUID")
        existing_ids.add(part_id)
    if plan.get("btrfsSubvolumesProposed") != ["/", "/var", "/var/home"]:
        raise Refusal("Unrecognized Atomic Btrfs subvolume proposal")
    operations = []
    fixed_formats = [("vfat", "/boot/efi"), ("ext4", "/boot"), ("btrfs", "/")]
    previous_end = PARTITIONS[-1][4]
    for part, (fs, mount) in zip(candidates, fixed_formats, strict=True):
        if (
            not isinstance(part, dict)
            or set(part)
            != {"number", "firstSector", "lastSector", "filesystem", "mountPoint", "role"}
            or part["filesystem"] != fs
            or part["mountPoint"] != mount
            or type(part["firstSector"]) is not int
            or type(part["lastSector"]) is not int
            or part["firstSector"] >= part["lastSector"]
            or part["firstSector"] <= previous_end
            or part["lastSector"] >= size // 512 - 33
        ):
            raise Refusal("Invalid candidate partition operation")
        previous_end = part["lastSector"]
        operations.extend(
            [
                {
                    "kind": "create-partition",
                    "number": part["number"],
                    "firstSector": part["firstSector"],
                    "lastSector": part["lastSector"],
                },
                {
                    "kind": "format-partition",
                    "number": part["number"],
                    "filesystem": fs,
                    "mountPoint": mount,
                },
            ]
        )
    for subvol in plan["btrfsSubvolumesProposed"]:
        operations.append({"kind": "create-btrfs-subvolume", "partitionNumber": 6, "mountPoint": subvol})
    last = size // 512 - 1
    metadata = [
        {"kind": "protective-mbr", "firstSector": 0, "lastSector": 0},
        {"kind": "gpt-primary", "firstSector": 1, "lastSector": 33},
        {"kind": "gpt-backup", "firstSector": last - 32, "lastSector": last},
    ]
    return {
        "operations": operations,
        "metadataWrites": metadata,
        "efiWrites": [{"partitionNumber": 4, "path": EFI_GRUB_CANDIDATE}],
    }


def _compare_multiset(observed: object, expected: list, context: str) -> None:
    if not isinstance(observed, list) or any(not isinstance(x, dict) for x in observed):
        raise Refusal(f"Missing {context} actions")
    pack = lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if Counter(map(pack, observed)) != Counter(map(pack, expected)):
        raise Refusal(f"Unknown, missing or duplicated {context} action")


def compare(plan: dict, observation: dict) -> dict:
    """Structural comparison ONLY. Real installer provenance is NOT established."""
    expected = expected_actions(plan)
    record = _exact(observation, OBSERVATION_KEYS, "Anaconda observation")
    if record["schemaVersion"] != 1 or record["origin"] not in (
        "synthetic-contract-replay",
        "anaconda-dbus-readonly-untrusted",
    ):
        raise Refusal("Unknown action capture source; cannot prove native observation")
    if record["origin"] == "anaconda-dbus-readonly-untrusted":
        raise Refusal("Guest action export lacks independent run/ISO provenance authentication")
    if (
        record["firmware"] != "uefi"
        or record["partitionTable"] != "gpt"
        or record["secureBootEnabled"] is not False
        or record["diskGuid"] != plan["diskGuid"]
        or record["logicalSectorBytes"] != 512
        or record["diskSerial"] != SERIAL
        or record["protectedExistingPartitions"] != plan["protectedExistingPartitions"]
    ):
        raise Refusal("Guest disk, UEFI/GPT, Secure Boot or protected partition evidence mismatch")
    source = assess_legacy_media(record["installer"])
    if record["atomicDeployment"] != {
        "payloadInstallObserved": False,
        "deploymentUpdateVerified": False,
        "rollbackVerified": False,
    }:
        raise Refusal("Atomic deployment stage unknown or contradictory")
    _compare_multiset(record["storageActions"], expected["operations"], "storage")
    _compare_multiset(record["metadataWrites"], expected["metadataWrites"], "GPT/PMBR")
    _compare_multiset(record["efiWrites"], expected["efiWrites"], "EFI bootloader")
    if record["nvramOperations"] != []:
        raise Refusal("Unexpected NVRAM or BootOrder mutation")
    return {
        "distributionId": "bazzite",
        "comparisonSource": "synthetic-contract-replay",
        "syntheticActionGraphMatchesProposal": True,
        "gptMetadataWritesAreAnticipatedNotObserved": True,
        "isoIdentityDiagnostic": source,
        "realAnacondaActionGraphAuthenticated": False,
        "nativeInstallerWriteSetVerified": False,
        "windowsEspPreservedByRealInstaller": False,
        "atomicDeploymentVerified": False,
        "partitionWriteAuthorized": False,
        "gptMetadataWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "nvramWriteAuthorized": False,
        "installationAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.proposal.is_symlink() or args.observation.is_symlink():
            raise Refusal("Symlink action evidence refused")
        if any(not 0 < p.stat().st_size <= 1024 * 1024 for p in (args.proposal, args.observation)):
            raise Refusal("Missing or unbounded action evidence")
        plan = json.loads(args.proposal.read_text(encoding="utf-8"))
        observed = json.loads(args.observation.read_text(encoding="utf-8"))
        result = compare(plan, observed)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, Refusal) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
