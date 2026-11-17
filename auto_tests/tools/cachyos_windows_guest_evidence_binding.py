#!/usr/bin/env python3
"""Cross-check real *candidate* Windows guest observations against a signed CachyOS plan.

Both Windows records may originate in a disposable guest's read-only PowerShell
collector, but their provenance is NOT cryptographically authenticated here.
Successful checks indicate data consistency, NOT actual Windows boot, rollback,
Linux boot or permission to modify a physical disk. No writer is invoked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from cachyos_windows_transaction_bridge import (
    AUTH,
    BridgeError,
    evaluate as verify_signed_bridge,
    read_regular_json,
    require,
    ROOT,
)

import importlib.util

SPEC = importlib.util.spec_from_file_location(
    "gaslux_guest_recovery_validator",
    ROOT / "auto_tests/tools/verify_windows_guest_recovery.py",
)
assert SPEC and SPEC.loader
GUEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUEST)

ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
WINRE_TYPE = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
WINDOWS_DATA_TYPE = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
LINUX_DATA_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"


def must_match_partition(disk: dict[str, Any], expected: dict[str, int],
                         required_type: str, name: str) -> dict[str, Any]:
    matches = [
        row for row in disk["partitions"]
        if all(row[prop] == expected[prop_name] for prop, prop_name in (
            ("number", "number"), ("offset", "offsetBytes"),
            ("size", "sizeBytes")))
    ]
    require(len(matches) == 1 and matches[0]["gptType"] == required_type,
            "Windows evidence has ambiguous/wrong " + name + " GPT geometry or type")
    return matches[0]


def check_before_against_plan(
    plan: dict[str, Any], candidate: dict[str, Any], before: dict[str, Any],
) -> dict[str, Any]:
    """Reject a Windows report for the wrong disk, geometry, boot or recovery."""
    GUEST.validate(before, "baseline")
    disk = plan["disk"]
    require(before["runId"] == plan["planId"],
            "Windows collector transaction differs from plan")
    require(before["windowsDiskId"] == disk["uniqueId"],
            "Windows collector has the wrong physical disk")
    guest_disk = GUEST.disk_map(before)[before["windowsDiskId"]]
    require(guest_disk["size"] == disk["sizeBytes"] and
            guest_disk["logicalSectorSize"] == disk["logicalSectorSizeBytes"] and
            guest_disk["partitionStyle"] == disk["partitionStyle"],
            "Windows collector has different disk geometry")
    require(before["secureBootEnabled"] is False and
            before["bitlocker"] == {
                "protectionStatus": "Off",
                "volumeStatus": "FullyDecrypted",
                "encryptionPercentage": 0,
            }, "Windows collector has incompatible Secure Boot or encryption state")
    require(before["espFilesystemUuid"] == candidate["espUuid"],
            "recorded Windows ESP FAT32 UUID is not the collector's measured UUID")
    require(before["windowsEfiSha256"] == candidate["windowsLoaderSha256"],
            "actual Windows EFI loader digest does not match the handoff baseline")
    require(hashlib.sha256(before["bcdAllRaw"].encode("utf-8")).hexdigest() ==
            candidate["bcdSha256"], "Windows BCD text does not match baseline hash")
    require(before["winreEnabled"] is True and before["winreWimSha256"] != "0" * 64,
            "Windows Recovery environment/image is not observed")
    w = must_match_partition(guest_disk, disk["windows"], WINDOWS_DATA_TYPE, "Windows")
    e = must_match_partition(guest_disk, disk["boot"], ESP_TYPE, "ESP")
    recovery = must_match_partition(guest_disk, disk["recovery"], WINRE_TYPE, "WinRE")
    require(w["guid"] == before["windowsPartitionGuid"] and w["isBoot"] is True,
            "Windows system partition identity does not match collector")
    require(e["guid"] == before["espPartitionGuid"] and e["isSystem"] is True,
            "Windows ESP identity does not match collector")
    require(len({w["guid"], e["guid"], recovery["guid"]}) == 3,
            "Windows boot, recovery and system partitions must be independent")
    return guest_disk


def check_target_geometry(
    plan: dict[str, Any],
    before_disk: dict[str, Any],
    after_disk: dict[str, Any],
    mode: str,
) -> None:
    old = GUEST.partition_map(before_disk)
    new = GUEST.partition_map(after_disk)
    if mode == "rollback":
        require(old == new, "rollback did not restore the exact GPT partition map")
        return
    require(mode == "postinstall", "unexpected Windows evidence phase")
    additions = set(new) - set(old)
    require(len(additions) == 1, "postinstall requires exactly one owned Linux partition")
    installed = new[next(iter(additions))]
    expected = plan["disk"]["installer"]
    require(all(installed[key] == expected[field] for key, field in (
        ("number", "number"), ("offset", "finalOffsetBytes"),
        ("size", "finalSizeBytes"))) and installed["gptType"] == LINUX_DATA_TYPE,
        "Linux partition does not match the Windows transaction-owned extent")
    require(installed["guid"] not in old, "Linux partition reused foreign GPT identity")


def evaluate_guest_binding(
    plan: dict[str, Any], state: dict[str, Any], baseline: dict[str, Any],
    before: dict[str, Any], after: dict[str, Any], mode: str,
    envelope: Path, signature: Path, public_key: Path,
    cmdline: str, observed_root_uuid: str,
) -> dict[str, Any]:
    # The pre-live state MUST be preserved as a historical snapshot. It cannot
    # be fabricated from a later success/rollback marker; neither attestation
    # nor a stable transaction state is inferred from these JSON records.
    bridge_result = verify_signed_bridge(
        plan, state, baseline, envelope, signature, public_key,
        cmdline, observed_root_uuid,
    )
    prior = check_before_against_plan(plan, baseline, before)
    comparison = GUEST.compare(before, after, mode)
    latest = GUEST.disk_map(after)[before["windowsDiskId"]]
    check_target_geometry(plan, prior, latest, mode)
    require(comparison["checked"] is True and
            comparison["windowsRebootObserved"] is True and
            comparison["windowsBootManagerHashPreserved"] is True,
            "Windows recovery comparator did not pass all required checks")
    return {
        **bridge_result,
        "comparisonMode": mode,
        "guestRecoveryDocumentsConsistent": True,
        "windowsGptExtentsCrossChecked": True,
        "windowsEspFatSerialCrossChecked": True,
        "windowsEfiLoaderHashCrossChecked": True,
        "windowsBcdRawDigestCrossChecked": True,
        "winreImageHashCompared": True,
        "windowsGuestObservationsSelfReported": True,
        "windowsBootVerified": False,
        "windowsBcdAndWinreRestorationVerified": False,
        "firmwareBootOrderRestorationVerified": False,
        "linuxKernelUpdateCrossbootVerified": False,
        "transactionIntegratedIntoProductionInstaller": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-plan", required=True, type=Path)
    parser.add_argument("--execution-state", required=True, type=Path)
    parser.add_argument("--windows-baseline", required=True, type=Path)
    parser.add_argument("--guest-before", required=True, type=Path)
    parser.add_argument("--guest-after", required=True, type=Path)
    parser.add_argument("--mode", choices=("postinstall", "rollback"), required=True)
    parser.add_argument("--signed-handoff", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--observed-root-uuid", required=True)
    args = parser.parse_args(argv)
    try:
        result = evaluate_guest_binding(
            read_regular_json(args.windows_plan),
            read_regular_json(args.execution_state),
            read_regular_json(args.windows_baseline),
            GUEST.read(args.guest_before),
            GUEST.read(args.guest_after),
            args.mode, args.signed_handoff, args.signature, args.public_key,
            Path("/proc/cmdline").read_text(encoding="ascii"),
            args.observed_root_uuid,
        )
    except (BridgeError, GUEST.EvidenceError, AUTH.AuthError, OSError,
            ValueError, TypeError, KeyError) as error:
        print(json.dumps({"guestRecoveryDocumentsConsistent": False,
                          "storageWritesAuthorized": False, "releaseEligible": False,
                          "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
