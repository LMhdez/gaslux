#!/usr/bin/env python3
"""Fail-closed Zorin Ubiquity handoff *proposal*, never an installation writer.

The shared Gaslux plan schema, pinned Zorin catalog and canonical Safety #307
inspect_gpt_fd are authoritative for their respective shapes. This module
does not authenticate a plan signature, VM origin, Ubiquity action graph or
Windows recovery. No proposal can authorize any disk or firmware operation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from libertix_disk_identity_gate import (
    DiskIdentityError,
    assert_snapshot_matches,
    inspect_gpt_fd,
)
from zorin_native_ubiquity_map import (
    ISO_SHA,
    UBIQUITY_EXEC_SHA,
    UBIQUITY_VERSION,
)

ROOT = Path(__file__).resolve().parents[2]
HANDOFF_SCHEMA = ROOT / "schemas/zorin-ubiquity-handoff-readonly.schema.json"
SHARED_PLAN_SCHEMA = ROOT / "schemas/installation-plan.schema.json"
CATALOG = ROOT / "release-config.json"
# SHA-256 of the JSON map generated from authenticated Ubiquity code in #264,
# documented in docs/ZORIN_UBIQUITY_NATIVE_CODE_MAP.md. It is a reference,
# NOT a reauthentication of those bytes or an installer execution trace.
PINNED_CODE_MAP_SHA = (
    "47f42ce781af0eb39bc19f6c3bf4f2fb20569"
    "c5467a8f17d8e6d84b273a08f24"
)
BOOT_ACTIONS = frozenset(
    ("ESP_WRITE", "NVRAM_WRITE", "GRUB_INSTALL", "BIOS_BOOT_WRITE")
)
PARTMAN_ACTIONS = frozenset(("PARTMAN_COMMIT",))
ROOT_ACTIONS = frozenset(("ROOT_CONFIGURE", "ROOT_FORMAT"))
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
MSR_TYPE = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
WINRE_TYPE = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
LINUX_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"


class UbiquityHandoffDenied(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def demand(ok: bool, reason: str) -> None:
    if not ok:
        raise UbiquityHandoffDenied(reason)


def canonical_sha(obj: dict) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        .encode("ascii")
    ).hexdigest()


def _schema_validate(obj: dict, path: Path, reason: str) -> None:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(obj)
    except (OSError, ValueError, TypeError) as exc:
        raise UbiquityHandoffDenied(reason) from exc
    except Exception as exc:
        # Includes jsonschema.ValidationError and SchemaError. Never issue a
        # partial approval if the schema engine or document is unavailable.
        raise UbiquityHandoffDenied(reason) from exc


def _catalog_identity() -> dict:
    try:
        entries = json.loads(CATALOG.read_text(encoding="utf-8"))["distributions"]
        matches = [item for item in entries if item.get("id") == "zorin"]
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise UbiquityHandoffDenied("E_CATALOG_UNAVAILABLE") from exc
    demand(len(matches) == 1, "E_CATALOG_AMBIGUOUS")
    return matches[0]


def _expected_role(part: dict, plan: dict) -> str:
    num = part["number"]
    disk = plan["disk"]
    if num == disk["boot"]["number"]:
        return "ESP"
    if num == disk["windows"]["number"]:
        return "WINDOWS"
    if num == disk["recovery"]["number"]:
        return "RECOVERY"
    if part["typeGuid"] == MSR_TYPE:
        return "MSR"
    # Other partitions remain protected, even when their ownership is unknown.
    return "OTHER"


def validate_ubiquity_handoff(
    proposal: dict, shared_plan: dict, expected_gpt: dict, readonly_disk_fd: int
) -> dict:
    """Validate a synthetic, unsigned proposal against an FD-bound GPT image.

    The caller-supplied plan and expected_gpt do not have authenticated origin.
    This function never issues authority, and cannot make a real VM writable.
    """
    _schema_validate(proposal, HANDOFF_SCHEMA, "E_HANDOFF_SCHEMA")
    _schema_validate(shared_plan, SHARED_PLAN_SCHEMA, "E_SHARED_PLAN_SCHEMA")

    catalog = _catalog_identity()
    iso = proposal["iso"]
    installer = proposal["installer"]
    distro = shared_plan["distribution"]
    demand(
        iso["osReleaseId"] == "zorin"
        and iso["sha256"] == ISO_SHA == catalog["isoInstallerSha256"]
        and iso["sizeBytes"] == catalog["isoInstallerSizeBytes"]
        and distro["id"] == "zorin"
        and distro["osReleaseId"] == "zorin"
        and distro["installerIsoSha256"] == ISO_SHA
        and distro["installerIsoUrl"] == catalog["isoInstaller"],
        "E_ISO_IDENTITY_MISMATCH",
    )
    demand(
        installer["name"] == "ubiquity"
        and installer["version"] == UBIQUITY_VERSION
        and installer["executable"] == "usr/bin/ubiquity"
        and installer["executableSha256"] == UBIQUITY_EXEC_SHA
        and proposal["sourceEvidence"]["codeMapSha256"] == PINNED_CODE_MAP_SHA,
        "E_INSTALLER_IDENTITY_MISMATCH",
    )
    demand(
        shared_plan["firmware"] == "uefi"
        and shared_plan["disk"]["partitionStyle"] == "GPT"
        and proposal["firmware"] == "uefi"
        and proposal["partitionStyle"] == "GPT"
        and shared_plan["runtime"]["bootStrategy"]
        in ("uefi-boot-next", "uefi-firmware-boot-order"),
        "E_UNVERIFIED_FIRMWARE_TABLE",
    )
    demand(
        shared_plan["runtime"]["secureBootEnabled"] is False,
        "E_SECURE_BOOT_UNPROVEN",
    )
    demand(
        proposal["planId"] == shared_plan["planId"]
        and shared_plan["runtime"]["recoveryRunId"] is not None
        and proposal["transactionId"] == shared_plan["runtime"]["recoveryRunId"],
        "E_FOREIGN_TRANSACTION",
    )

    destination = proposal["destination"]
    plan_disk = shared_plan["disk"]
    demand(
        destination["diskUniqueId"] == plan_disk["uniqueId"],
        "E_WRONG_DISK",
    )
    demand(
        destination["partitionTableId"] == plan_disk["partitionTableId"]
        and destination["sizeBytes"] == plan_disk["sizeBytes"]
        and destination["logicalSectorSizeBytes"]
        == plan_disk["logicalSectorSizeBytes"],
        "E_GPT_GEOMETRY_MISMATCH",
    )
    try:
        observed = inspect_gpt_fd(
            readonly_disk_fd,
            logical_sector_size=destination["logicalSectorSizeBytes"],
        )
        assert_snapshot_matches(expected_gpt, observed)
    except (DiskIdentityError, OSError, TypeError, ValueError) as exc:
        raise UbiquityHandoffDenied("E_GPT_GEOMETRY_MISMATCH") from exc
    demand(
        canonical_sha(expected_gpt) == proposal["expectedGptSnapshotSha256"]
        and observed["partitionTableId"] == destination["partitionTableId"]
        and observed["sizeBytes"] == destination["sizeBytes"]
        and observed["logicalSectorSizeBytes"]
        == destination["logicalSectorSizeBytes"],
        "E_GPT_GEOMETRY_MISMATCH",
    )

    partitions = {part["number"]: part for part in observed["partitions"]}
    target_number = destination["partitionNumber"]
    target = partitions.get(target_number)
    demand(target is not None, "E_GPT_GEOMETRY_MISMATCH")
    installer_partition = plan_disk["installer"]
    demand(
        installer_partition["number"] == target_number
        and target_number
        not in {
            plan_disk["boot"]["number"],
            plan_disk["windows"]["number"],
            plan_disk["recovery"]["number"],
        }
        and target["typeGuid"] == LINUX_TYPE
        and target["partGuid"] == destination["partGuid"]
        and target["offsetBytes"] == destination["offsetBytes"]
        and target["sizeBytes"] == destination["partitionBytes"]
        and target["offsetBytes"] == installer_partition["finalOffsetBytes"]
        and target["offsetBytes"] == installer_partition["offsetBytes"]
        and target["sizeBytes"] == installer_partition["finalSizeBytes"]
        and target["sizeBytes"] == installer_partition["stagingSizeBytes"],
        "E_GPT_GEOMETRY_MISMATCH",
    )
    for role, key in (
        ("ESP", "boot"),
        ("WINDOWS", "windows"),
        ("RECOVERY", "recovery"),
    ):
        owned = plan_disk[key]
        part = partitions.get(owned["number"])
        demand(
            part is not None
            and part["offsetBytes"] == owned["offsetBytes"]
            and part["sizeBytes"] == owned["sizeBytes"],
            "E_GPT_GEOMETRY_MISMATCH",
        )
        if role == "ESP":
            demand(part["typeGuid"] == ESP_TYPE, "E_GPT_GEOMETRY_MISMATCH")
        if role == "RECOVERY":
            demand(part["typeGuid"] == WINRE_TYPE, "E_GPT_GEOMETRY_MISMATCH")

    protections = proposal["protectedPartitions"]
    protected_by_number = {p["number"]: p for p in protections}
    demand(
        len(protected_by_number) == len(protections)
        and set(protected_by_number) == set(partitions) - {target_number},
        "E_WINDOWS_PROTECTED_PARTITION",
    )
    for number, declared in protected_by_number.items():
        part = partitions[number]
        demand(
            declared["partGuid"] == part["partGuid"]
            and declared["role"] == _expected_role(part, shared_plan),
            "E_WINDOWS_PROTECTED_PARTITION",
        )

    for action in proposal["proposedOperations"]:
        kind = action["kind"]
        part = action["partitionNumber"]
        if kind in BOOT_ACTIONS:
            raise UbiquityHandoffDenied("E_UNAUTHORIZED_BOOTLOADER_ACTION")
        if part != target_number or part in protected_by_number:
            raise UbiquityHandoffDenied("E_WINDOWS_PROTECTED_PARTITION")
        if kind in PARTMAN_ACTIONS:
            raise UbiquityHandoffDenied("E_UNAUTHENTICATED_PARTMAN_ACTION")
        demand(kind in ROOT_ACTIONS, "E_UNAUTHENTICATED_PARTMAN_ACTION")
    # A structurally coherent proposal does NOT become a trusted action plan:
    # Ubiquity has no authenticated dry-run/action graph demonstrated here.
    return {
        "structurallyValidReadOnlyProposal": True,
        "authorization": "DENY_NO_WRITER",
        "writeOperationsAuthorized": [],
        "nativeInstallerInvoked": False,
        "productionStorageWritesAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "sameDiskDualBootVerified": False,
        "windowsInPlaceRollbackProven": False,
        "stable": False,
        "reasons": [
            "NO_AUTHENTICATED_UBIQUITY_ACTION_GRAPH",
            "NO_TRUSTED_PLAN_OR_GUEST_SOURCE",
            "NO_INDEPENDENT_WINDOWS_RECOVERY_PROOF",
        ],
    }
