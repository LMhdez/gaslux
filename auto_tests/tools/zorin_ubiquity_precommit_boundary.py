#!/usr/bin/env python3
"""Classify Zorin 18.1/Ubiquity pre-commit evidence without enabling a writer.

Reuses the #333 handoff and canonical Safety #307 GPT/FD check. The #264
source map establishes file provenance and static token references, NOT an
authenticated graph, mutation ordering, or a non-mutating dry-run interface.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from zorin_native_ubiquity_map import validate_consistency
from zorin_ubiquity_handoff_readonly import (
    PINNED_CODE_MAP_SHA,
    UBIQUITY_EXEC_SHA,
    UbiquityHandoffDenied,
    canonical_sha,
    validate_ubiquity_handoff,
)

ROOT = Path(__file__).resolve().parents[2]
MAP_SCHEMA = ROOT / "schemas/zorin-native-ubiquity-capabilities.schema.json"
MAP_MAX_BYTES = 2 * 1024 * 1024
CODE_MAP_SOURCE = "STATIC_CODE_REFERENCE_ONLY"
PRECOMMIT_UNAVAILABLE = "UBIQUITY_PRECOMMIT_PLAN_UNAVAILABLE"
ROUTE = "ROUTE_B"
OBSERVATION_FIELDS = frozenset(
    (
        "planId",
        "transactionId",
        "installerExecutableSha256",
        "codeMapSha256",
        "selectedDiskUniqueId",
        "commitDiskUniqueId",
        "gptSnapshotSha256",
        "partmanActions",
        "bootloaderActions",
        "dryRunClaimed",
        "firstWriteBeforeValidation",
        "completePrecommitPlanClaimed",
        "actionGraphAuthenticated",
    )
)


@dataclass(frozen=True)
class PrecommitDecision:
    route: str
    status: str
    authorization: str
    staticMapValidated: bool
    earliestPossibleMutationLocated: bool
    mutationOrderingAuthenticated: bool
    precommitActionGraphAuthenticated: bool
    firstWriteFenced: bool
    nativeInstallerInvoked: bool
    productionStorageWritesAuthorized: bool
    windowsEspWriteAuthorized: bool
    sameDiskDualBootVerified: bool
    windowsInPlaceRollbackProven: bool
    stable: bool
    denialReasons: tuple[str, ...]


def _deny(reason: str) -> None:
    raise UbiquityHandoffDenied(reason)


def validate_static_code_map(code_map_bytes: bytes | None) -> bool:
    """Optional fresh verification of #264 artifact; no source execution.

    Even the authentic map cannot establish an effect-free pre-commit phase:
    it is composed of static token matches, not a call graph or I/O trace.
    """
    if code_map_bytes is None:
        return False
    if (
        type(code_map_bytes) is not bytes
        or not 0 < len(code_map_bytes) <= MAP_MAX_BYTES
        or hashlib.sha256(code_map_bytes).hexdigest() != PINNED_CODE_MAP_SHA
    ):
        _deny("E_INSTALLER_SOURCE_PROVENANCE")
    try:
        report = json.loads(code_map_bytes)
        schema = json.loads(MAP_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(report)
        validate_consistency(report)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise UbiquityHandoffDenied("E_INSTALLER_SOURCE_PROVENANCE") from exc
    except Exception as exc:
        raise UbiquityHandoffDenied("E_INSTALLER_SOURCE_PROVENANCE") from exc

    # The file's hash proves that this is the selected #264 report. These
    # checks enforce its explicitly *negative* runtime claims.
    if not (
        report["installer"]["sha256"] == UBIQUITY_EXEC_SHA
        and report["nativeInstallerExecuted"] is False
        and report["automationSafeForUnattendedInstall"] is False
        and report["partitionLockdownVerified"] is False
        and report["outsideLinuxTargetWriteSetAuthenticated"] is False
        and report["efiAndNvramPreservationVerified"] is False
        and all(
            item["runtimeBehaviorVerified"] is False
            for item in report["capabilities"].values()
        )
        and all(
            item["observedWrites"] is False
            for item in report["potentialWriteSurfaces"].values()
        )
        and "lib/partman/lib/commit.sh" in report["unreadablePaths"]
        and "lib/partman/lib/resize.sh" in report["unreadablePaths"]
    ):
        _deny("E_INSTALLER_SOURCE_PROVENANCE")
    return True


def validate_untrusted_candidate(
    candidate: dict[str, Any] | None, proposal: dict, shared_plan: dict
) -> None:
    """Refuse every candidate that pretends an Ubiquity trace is authority.

    This is *not* an interface to Ubiquity. The typed candidate is an
    adversarial input format for testing absent evidence boundaries only.
    """
    if candidate is None:
        return
    if type(candidate) is not dict or set(candidate) != OBSERVATION_FIELDS:
        _deny("E_PARTIAL_PRECOMMIT_OBSERVATION")
    if not (
        type(candidate["planId"]) is str
        and type(candidate["transactionId"]) is str
        and type(candidate["selectedDiskUniqueId"]) is str
        and type(candidate["commitDiskUniqueId"]) is str
        and type(candidate["gptSnapshotSha256"]) is str
        and type(candidate["codeMapSha256"]) is str
        and type(candidate["installerExecutableSha256"]) is str
        and type(candidate["partmanActions"]) is list
        and type(candidate["bootloaderActions"]) is list
        and all(
            type(candidate[field]) is bool
            for field in (
                "dryRunClaimed",
                "firstWriteBeforeValidation",
                "completePrecommitPlanClaimed",
                "actionGraphAuthenticated",
            )
        )
    ):
        _deny("E_PARTIAL_PRECOMMIT_OBSERVATION")
    if not (
        candidate["planId"] == shared_plan["planId"] == proposal["planId"]
        and candidate["transactionId"]
        == shared_plan["runtime"]["recoveryRunId"]
        == proposal["transactionId"]
    ):
        _deny("E_FOREIGN_TRANSACTION")
    if (
        candidate["installerExecutableSha256"] != UBIQUITY_EXEC_SHA
        or candidate["codeMapSha256"] != PINNED_CODE_MAP_SHA
    ):
        _deny("E_INSTALLER_SOURCE_PROVENANCE")
    if candidate["selectedDiskUniqueId"] != proposal["destination"]["diskUniqueId"]:
        _deny("E_WRONG_DISK")
    if candidate["commitDiskUniqueId"] != candidate["selectedDiskUniqueId"]:
        _deny("E_DISK_CHANGED_BEFORE_COMMIT")
    if candidate["gptSnapshotSha256"] != proposal["expectedGptSnapshotSha256"]:
        _deny("E_DESTINATION_CHANGED")
    if candidate["firstWriteBeforeValidation"]:
        _deny("E_FIRST_WRITE_PRECEDES_VALIDATION")
    if candidate["partmanActions"]:
        _deny("E_UNOBSERVED_PARTMAN_ACTION")
    if candidate["bootloaderActions"]:
        _deny("E_UNAUTHORIZED_BOOTLOADER_ACTION")
    if any(
        candidate[field]
        for field in (
            "dryRunClaimed",
            "completePrecommitPlanClaimed",
            "actionGraphAuthenticated",
        )
    ):
        _deny("E_FALSE_DRY_RUN")


def classify_zorin_precommit(
    proposal: dict,
    shared_plan: dict,
    expected_gpt: dict,
    readonly_disk_fd: int,
    *,
    code_map_bytes: bytes | None = None,
    candidate: dict | None = None,
) -> PrecommitDecision:
    """A valid #333 proposal always classifies ROUTE_B/deny, never install."""
    handoff = validate_ubiquity_handoff(
        proposal, shared_plan, expected_gpt, readonly_disk_fd
    )
    if not handoff["structurallyValidReadOnlyProposal"]:
        _deny("E_PARTIAL_PRECOMMIT_OBSERVATION")
    map_validated = validate_static_code_map(code_map_bytes)
    validate_untrusted_candidate(candidate, proposal, shared_plan)
    # A pinned JSON snapshot of GPT is not a trusted live/physical writer
    # fence. Revalidate its self-consistency without upgrading provenance.
    if canonical_sha(expected_gpt) != proposal["expectedGptSnapshotSha256"]:
        _deny("E_DESTINATION_CHANGED")
    return PrecommitDecision(
        route=ROUTE,
        status=PRECOMMIT_UNAVAILABLE,
        authorization="DENY_NO_WRITER",
        staticMapValidated=map_validated,
        earliestPossibleMutationLocated=False,
        mutationOrderingAuthenticated=False,
        precommitActionGraphAuthenticated=False,
        firstWriteFenced=False,
        nativeInstallerInvoked=False,
        productionStorageWritesAuthorized=False,
        windowsEspWriteAuthorized=False,
        sameDiskDualBootVerified=False,
        windowsInPlaceRollbackProven=False,
        stable=False,
        denialReasons=(
            "PARTMAN_WRITE_CAN_PRECEDE_UNOBSERVED_COMMIT",
            "FIRST_PERSISTENT_WRITE_NOT_AUTHENTICATED",
            "NO_VERIFIED_NON_MUTATING_UBIQUITY_DRY_RUN",
            "NO_AUTHENTICATED_PRECOMMIT_ACTION_GRAPH",
            "TEN_PARTMAN_LIBRARIES_NOT_SOURCE_AUTHENTICATED",
            "NO_TRUSTED_TARGET_TRANSACTION_AND_RECOVERY_FENCE",
        ),
    )
