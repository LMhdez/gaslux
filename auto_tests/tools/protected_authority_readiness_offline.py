"""Protected-authority readiness: offline diagnostic only, fail-closed by design.

No network, GitHub token, workflow dispatch, ledger, cryptography, QEMU or writer.
Only a future separately reviewed administrative adapter could establish provenance.
Runner-controlled responses and successful CI MUST NOT become authority.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas/protected-authority-readiness-v1.schema.json"
VALIDATOR = Draft202012Validator(
    json.loads(SCHEMA.read_text(encoding="utf-8")),
    format_checker=FormatChecker(),
)

VERIFIED = "VERIFIED"
MISSING = "MISSING"
NOT_VERIFIABLE = "NOT_VERIFIABLE"
BLOCKED_TRUST_ROOT = "BLOCKED_TRUST_ROOT"

# These are independent obligations, not claims from a request branch.
CONTROLS = (
    "main.protection",
    "dev.protection",
    "main.rulesets",
    "dev.rulesets",
    "reviews.required",
    "reviews.selfApprovalExcluded",
    "requester.branchIsolation",
    "environment.requiredReviewers",
    "environment.branchRestriction",
    "controller.protectedLocation",
    "controller.immutableWorkflow",
    "controller.tokenPermissions",
    "commit.preparationExact",
    "commit.authorizationExact",
    "ledger.externalService",
    "ledger.globalUniqueness",
    "ledger.consumeAtomic",
    "ledger.rollbackResistant",
    "ledger.independentRevocation",
    "coordinator.freshChallenge",
    "observer.independentAttestation",
    "safety.noWriter",
    "observer.readOnlyProducer",
)
CAPABILITY_NAMES = (
    "protectedControllerOperational",
    "externalLedgerOperational",
    "guestAttestationVerified",
    "qemuExecutionAuthorized",
    "guestCommandChannelAuthorized",
    "diskWritesAuthorized",
    "productionInstallationAuthorized",
)

# GitHub API response shape alone cannot attest the administrative source.
# These values are reference metadata, NOT verified execution grants.
PINNED_CONTRACTS = {
    "trigger275": "1a6446b408c78386e720f8d2b1f2063c1d3f7db1",
    "ledger285": "fda13b8a2a48d8e5f00c3f9be306499d85e0d336",
    "noWriter267": "0be04192acd542646a5b6cd952e01620379edf5d",
    "observer294": "e7941ef3eb26c0cae1a2d7fbe1b3009eb050c5c9",
}


def _reason(control: str, entry: dict[str, Any] | None) -> str:
    if entry is None:
        return "EVIDENCE_ABSENT"
    status = entry["httpStatus"]
    origin = entry["source"]
    payload = entry["payload"]
    if status == 403:
        return "API_FORBIDDEN_NOT_VERIFIABLE"
    if status != 200 and status is not None:
        return "API_UNAVAILABLE_OR_UNSUPPORTED"
    if origin == "PR_COMMENT":
        return "PR_COMMENT_NOT_AN_ADMINISTRATIVE_APPROVAL"
    if origin == "CI_STATUS":
        return "GREEN_CI_NOT_AN_ADMINISTRATIVE_AUTHORITY"
    if origin in {"RUNNER_LOCAL", "SQLITE_LOCAL", "EXTERNAL_UNVERIFIED"}:
        return "SELF_ASSERTED_OR_LOCAL_SOURCE"
    # Even 'GITHUB_READ_ONLY' is merely an untrusted label in this JSON.
    if status != 200 or not isinstance(payload, dict):
        return "INCOMPLETE_API_EVIDENCE"
    if control in {"main.protection", "dev.protection"}:
        if payload.get("protected") is False:
            return "DIRECT_BRANCH_PROTECTION_FLAG_FALSE_RULESETS_UNPROVEN"
        return "BRANCH_API_200_DOES_NOT_PROVE_ALL_APPLICABLE_RULES"
    if control in {"main.rulesets", "dev.rulesets"}:
        if payload.get("rulesets") == []:
            return "EMPTY_RULESET_LIST_NOT_AN_INDEPENDENT_ADMIN_PROOF"
        return "RULESET_ENUMERATION_NOT_INDEPENDENTLY_AUTHENTICATED"
    if control == "reviews.selfApprovalExcluded":
        if payload.get("requester") == payload.get("approver"):
            return "SELF_APPROVAL_NOT_EXCLUDED"
        return "REVIEWER_IDENTITY_NOT_INDEPENDENTLY_VERIFIED"
    if control == "controller.protectedLocation":
        if payload.get("controllerRef") != "refs/heads/main":
            return "WORKFLOW_REQUESTER_CONTROLLED_OR_WRONG_REF"
        return "CONTROLLER_REF_NOT_AN_AUTHENTICATED_PROTECTED_CHECKOUT"
    if control in {"commit.preparationExact", "commit.authorizationExact"}:
        expected, actual = payload.get("expectedSha"), payload.get("actualSha")
        if expected != actual or not _full_sha(expected):
            return "EXACT_COMMIT_IDENTITY_MISMATCH"
        return "SHA_EQUALITY_WITHOUT_PROTECTED_PIN_ORIGIN"
    if control == "controller.tokenPermissions":
        return "RUNNER_TOKEN_CANNOT_ATTEST_ADMINISTRATIVE_PROTECTION"
    if control.startswith("ledger."):
        if payload.get("backend") in {"sqlite", "local-file", "runner-memory"}:
            return "LOCAL_LEDGER_NOT_EXTERNALLY_ROLLBACK_RESISTANT"
        if payload.get("snapshotRestored") is True:
            return "LEDGER_SNAPSHOT_ROLLBACK_UNFENCED"
        return "EXTERNAL_LEDGER_AUTHORITY_UNVERIFIED"
    if control == "coordinator.freshChallenge":
        if payload.get("reused") is True or payload.get("expired") is True:
            return "REPLAYED_OR_EXPIRED_CHALLENGE"
        return "CHALLENGE_NOT_EXTERNALLY_CONSUMED_OR_TIME_ATTESTED"
    if control in {"safety.noWriter", "observer.readOnlyProducer"}:
        return "READ_ONLY_OR_NO_WRITER_NOT_EXECUTION_AUTHORITY"
    if control == "observer.independentAttestation":
        return "GUEST_ATTESTATION_NOT_INDEPENDENTLY_VERIFIED"
    return "REQUIRES_INDEPENDENT_ADMINISTRATIVE_PROVENANCE"


def _full_sha(value: object) -> bool:
    return type(value) is str and len(value) == 40 and all(
        c in "0123456789abcdef" for c in value
    )


def assess_readiness(untrusted_report: object) -> dict[str, Any]:
    """Never authorize: caller-provided observations cannot authenticate themselves.

    VERIFIED/MISSING are reserved for a future separately reviewed trusted
    administrative collector. This offline component cannot mint either state.
    """
    errors = list(VALIDATOR.iter_errors(untrusted_report))
    if errors:
        reasons = {
            key: {"status": NOT_VERIFIABLE, "reason": "INPUT_SCHEMA_INVALID"}
            for key in CONTROLS
        }
    else:
        observations = untrusted_report["observations"]
        reasons = {
            key: {"status": NOT_VERIFIABLE, "reason": _reason(key, observations.get(key))}
            for key in CONTROLS
        }
    return {
        "contractVersion": 1,
        "repository": "LMhdez/gaslux",
        "decision": BLOCKED_TRUST_ROOT,
        "readOnlyDiagnostic": True,
        "individualStatusesDefined": [VERIFIED, MISSING, NOT_VERIFIABLE],
        "controls": reasons,
        "capabilities": {key: False for key in CAPABILITY_NAMES},
    }


def probe_existing_denial_contracts(
    *, trigger_module: Any, ledger_module: Any, safety_module: Any, grant: dict
) -> dict[str, Any]:
    """Call genuine pinned #275/#285/#267 interfaces only in refusal mode.

    These probes are not source authenticity, a ledger lease or writer approval.
    The #285 model is NOT instantiated as an external service.
    """
    observed = {}
    try:
        ledger_module._check_grant(grant)
        observed["ledgerSchema"] = "STRUCTURAL_ONLY"
    except (ValueError, TypeError, KeyError):
        observed["ledgerSchema"] = "INVALID"
    try:
        ledger_module._decision_reason(grant, None)
        observed["externalDecision"] = "NOT_PRESENT"
    except (ValueError, TypeError, KeyError):
        observed["externalDecision"] = "NOT_VERIFIABLE"
    try:
        trigger_module.validate_git(Path("."), {})
    except trigger_module.Refused:
        observed["exactGitTrigger"] = "REFUSED_MISSING_PROTECTED_PINS"
    else:
        observed["exactGitTrigger"] = "UNEXPECTED_ACCEPTANCE_STILL_BLOCKED"
    try:
        safety_module.decide_no_writer(
            plan={}, plan_bytes=b"", transaction_id="", vm_id="",
            host_evidence={}, guest_evidence={}, immediate_evidence={},
            host_key=b"", guest_key=b"", fresh_nonce="",
            owned_regions=[], write_set=[],
        )
    except safety_module.PrewriteDenied:
        observed["noWriter"] = "REFUSED_INVALID_LAB_INPUT"
    else:
        observed["noWriter"] = "UNEXPECTED_ACCEPTANCE_STILL_BLOCKED"
    return {
        "decision": BLOCKED_TRUST_ROOT,
        "upstreamContractObservations": observed,
        "capabilities": {key: False for key in CAPABILITY_NAMES},
    }
