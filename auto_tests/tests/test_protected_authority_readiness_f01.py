"""F-01 adversarial contract: imports the real #295 readiness module, no mocks."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "auto_tests/tools/protected_authority_readiness_offline.py"
SCHEMA = ROOT / "schemas/protected-authority-readiness-v1.schema.json"
SPEC = importlib.util.spec_from_file_location("protected_readiness_f01_real", MODULE)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

LEDGER_CONTROLS = (
    "ledger.externalService",
    "ledger.globalUniqueness",
    "ledger.consumeAtomic",
    "ledger.rollbackResistant",
    "ledger.independentRevocation",
)
INVALID_BACKENDS = (
    [],
    {},
    ["sqlite"],
    [{"nested": ["sqlite", {"backend": "local-file"}]}],
    {"backend": "sqlite"},
    {"nested": {"items": [1, {"source": "GITHUB_READ_ONLY"}]}},
    None,
    0,
    23,
    True,
    False,
)
TEXT_BACKENDS = (
    ("sqlite", "LOCAL_LEDGER_NOT_EXTERNALLY_ROLLBACK_RESISTANT"),
    ("local-file", "LOCAL_LEDGER_NOT_EXTERNALLY_ROLLBACK_RESISTANT"),
    ("runner-memory", "LOCAL_LEDGER_NOT_EXTERNALLY_ROLLBACK_RESISTANT"),
    ("external", "EXTERNAL_LEDGER_AUTHORITY_UNVERIFIED"),
    ("unfamiliar-service", "EXTERNAL_LEDGER_AUTHORITY_UNVERIFIED"),
    ("", "EXTERNAL_LEDGER_AUTHORITY_UNVERIFIED"),
)


def build(control: str, payload: dict) -> dict:
    return {
        "contractVersion": 1,
        "repository": "LMhdez/gaslux",
        "requestRef": "refs/heads/f01-offline-only",
        "observations": {
            control: {
                "source": "GITHUB_READ_ONLY",
                "httpStatus": 200,
                "payload": payload,
            },
        },
    }


def valid_schema(report: dict) -> bool:
    definition = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(definition)
    Draft202012Validator(definition, format_checker=FormatChecker()).validate(report)
    return True


def blocked(output: dict) -> None:
    assert output["decision"] == "BLOCKED_TRUST_ROOT"
    assert output["readOnlyDiagnostic"] is True
    assert len(output["controls"]) == 23
    assert set(output["controls"]) == set(gate.CONTROLS)
    assert all(value["status"] == "NOT_VERIFIABLE" for value in output["controls"].values())
    assert set(output["capabilities"]) == set(gate.CAPABILITY_NAMES)
    assert len(output["capabilities"]) == 7
    assert all(value is False for value in output["capabilities"].values())


@pytest.mark.parametrize("control", LEDGER_CONTROLS)
@pytest.mark.parametrize("backend", INVALID_BACKENDS)
def test_schema_accepts_json_backend_but_fails_closed(control, backend):
    data = build(control, {"backend": backend})
    assert valid_schema(data)
    result = gate.assess_readiness(data)
    blocked(result)
    assert result["controls"][control]["reason"] == ("LEDGER_BACKEND_FIELD_INVALID_OR_UNVERIFIABLE")


@pytest.mark.parametrize("control", LEDGER_CONTROLS)
@pytest.mark.parametrize(("backend", "reason"), TEXT_BACKENDS)
def test_existing_text_backends_preserve_reason(control, backend, reason):
    data = build(control, {"backend": backend})
    assert valid_schema(data)
    result = gate.assess_readiness(data)
    blocked(result)
    assert result["controls"][control]["reason"] == reason


@pytest.mark.parametrize("control", LEDGER_CONTROLS)
def test_backend_absent_is_explicitly_unverifiable(control):
    data = build(control, {})
    assert valid_schema(data)
    result = gate.assess_readiness(data)
    blocked(result)
    assert result["controls"][control]["reason"] == ("LEDGER_BACKEND_FIELD_INVALID_OR_UNVERIFIABLE")


@pytest.mark.parametrize("control", LEDGER_CONTROLS)
def test_snapshot_restore_string_not_promoted(control):
    data = build(control, {"backend": "external", "snapshotRestored": True})
    assert valid_schema(data)
    result = gate.assess_readiness(data)
    blocked(result)
    assert result["controls"][control]["reason"] == "LEDGER_SNAPSHOT_ROLLBACK_UNFENCED"


@pytest.mark.parametrize(
    ("control", "payload"),
    [
        ("main.protection", {"protected": [{"nested": [True, False]}]}),
        ("main.rulesets", {"rulesets": [{"rules": [None, 1, False]}]}),
        (
            "reviews.selfApprovalExcluded",
            {"requester": {"id": [1]}, "approver": ["different"]},
        ),
        ("controller.protectedLocation", {"controllerRef": [{"branch": "main"}]}),
        (
            "commit.preparationExact",
            {"expectedSha": [None, {"sha": "a" * 40}], "actualSha": []},
        ),
        (
            "commit.authorizationExact",
            {"expectedSha": {"a": [True]}, "actualSha": {"a": [True]}},
        ),
        ("coordinator.freshChallenge", {"reused": [True], "expired": {}}),
        ("observer.independentAttestation", {"verified": {"proof": [1, 2, 3]}}),
        ("safety.noWriter", {"authorized": ["YES"]}),
    ],
)
def test_other_schema_accepted_nested_json_never_escalates(control, payload):
    data = build(control, payload)
    assert valid_schema(data)
    blocked(gate.assess_readiness(data))


def test_synthetic_verified_marker_is_not_an_admin_authority():
    data = build(
        "ledger.consumeAtomic",
        {"backend": "external", "status": "VERIFIED", "controllerApproved": True},
    )
    assert valid_schema(data)
    result = gate.assess_readiness(data)
    blocked(result)
    assert result["controls"]["ledger.consumeAtomic"]["status"] == "NOT_VERIFIABLE"


def test_complete_self_declared_positive_report_still_blocks():
    data = build("ledger.externalService", {"backend": "external"})
    data["observations"] = {
        key: {
            "source": "GITHUB_READ_ONLY",
            "httpStatus": 200,
            "payload": {"backend": "external", "status": "VERIFIED", "authorized": True},
        }
        for key in gate.CONTROLS
    }
    assert valid_schema(data)
    blocked(gate.assess_readiness(data))
