"""Offline-only historical Q4OS UI evidence contracts; no guest or disk access."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "schemas/distro-ui-map.schema.json"
EVIDENCE = ROOT / "schemas/distro-ui-evidence.schema.json"


def _schema(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(document)
    return document


def test_both_historical_schemas_are_valid_and_closed() -> None:
    for path in (MAP, EVIDENCE):
        schema = _schema(path)
        assert schema["additionalProperties"] is False
        assert schema["properties"]["distribution"]["const"] == "q4os"
        assert schema["properties"]["schemaVersion"]["const"] == 1


def test_map_explicitly_denies_windows_disk_and_native_install() -> None:
    schema = _schema(MAP)
    lab = schema["properties"]["lab"]["properties"]
    stop = schema["properties"]["stopBoundary"]["properties"]
    assert lab["windowsDiskAttached"]["const"] is False
    assert lab["vmReplicasRequired"]["const"] == 2
    assert stop["nativeCalamaresInstallExecuted"]["const"] is False
    assert stop["windowsDiskModified"]["const"] is False


def test_stop_boundary_rejects_privileged_claims() -> None:
    stop = _schema(MAP)["properties"]["stopBoundary"]
    validator = Draft202012Validator(stop)
    allowed = {
        "lastObservedState": "calamares-users-unfilled",
        "nextStateUnobserved": "calamares-summary",
        "nativeCalamaresInstallExecuted": False,
        "windowsDiskModified": False,
        "accountInputAttempted": False,
        "reason": "Synthetic historical observation only, no native installation",
    }
    assert validator.is_valid(allowed)
    for key in ("nativeCalamaresInstallExecuted", "windowsDiskModified", "accountInputAttempted"):
        forbidden = {**allowed, key: True}
        assert not validator.is_valid(forbidden), key


def test_evidence_does_not_claim_upstream_signature() -> None:
    schema = _schema(EVIDENCE)
    iso = schema["properties"]["iso"]
    validator = Draft202012Validator(iso)
    synthetic = {
        "version": "6.10 r2",
        "officialUrl": "https://downloads.sourceforge.net/project/q4os/test",
        "sha256": "0" * 64,  # Synthetic schema-only value; never an artifact digest.
        "sizeBytes": None,
        "upstreamGpgSignatureVerified": False,
    }
    assert validator.is_valid(synthetic)
    assert not validator.is_valid({**synthetic, "upstreamGpgSignatureVerified": True})


def test_arbitrary_runtime_permissions_are_not_schema_fields() -> None:
    for path, forbidden_name in (
        (MAP, "inputAuthorized"),
        (EVIDENCE, "diskWritesAuthorized"),
    ):
        validator = Draft202012Validator(_schema(path))
        untrusted = {"schemaVersion": 1, "distribution": "q4os", forbidden_name: True}
        violations = list(validator.iter_errors(untrusted))
        assert any(item.validator == "additionalProperties" for item in violations)
        assert any(item.validator == "required" for item in violations)
