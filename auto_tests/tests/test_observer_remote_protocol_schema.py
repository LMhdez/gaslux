"""Schema contracts for the future remote Observer API; no network service is started."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[2]
REQUEST_SCHEMA = json.loads(
    (ROOT / "schemas/observer-readonly-request.schema.json").read_text(encoding="utf-8")
)
RESPONSE_SCHEMA = json.loads(
    (ROOT / "schemas/observer-readonly-response.schema.json").read_text(encoding="utf-8")
)
REQUEST_VALIDATOR = Draft202012Validator(REQUEST_SCHEMA, format_checker=FormatChecker())
RESPONSE_VALIDATOR = Draft202012Validator(RESPONSE_SCHEMA, format_checker=FormatChecker())


def valid_request(operation="session.identify"):
    return {
        "protocol": 1,
        "operation": operation,
        "session_id": None if operation == "session.identify" else "11111111-1111-4111-8111-111111111111",
        "transaction_id": "22222222-2222-4222-8222-222222222222",
        "request_id": "33333333-3333-4333-8333-333333333333",
        "nonce": "A" * 43,
        "sequence": 0,
        "timeout_ms": 5000,
        "max_response_bytes": 1048576,
    }


def valid_response():
    return {
        "protocol": 1,
        "operation": "state.read",
        "status": "ok",
        "session_id": "11111111-1111-4111-8111-111111111111",
        "transaction_id": "22222222-2222-4222-8222-222222222222",
        "request_id": "33333333-3333-4333-8333-333333333333",
        "request_sha256": "a" * 64,
        "nonce": "A" * 43,
        "sequence": 1,
        "issued_at": "2026-11-20T12:00:00Z",
        "expires_at": "2026-11-20T12:00:30Z",
        "controller": {
            "controller_id": "gaslux-control-plane",
            "key_id": "observer-control-2026-01",
            "artifact_sha256": "b" * 64,
            "policy_sha256": "c" * 64,
        },
        "collector": {"collector_id": "observer-frame-collector", "artifact_sha256": "d" * 64},
        "guest": {
            "vm_uuid": "44444444-4444-4444-8444-444444444444",
            "identity_assurance": "host-observed",
            "qemu_process": {"pid": 4102, "start_ticks": 99001, "executable_sha256": "e" * 64},
            "attestation": {
                "status": "not-provided",
                "evidence_sha256": None,
                "verifier_id": None,
                "trust_anchor_id": None,
            },
        },
        "result": {
            "kind": "state",
            "observed_at": "2026-11-20T12:00:01Z",
            "snapshot": {"installer": "anaconda", "screen": "summary", "read_only": True},
        },
        "result_sha256": "f" * 64,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": "observer-control-2026-01",
            "value": "B" * 86,
        },
    }


def test_request_schema_accepts_only_the_four_read_only_operations():
    for operation in ("session.identify", "state.read", "frame.read", "session.close"):
        REQUEST_VALIDATOR.validate(valid_request(operation))


@pytest.mark.parametrize(
    "operation", ["qmp.execute", "rfb.input", "shell.exec", "install", "partition"]
)
def test_request_schema_rejects_mutating_or_generic_operations(operation):
    payload = valid_request()
    payload["operation"] = operation
    with pytest.raises(ValidationError):
        REQUEST_VALIDATOR.validate(payload)


def test_request_schema_requires_fresh_nonce_and_rejects_unknown_fields():
    payload = valid_request()
    payload["nonce"] = "short"
    with pytest.raises(ValidationError):
        REQUEST_VALIDATOR.validate(payload)
    payload = valid_request()
    payload["qmp_command"] = "query-status"
    with pytest.raises(ValidationError):
        REQUEST_VALIDATOR.validate(payload)


def test_response_schema_requires_signed_identity_bound_envelope():
    RESPONSE_VALIDATOR.validate(valid_response())


def test_guest_claim_cannot_be_mislabelled_as_cryptographically_attested():
    payload = valid_response()
    payload["guest"]["identity_assurance"] = "cryptographically-attested"
    with pytest.raises(ValidationError):
        RESPONSE_VALIDATOR.validate(payload)


def test_refusal_response_cannot_smuggle_success_payload():
    payload = valid_response()
    payload["status"] = "refused"
    with pytest.raises(ValidationError):
        RESPONSE_VALIDATOR.validate(payload)


def test_response_rejects_unknown_signature_algorithm_and_fields():
    payload = valid_response()
    payload["signature"]["algorithm"] = "none"
    with pytest.raises(ValidationError):
        RESPONSE_VALIDATOR.validate(payload)
    payload = valid_response()
    payload["shell"] = "not-an-operation"
    with pytest.raises(ValidationError):
        RESPONSE_VALIDATOR.validate(payload)
