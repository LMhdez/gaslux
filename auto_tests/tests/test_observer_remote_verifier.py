"""Adversarial tests for the local, fail-closed remote Observer response verifier."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_tests.installer_observer.remote_verifier import (
    InMemoryReplayGuard,
    RemoteResponseVerifier,
    SQLiteReplayGuard,
    TrustStore,
    TrustedController,
    VerificationRefused,
)

NOW = datetime(2026, 11, 20, 13, 0, tzinfo=timezone.utc)
SESSION_ID = "11111111-1111-4111-8111-111111111111"
TRANSACTION_ID = "22222222-2222-4222-8222-222222222222"
REQUEST_ID = "33333333-3333-4333-8333-333333333333"
VM_UUID = "44444444-4444-4444-8444-444444444444"
KEY_ID = "observer-test-key-01"


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def trusted_material():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    policy = TrustedController(
        key_id=KEY_ID,
        public_key_raw=public_key,
        controller_id="test-controller",
        controller_artifact_sha256="a" * 64,
        policy_sha256="b" * 64,
        collector_id="test-collector",
        collector_artifact_sha256="c" * 64,
        vm_uuid=VM_UUID,
        qemu_executable_sha256="d" * 64,
        distribution_id="q4os",
        distribution_version="6.10-r2",
        iso_sha256="e" * 64,
        installer_id="calamares",
        attestation_verifier_id="test-attestation-verifier",
        attestation_trust_anchor_id="test-vtpm-root",
    )
    return private_key, TrustStore({KEY_ID: policy})


def make_request(operation="session.identify", *, sequence=0, nonce="A" * 43, request_id=None):
    return {
        "protocol": 1,
        "operation": operation,
        "session_id": None if operation == "session.identify" else SESSION_ID,
        "transaction_id": TRANSACTION_ID,
        "request_id": request_id or (REQUEST_ID if sequence == 0 else f"{sequence:08d}-3333-4333-8333-333333333333"),
        "nonce": nonce,
        "sequence": sequence,
        "timeout_ms": 5000,
        "max_response_bytes": 1048576,
    }


def make_result(operation="session.identify", *, frame=None):
    if operation == "session.identify":
        return {
            "kind": "session",
            "closed": False,
            "session_expires_at": (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        }
    if operation == "state.read":
        return {
            "kind": "state",
            "observed_at": (NOW + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "snapshot": {"distribution": "q4os", "screen": "summary", "read_only": True},
        }
    if operation == "frame.read":
        image = frame or b"\x89PNG\r\n\x1a\nsynthetic"
        return {
            "kind": "frame",
            "media_type": "image/png",
            "encoding": "base64",
            "data": base64.b64encode(image).decode("ascii"),
            "sha256": sha(image),
        }
    return {"kind": "session", "closed": True, "session_expires_at": None}


def make_response(private_key, request, *, operation=None, mutate=None, alternate_signing=False):
    operation = operation or request["operation"]
    result = make_result(operation)
    response = {
        "protocol": 1,
        "operation": operation,
        "status": "ok",
        "session_id": SESSION_ID,
        "transaction_id": request["transaction_id"],
        "request_id": request["request_id"],
        "request_sha256": sha(rfc8785.dumps(request)),
        "nonce": request["nonce"],
        "sequence": request["sequence"],
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(seconds=20)).isoformat().replace("+00:00", "Z"),
        "controller": {
            "controller_id": "test-controller",
            "key_id": KEY_ID,
            "artifact_sha256": "a" * 64,
            "policy_sha256": "b" * 64,
        },
        "collector": {
            "collector_id": "test-collector",
            "artifact_sha256": "c" * 64,
        },
        "guest": {
            "vm_uuid": VM_UUID,
            "identity_assurance": "cryptographically-attested",
            "qemu_process": {"pid": 4102, "start_ticks": 99001, "executable_sha256": "d" * 64},
            "distribution": {
                "id": "q4os",
                "version": "6.10-r2",
                "iso_sha256": "e" * 64,
                "installer_id": "calamares",
            },
            "attestation": {
                "status": "verified",
                "evidence_sha256": "f" * 64,
                "verifier_id": "test-attestation-verifier",
                "trust_anchor_id": "test-vtpm-root",
            },
        },
        "result": result,
        "result_sha256": sha(rfc8785.dumps(result)),
    }
    if operation != "session.identify":
        response["session_id"] = request["session_id"]
    if mutate:
        mutate(response)
    unsigned = dict(response)
    signing_payload = unsigned
    if alternate_signing:
        signing_payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    else:
        signing_payload = rfc8785.dumps(unsigned)
    signature = private_key.sign(signing_payload)
    response["signature"] = {
        "algorithm": "Ed25519",
        "key_id": KEY_ID,
        "value": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }
    return response


def verifier(trust_store, replay=None):
    return RemoteResponseVerifier(trust_store, replay or InMemoryReplayGuard())


def assert_refused(code, callable_):
    with pytest.raises(VerificationRefused) as caught:
        callable_()
    assert caught.value.code == code


def verify_one(v, request, response, *, deadline=None):
    return v.verify(
        request,
        response,
        deadline=deadline or NOW + timedelta(seconds=4),
        now=NOW,
    )


def test_valid_signed_response_verifies_separate_trust_dimensions():
    private, store = trusted_material()
    request = make_request()
    response = make_response(private, request)
    verified = verify_one(verifier(store), request, response)
    assert verified.controller_signature_verified is True
    assert verified.controller_workload_trusted is True
    assert verified.collector_trusted is True
    assert verified.guest_attestation_status == "verified"
    assert verified.guest_attestation_assertion == "trusted-controller-asserted"
    # The verifier checks the signed controller assertion, not the TPM quote itself.
    assert verified.guest_attestation_verified_locally is False
    assert verified.distribution_id == "q4os"


def test_missing_trust_anchor_is_always_refused():
    private, _ = trusted_material()
    request = make_request()
    response = make_response(private, request)
    assert_refused(
        "trust-anchor-missing",
        lambda: verify_one(RemoteResponseVerifier(None, InMemoryReplayGuard()), request, response),
    )
    assert_refused(
        "untrusted-key",
        lambda: verify_one(verifier(TrustStore({})), request, response),
    )


def test_altered_signature_is_refused():
    private, store = trusted_material()
    request = make_request()
    response = make_response(private, request)
    response["signature"]["value"] = "A" * 86
    assert_refused("signature-invalid", lambda: verify_one(verifier(store), request, response))


def test_nonce_replay_is_refused_after_first_acceptance():
    private, store = trusted_material()
    request = make_request()
    response = make_response(private, request)
    v = verifier(store)
    verify_one(v, request, response)
    assert_refused("replay", lambda: verify_one(v, request, response))


def test_expired_response_is_refused():
    private, store = trusted_material()
    request = make_request()

    def expire(response):
        response["issued_at"] = (NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        response["expires_at"] = (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")

    response = make_response(private, request, mutate=expire)
    assert_refused("expired", lambda: verify_one(verifier(store), request, response))


def test_caller_deadline_is_enforced():
    private, store = trusted_material()
    request = make_request()
    response = make_response(private, request)
    assert_refused(
        "deadline-exceeded",
        lambda: verifier(store).verify(
            request, response, deadline=NOW - timedelta(seconds=1), now=NOW
        ),
    )


def test_transaction_mismatch_is_refused():
    private, store = trusted_material()
    request = make_request()
    response = make_response(private, request)

    def mismatch(payload):
        payload["transaction_id"] = "99999999-9999-4999-8999-999999999999"

    mismatch_response = make_response(private, request, mutate=mismatch)
    assert_refused(
        "request-binding-failed",
        lambda: verify_one(verifier(store), request, mismatch_response),
    )


def test_session_mismatch_is_refused_after_session_creation():
    private, store = trusted_material()
    v = verifier(store)
    identify = make_request()
    verify_one(v, identify, make_response(private, identify))
    request = make_request("state.read", sequence=1, nonce="B" * 43)

    def mismatch(payload):
        payload["session_id"] = "99999999-9999-4999-8999-999999999999"

    response = make_response(private, request, mutate=mismatch)
    assert_refused(
        "session-binding-failed",
        lambda: verify_one(v, request, response),
    )

def test_sequence_must_advance_monotonically():
    private, store = trusted_material()
    v = verifier(store)
    identify = make_request()
    verify_one(v, identify, make_response(private, identify))
    request = make_request("state.read", sequence=1, nonce="B" * 43)
    response = make_response(private, request)
    verify_one(v, request, response)
    repeated_sequence = make_request(
        "state.read", sequence=1, nonce="C" * 43,
        request_id="99999999-3333-4333-8333-333333333333",
    )
    repeated_response = make_response(private, repeated_sequence)
    assert_refused(
        "replay",
        lambda: verify_one(v, repeated_sequence, repeated_response),
    )


def test_attestation_absent_is_refused_even_when_signature_is_valid():
    private, store = trusted_material()

    def remove_attestation(response):
        response["guest"]["identity_assurance"] = "host-observed"
        response["guest"]["attestation"] = {
            "status": "not-provided",
            "evidence_sha256": None,
            "verifier_id": None,
            "trust_anchor_id": None,
        }

    request = make_request()
    response = make_response(private, request, mutate=remove_attestation)
    assert_refused(
        "guest-attestation-required",
        lambda: verify_one(verifier(store), request, response),
    )


def test_attestation_verifier_and_anchor_must_be_pinned():
    private, store = trusted_material()

    def replace_verifier(response):
        response["guest"]["attestation"]["verifier_id"] = "untrusted-verifier"

    request = make_request()
    response = make_response(private, request, mutate=replace_verifier)
    assert_refused(
        "guest-attestation-failed",
        lambda: verify_one(verifier(store), request, response),
    )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("controller_id", "attacker-controller", "controller-integrity-failed"),
        ("artifact_sha256", "9" * 64, "controller-integrity-failed"),
    ],
)
def test_controller_identity_and_artifact_are_pinned(field, value, code):
    private, store = trusted_material()

    def tamper(response):
        response["controller"][field] = value

    request = make_request()
    response = make_response(private, request, mutate=tamper)
    assert_refused(code, lambda: verify_one(verifier(store), request, response))


def test_collector_identity_is_pinned():
    private, store = trusted_material()

    def tamper(response):
        response["collector"]["collector_id"] = "other-collector"

    request = make_request()
    response = make_response(private, request, mutate=tamper)
    assert_refused(
        "collector-integrity-failed",
        lambda: verify_one(verifier(store), request, response),
    )


def test_distribution_and_guest_identity_are_pinned():
    private, store = trusted_material()

    def tamper(response):
        response["guest"]["distribution"]["id"] = "bazzite"

    request = make_request()
    response = make_response(private, request, mutate=tamper)
    assert_refused(
        "distribution-identity-mismatch",
        lambda: verify_one(verifier(store), request, response),
    )


def test_result_digest_is_checked_independently_of_signature():
    private, store = trusted_material()

    def tamper(response):
        response["result"]["snapshot"]["screen"] = "installer"

    request = make_request("state.read", sequence=1, nonce="B" * 43)
    response = make_response(private, request, mutate=tamper)
    # The signature is valid for the mutated response, but the old result hash is not.
    assert_refused(
        "result-integrity-failed",
        lambda: verify_one(verifier(store), request, response),
    )


def test_rfc8785_is_required_not_python_json_sorting():
    private, store = trusted_material()

    def include_float(response):
        response["result"]["snapshot"]["measurement"] = 1.0
        response["result_sha256"] = sha(rfc8785.dumps(response["result"]))

    request = make_request("state.read", sequence=1, nonce="B" * 43)
    response = make_response(private, request, mutate=include_float, alternate_signing=True)
    assert_refused(
        "signature-invalid",
        lambda: verify_one(verifier(store), request, response),
    )


def test_framebuffer_content_hash_is_checked():
    private, store = trusted_material()

    def tamper_frame(response):
        response["result"]["data"] = base64.b64encode(b"\x89PNG\r\n\x1a\nchanged").decode()
        response["result_sha256"] = sha(rfc8785.dumps(response["result"]))

    request = make_request("frame.read", sequence=1, nonce="B" * 43)
    response = make_response(private, request, operation="frame.read", mutate=tamper_frame)
    assert_refused(
        "frame-integrity-failed",
        lambda: verify_one(verifier(store), request, response),
    )


def test_duplicate_json_properties_are_refused():
    private, store = trusted_material()
    request = b'{"protocol":1,"protocol":1}'
    response = make_response(private, make_request())
    assert_refused(
        "json-duplicate-property",
        lambda: verifier(store).verify(
            request, response, deadline=NOW + timedelta(seconds=4), now=NOW
        ),
    )


def test_durable_replay_guard_survives_verifier_reconstruction(tmp_path):
    private, store = trusted_material()
    guard = SQLiteReplayGuard(tmp_path / "replay.sqlite3")
    request = make_request()
    response = make_response(private, request)
    verify_one(verifier(store, guard), request, response)
    # Re-open the durable replay database in a fresh verifier instance.
    reopened = SQLiteReplayGuard(tmp_path / "replay.sqlite3")
    assert_refused("replay", lambda: verify_one(verifier(store, reopened), request, response))


def test_durable_replay_guard_refuses_symlink_database(tmp_path):
    target = tmp_path / "real.sqlite3"
    target.touch(mode=0o600)
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlinks"):
        SQLiteReplayGuard(link)


def test_signed_broker_refusal_is_returned_as_refusal_not_success():
    private, store = trusted_material()
    request = make_request()

    def refuse(response):
        response["status"] = "refused"
        response["session_id"] = None
        response["result"] = {
            "kind": "refusal",
            "code": "unauthorized",
            "message": "Policy denied",
        }
        response["result_sha256"] = sha(rfc8785.dumps(response["result"]))

    response = make_response(private, request, mutate=refuse)
    verified = verify_one(verifier(store), request, response)
    assert verified.status == "refused"
    assert verified.refusal_code == "unauthorized"
