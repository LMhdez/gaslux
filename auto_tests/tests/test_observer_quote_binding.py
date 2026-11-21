"""Adversarial local consistency contract for detached quote + signed v1 response."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from auto_tests.installer_observer.durable_quote_replay import DurableQuoteReplayGuard
from auto_tests.installer_observer.guest_attestation import (
    AttestationRefused,
    OfflineQuoteVerifier,
)
from auto_tests.installer_observer.quote_binding import (
    propose_quote_binding,
    verify_quote_binding,
)
from auto_tests.installer_observer.remote_verifier import InMemoryReplayGuard, RemoteResponseVerifier
from auto_tests.tests.test_observer_guest_attestation import fixture, sign_quote
from auto_tests.tests.test_observer_remote_verifier import (
    NOW,
    SESSION_ID,
    VM_UUID,
    make_request,
    make_response,
    nonce_for,
    trusted_material,
)


def setup(tmp_path):
    tmp_path.chmod(0o700)
    key, policy, evidence = fixture()
    private, trust = trusted_material()
    request0 = make_request(nonce=nonce_for(0x41))
    response0 = make_response(private, request0)
    remote = RemoteResponseVerifier(trust, InMemoryReplayGuard())
    remote.verify(request0, response0, deadline=NOW + timedelta(seconds=4), now=NOW)
    request = make_request("state.read", sequence=1, nonce=nonce_for(0x42))
    response = make_response(private, request)
    ctx = replace(
        evidence.context,
        nonce=bytes([0x42]) * 32,
        transaction_id=request["transaction_id"],
        session_id=SESSION_ID,
        request_id=request["request_id"],
        vm_uuid=VM_UUID,
        distribution_id="q4os",
        iso_sha256="e" * 64,
        trust_anchor_id="test-vtpm-root",
    )
    policy = replace(
        policy,
        vm_uuid=VM_UUID,
        distribution_id="q4os",
        iso_sha256="e" * 64,
        trust_anchor_id="test-vtpm-root",
        valid_from=NOW - timedelta(minutes=5),
        valid_until=NOW + timedelta(minutes=5),
    )
    signed_quote = sign_quote(
        key, evidence.ak_spki_der, ctx, evidence.pcrs, policy.qualified_signer_hex
    )
    path = tmp_path / "binding.sqlite3"
    quote_verifier = OfflineQuoteVerifier(policy, DurableQuoteReplayGuard.provision(path))
    proposal = propose_quote_binding(
        request,
        response,
        signed_quote,
        ctx,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_sha256=policy.policy_sha256,
        trust_anchor_id=policy.trust_anchor_id,
    )
    return dict(
        key=key, policy=policy, evidence=signed_quote, context=ctx,
        request=request, response=response, private=private, remote=remote,
        proposal=proposal, quote=quote_verifier, path=path,
    )


def bind(data, **updates):
    args = {
        "request": data["request"],
        "response": data["response"],
        "proposal": data["proposal"],
        "evidence": data["evidence"],
        "expected_context": data["context"],
        "remote_verifier": data["remote"],
        "quote_verifier": data["quote"],
        "deadline": NOW + timedelta(seconds=4),
        "now": NOW,
    }
    args.update(updates)
    return verify_quote_binding(**args)


def refusal(code, fn):
    with pytest.raises(AttestationRefused) as caught:
        fn()
    assert caught.value.code == code


def proposed(data, *, context=None, evidence=None, request=None, response=None, policy=None):
    ctx = context or data["context"]
    p = policy or data["policy"]
    return propose_quote_binding(
        request or data["request"],
        response or data["response"],
        evidence or data["evidence"],
        ctx,
        policy_id=p.policy_id,
        policy_version=p.policy_version,
        policy_sha256=p.policy_sha256,
        trust_anchor_id=p.trust_anchor_id,
    )


def resign(data, context):
    original = data["evidence"]
    return sign_quote(
        data["key"], original.ak_spki_der, context, original.pcrs,
        data["policy"].qualified_signer_hex,
    )


def test_exact_signed_v1_and_quote_are_only_locally_consistent(tmp_path):
    data = setup(tmp_path)
    result = bind(data)
    assert result.controller_signature_valid and result.quote_signature_valid
    assert result.pcr_digest_valid and result.challenge_valid
    assert result.replay_consumed_durably and result.binding_consistency_valid
    assert result.ak_trust_status == "AK_TRUST_UNVERIFIED"
    assert result.measured_boot_status == "MEASURED_BOOT_POLICY_UNVERIFIED"
    assert result.vm_binding_status == "VM_BINDING_UNVERIFIED"
    assert result.execution_domain_status == "EXECUTION_DOMAIN_UNVERIFIED"
    assert result.classification == "NOT_INDEPENDENT"
    assert not result.independent_attestation_verified
    assert not result.guest_input_authorized


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("transaction_id", "other-txn", "BINDING_TRANSACTION_MISMATCH"),
        ("session_id", "other-session", "BINDING_SESSION_MISMATCH"),
        ("request_id", "other-request", "BINDING_REQUEST_MISMATCH"),
        ("vm_uuid", "99999999-9999-4999-8999-999999999999", "BINDING_VM_MISMATCH"),
        ("iso_sha256", "f" * 64, "BINDING_ISO_MISMATCH"),
        ("distribution_id", "other-distro", "BINDING_DISTRIBUTION_MISMATCH"),
    ),
)
def test_cross_context_genuine_quote_is_refused(tmp_path, field, value, reason):
    data = setup(tmp_path)
    altered = replace(data["context"], **{field: value})
    signed = resign(data, altered)
    refusal(reason, lambda: proposed(data, context=altered, evidence=signed))


@pytest.mark.parametrize(
    "field",
    ("policy_id", "policy_version", "policy_sha256", "trust_anchor_id"),
)
def test_wrong_quote_policy_cannot_bind(tmp_path, field):
    data = setup(tmp_path)
    altered = replace(data["context"], **{field: "wrong" if field != "policy_sha256" else "f" * 64})
    signed = resign(data, altered)
    refusal("BINDING_POLICY_MISMATCH" if field != "trust_anchor_id" else "BINDING_TRUST_ANCHOR_MISMATCH",
            lambda: proposed(data, context=altered, evidence=signed))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("classification", "INDEPENDENT"),
        ("independent_attestation_verified", True),
        ("guest_input_authorized", True),
        ("measured_boot_status", "MEASURED_BOOT_POLICY_VERIFIED"),
        ("vm_binding_status", "VM_BINDING_VERIFIED"),
        ("execution_domain_status", "EXECUTION_DOMAIN_VERIFIED"),
        ("ak_trust_status", "AK_TRUST_VERIFIED"),
    ),
)
def test_unsigned_proposal_cannot_elevate_assurance_or_input(tmp_path, field, value):
    data = setup(tmp_path)
    proposal = {**data["proposal"], field: value}
    refusal("BINDING_PROPOSAL_INVALID", lambda: bind(data, proposal=proposal))


def test_extra_assertion_is_not_authenticated_attestation(tmp_path):
    data = setup(tmp_path)
    proposal = {**data["proposal"], "trust_anchor_verified": True}
    refusal("BINDING_PROPOSAL_INVALID", lambda: bind(data, proposal=proposal))


def test_unsigned_altered_controller_response_cannot_match_quote(tmp_path):
    data = setup(tmp_path)
    forged = {**data["response"], "issued_at": "2026-11-20T12:59:59Z"}
    proposal = proposed(data, response=forged)
    refusal("BINDING_REMOTE_RESPONSE_REFUSED", lambda: bind(data, response=forged, proposal=proposal))


def test_replayed_remote_response_is_rejected(tmp_path):
    data = setup(tmp_path)
    bind(data)
    refusal("BINDING_REMOTE_RESPONSE_REFUSED", lambda: bind(data))


def test_outside_response_time_window_is_refused(tmp_path):
    data = setup(tmp_path)
    refusal(
        "BINDING_REMOTE_RESPONSE_REFUSED",
        lambda: bind(data, now=NOW + timedelta(minutes=1), deadline=NOW + timedelta(minutes=2)),
    )


def test_no_non_durable_guard_may_claim_durable_binding(tmp_path):
    from auto_tests.installer_observer.guest_attestation import LaboratoryReplayGuard

    data = setup(tmp_path)
    alternative = OfflineQuoteVerifier(data["policy"], LaboratoryReplayGuard())
    refusal("BINDING_DURABLE_REPLAY_REQUIRED", lambda: bind(data, quote_verifier=alternative))


def test_changed_quote_signature_digest_blocks_proposal(tmp_path):
    data = setup(tmp_path)
    signed = replace(
        data["evidence"],
        signature=data["evidence"].signature[:-1]
        + bytes([data["evidence"].signature[-1] ^ 1]),
    )
    # A new proposal describes these modified bytes but the genuine TPM check
    # must reject the signature after signed v1 verification.
    proposal = proposed(data, evidence=signed)
    refusal(
        "QUOTE_SIGNATURE_INVALID",
        lambda: bind(data, evidence=signed, proposal=proposal),
    )
