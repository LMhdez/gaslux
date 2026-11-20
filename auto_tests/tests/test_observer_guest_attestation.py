"""Laboratory-only TPM2 quote wire fixtures and adversarial verification."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from auto_tests.installer_observer.guest_attestation import (
    AttestationRefused,
    LaboratoryReplayGuard,
    OfflineQuoteVerifier,
    OfflineTrustPolicy,
    QuoteContext,
    QuoteEvidence,
    make_challenge,
)

NOW = datetime(2026, 11, 20, 21, 0, tzinfo=UTC)


def b16(value):
    return value.to_bytes(2, "big")


def tpm2b(data):
    return b16(len(data)) + data


def sign_quote(key, spki, context, pcrs, signer, *, selection=(0, 7)):
    bits = sum(1 << i for i in selection).to_bytes(3, "little")
    committed = hashlib.sha256(b"".join(pcrs[i] for i in selection)).digest()
    attest = (
        (0xFF544347).to_bytes(4, "big")
        + b16(0x8018)
        + tpm2b(bytes.fromhex(signer))
        + tpm2b(make_challenge(context))
        + bytes(17)
        + bytes(8)
        + (1).to_bytes(4, "big")
        + b16(0x000B)
        + b"\x03"
        + bits
        + tpm2b(committed)
    )
    der = key.sign(attest, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    signature = b16(0x0018) + b16(0x000B) + tpm2b(r.to_bytes(32, "big"))
    signature += tpm2b(s.to_bytes(32, "big"))
    return QuoteEvidence(attest, signature, spki, "lab-ak", context, pcrs)


def fixture():
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    context = QuoteContext(
        nonce=bytes(range(32)),
        transaction_id="txn-1",
        session_id="session-1",
        request_id="request-1",
        vm_uuid="vm-lab",
        distribution_id="q4os",
        iso_sha256="e" * 64,
        policy_id="lab-policy",
        policy_version="1",
        policy_sha256="a" * 64,
        trust_anchor_id="lab-anchor",
    )
    pcrs = {0: b"\x10" * 32, 7: b"\x17" * 32}
    policy = OfflineTrustPolicy(
        policy_id=context.policy_id,
        policy_version=context.policy_version,
        policy_sha256=context.policy_sha256,
        trust_anchor_id=context.trust_anchor_id,
        vm_uuid=context.vm_uuid,
        distribution_id=context.distribution_id,
        iso_sha256=context.iso_sha256,
        ak_id="lab-ak",
        ak_spki_sha256=hashlib.sha256(spki).hexdigest(),
        qualified_signer_hex="000b" + "ab" * 32,
        signature_algorithm="ecdsa-sha256",
        pcrs={i: value.hex() for i, value in pcrs.items()},
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
    )
    return key, policy, sign_quote(key, spki, context, pcrs, policy.qualified_signer_hex)


def run(policy, evidence, *, expected_context=None, guard=None):
    if guard is None:
        guard = LaboratoryReplayGuard()
    return OfflineQuoteVerifier(policy, guard).verify(
        evidence,
        expected_context=expected_context or evidence.context,
        now=NOW,
    )


def refused(reason, policy, evidence, *, expected_context=None, guard=None):
    with pytest.raises(AttestationRefused) as exc:
        run(policy, evidence, expected_context=expected_context, guard=guard)
    assert exc.value.code == reason


def test_valid_synthetic_tpm_quote_math_is_not_independent_attestation():
    _, policy, evidence = fixture()
    result = run(policy, evidence)
    assert result.quote_signature_valid and result.challenge_valid
    assert result.pcr_digest_valid and result.pcr_reference_matches
    assert result.ak_trust_status == "AK_TRUST_UNVERIFIED"
    assert result.measured_boot_status == "MEASURED_BOOT_POLICY_UNVERIFIED"
    assert result.vm_binding_status == "VM_BINDING_UNVERIFIED"
    assert result.execution_domain_status == "EXECUTION_DOMAIN_UNVERIFIED"
    assert result.independent_attestation_verified is False
    assert result.classification == "NOT_INDEPENDENT"


def test_unprovisioned_trust_store_is_refused():
    _, _, evidence = fixture()
    refused("TRUST_STORE_MISSING", None, evidence)


def test_replay_refused():
    _, policy, evidence = fixture()
    guard = LaboratoryReplayGuard()
    run(policy, evidence, guard=guard)
    refused("CHALLENGE_REPLAY", policy, evidence, guard=guard)


def test_invalid_quote_signature():
    _, policy, evidence = fixture()
    altered = evidence.signature[:-1] + bytes((evidence.signature[-1] ^ 1,))
    refused("QUOTE_SIGNATURE_INVALID", policy, replace(evidence, signature=altered))


def test_ak_replacement_and_trust_store_substitution():
    _, policy, evidence = fixture()
    attacker = ec.generate_private_key(ec.SECP256R1())
    spki = attacker.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    refused("AK_PUBLIC_KEY_UNTRUSTED", policy, replace(evidence, ak_spki_der=spki))
    refused(
        "AK_PUBLIC_KEY_UNTRUSTED",
        replace(policy, ak_spki_sha256="1" * 64),
        evidence,
    )


@pytest.mark.parametrize("field", ("session_id", "transaction_id", "request_id"))
def test_quote_cannot_cross_request_context(field):
    _, policy, evidence = fixture()
    modified = replace(evidence.context, **{field: "other"})
    refused(
        "CONTEXT_MISMATCH",
        policy,
        replace(evidence, context=modified),
        expected_context=evidence.context,
    )


def test_nonce_mismatch_and_bad_nonce_size():
    _, policy, evidence = fixture()
    changed = replace(evidence.context, nonce=b"\xff" * 32)
    refused(
        "CONTEXT_MISMATCH",
        policy,
        replace(evidence, context=changed),
        expected_context=evidence.context,
    )
    invalid = replace(evidence.context, nonce=b"short")
    refused("NONCE_INVALID", policy, replace(evidence, context=invalid))


def test_attacker_signed_quote_cannot_replace_expected_context():
    key, policy, evidence = fixture()
    changed = replace(evidence.context, request_id="attacker-request")
    other = sign_quote(
        key,
        evidence.ak_spki_der,
        changed,
        evidence.pcrs,
        policy.qualified_signer_hex,
    )
    refused("CONTEXT_MISMATCH", policy, other, expected_context=evidence.context)


def test_untrusted_pcr_value_and_reference():
    _, policy, evidence = fixture()
    altered = dict(evidence.pcrs)
    altered[7] = b"\xee" * 32
    refused("PCR_DIGEST_MISMATCH", policy, replace(evidence, pcrs=altered))
    refused(
        "PCR_POLICY_MISMATCH",
        replace(policy, pcrs={0: "0" * 64, 7: "1" * 64}),
        evidence,
    )


def test_pcr_selection_exact():
    key, policy, evidence = fixture()
    other = sign_quote(
        key,
        evidence.ak_spki_der,
        evidence.context,
        evidence.pcrs,
        policy.qualified_signer_hex,
        selection=(0,),
    )
    refused("PCR_SELECTION_MISMATCH", policy, other)


def test_truncated_and_oversized_quote():
    _, policy, evidence = fixture()
    refused("QUOTE_TRUNCATED", policy, replace(evidence, attest=evidence.attest[:-2]))
    refused("QUOTE_OVERSIZED", policy, replace(evidence, attest=b"X" * 8193))


def test_disallowed_algorithm():
    _, policy, evidence = fixture()
    refused(
        "ALGORITHM_NOT_ALLOWED",
        policy,
        replace(evidence, signature=b16(0x0018) + b16(0x0004)),
    )


def test_event_log_not_falsely_authenticated():
    _, policy, evidence = fixture()
    refused("EVENT_LOG_UNVERIFIED", policy, replace(evidence, event_log=b"forged"))
    refused(
        "AK_TRUST_UNVERIFIED",
        policy,
        replace(evidence, ek_ak_credential_proof=b"fabricated"),
    )


def test_expiration_and_ak_revocation():
    _, policy, evidence = fixture()
    refused(
        "POLICY_EXPIRED",
        replace(policy, valid_until=NOW - timedelta(seconds=1)),
        evidence,
    )
    refused(
        "AK_REVOKED",
        replace(policy, revoked_ak_ids=frozenset({"lab-ak"})),
        evidence,
    )


def test_vm_and_policy_origin_mismatch():
    _, policy, evidence = fixture()
    refused("CONTEXT_MISMATCH", replace(policy, vm_uuid="different-vm"), evidence)
    refused(
        "CONTEXT_MISMATCH",
        replace(policy, policy_sha256="f" * 64),
        evidence,
    )


def test_qualified_signer_mismatch():
    _, policy, evidence = fixture()
    refused(
        "AK_QUALIFIED_SIGNER_MISMATCH",
        replace(policy, qualified_signer_hex=""),
        evidence,
    )


def test_replay_guard_missing_and_invalid():
    _, policy, evidence = fixture()
    with pytest.raises(AttestationRefused) as missing:
        OfflineQuoteVerifier(policy, None).verify(
            evidence, expected_context=evidence.context, now=NOW
        )
    assert missing.value.code == "REPLAY_GUARD_MISSING"
    refused("REPLAY_GUARD_INVALID", policy, evidence, guard=object())


def test_valid_controller_ed25519_does_not_validate_invalid_tpm_quote():
    from auto_tests.tests.test_observer_remote_verifier import (
        make_request,
        make_response,
        trusted_material,
        verifier,
        verify_one,
    )

    private, trust = trusted_material()
    request = make_request()
    signed_response = make_response(private, request)
    authenticated = verify_one(verifier(trust), request, signed_response)
    assert authenticated.controller_signature_verified is True
    assert authenticated.guest_attestation_verified_locally is False
    _, policy, evidence = fixture()
    corrupt = evidence.signature[:-1] + bytes((evidence.signature[-1] ^ 1,))
    refused("QUOTE_SIGNATURE_INVALID", policy, replace(evidence, signature=corrupt))


def test_valid_tpm_quote_does_not_validate_invalid_controller_ed25519():
    from auto_tests.installer_observer.remote_verifier import VerificationRefused
    from auto_tests.tests.test_observer_remote_verifier import (
        make_request,
        make_response,
        trusted_material,
        verifier,
        verify_one,
    )

    _, policy, evidence = fixture()
    assert run(policy, evidence).quote_signature_valid
    private, trust = trusted_material()
    request = make_request()
    signed_response = make_response(private, request)
    signed_response["signature"]["value"] = "A" * 86
    with pytest.raises(VerificationRefused) as caught:
        verify_one(verifier(trust), request, signed_response)
    assert caught.value.code == "signature-invalid"
