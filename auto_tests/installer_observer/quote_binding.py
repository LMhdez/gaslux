"""Detached TPM/Observer v1 binding consistency verifier (NOT an attestation authority).

The v1 signed response does not transport a TPM quote. This separate strict
v2 proposal binds an independently submitted quote to the exact signed v1
response and expected request; neither a fabricated receipt nor matching IDs
authenticates the guest, its measured boot or its QEMU process.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from .durable_quote_replay import DurableQuoteReplayGuard
from .guest_attestation import (
    AttestationRefused,
    OfflineQuoteVerifier,
    QuoteContext,
    QuoteEvidence,
    make_challenge,
    require,
)
from .remote_verifier import RemoteResponseVerifier, VerificationRefused

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas/observer-tpm-quote-binding-v2.schema.json"
)
_BINDING_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(_BINDING_SCHEMA)
_BINDING_VALIDATOR = Draft202012Validator(_BINDING_SCHEMA, format_checker=FormatChecker())


@dataclass(frozen=True)
class LocalBindingAssessment:
    """Consistent signed controller envelope and valid TPM math, NOT VM attestation."""

    controller_signature_valid: bool
    quote_signature_valid: bool
    challenge_valid: bool
    pcr_digest_valid: bool
    replay_consumed_durably: bool
    binding_consistency_valid: bool
    ak_trust_status: str = "AK_TRUST_UNVERIFIED"
    measured_boot_status: str = "MEASURED_BOOT_POLICY_UNVERIFIED"
    vm_binding_status: str = "VM_BINDING_UNVERIFIED"
    execution_domain_status: str = "EXECUTION_DOMAIN_UNVERIFIED"
    independent_attestation_verified: bool = False
    guest_input_authorized: bool = False
    classification: str = "NOT_INDEPENDENT"


def _hash_json(value: Mapping[str, Any]) -> str:
    try:
        return hashlib.sha256(rfc8785.dumps(value)).hexdigest()
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AttestationRefused("BINDING_CANONICALIZATION_INVALID") from exc


def propose_quote_binding(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    evidence: QuoteEvidence,
    context: QuoteContext,
    *,
    policy_id: str,
    policy_version: str,
    policy_sha256: str,
    trust_anchor_id: str,
) -> dict[str, Any]:
    """Compute exact expected fields, without cryptographic validation or authority.

    This helper cannot verify signatures and MUST NOT be used as a receipt of
    independent attestation. Use verify_quote_binding for cryptographic checks.
    """
    require(isinstance(request, Mapping) and isinstance(response, Mapping), "BINDING_INVALID")
    require(
        isinstance(evidence, QuoteEvidence) and isinstance(context, QuoteContext),
        "BINDING_INVALID",
    )
    require(evidence.context == context, "BINDING_CONTEXT_MISMATCH")
    try:
        guest = response["guest"]
        distro = guest["distribution"]
        attestation = guest["attestation"]
        session = response["session_id"]
        op = request["operation"]
        require(op in ("state.read", "frame.read"), "BINDING_OPERATION_UNSUPPORTED")
        require(
            response["operation"] == op and response["status"] == "ok",
            "BINDING_RESPONSE_INVALID",
        )
        require(request["session_id"] == session, "BINDING_SESSION_MISMATCH")
        require(context.session_id == session, "BINDING_SESSION_MISMATCH")
        require(
            context.transaction_id == request["transaction_id"] == response["transaction_id"],
            "BINDING_TRANSACTION_MISMATCH",
        )
        require(
            context.request_id == request["request_id"] == response["request_id"],
            "BINDING_REQUEST_MISMATCH",
        )
        nonce = base64.urlsafe_b64encode(context.nonce).decode("ascii").rstrip("=")
        require(nonce == request["nonce"] == response["nonce"], "BINDING_NONCE_MISMATCH")
        require(context.vm_uuid == guest["vm_uuid"], "BINDING_VM_MISMATCH")
        require(context.distribution_id == distro["id"], "BINDING_DISTRIBUTION_MISMATCH")
        require(context.iso_sha256 == distro["iso_sha256"], "BINDING_ISO_MISMATCH")
        require(trust_anchor_id == context.trust_anchor_id, "BINDING_TRUST_ANCHOR_MISMATCH")
        require(attestation["trust_anchor_id"] == trust_anchor_id, "BINDING_TRUST_ANCHOR_MISMATCH")
        require(
            context.policy_id == policy_id
            and context.policy_version == policy_version
            and context.policy_sha256 == policy_sha256,
            "BINDING_POLICY_MISMATCH",
        )
        proposal = {
            "contract_version": 2,
            "kind": "detached-tpm-quote-binding-proposal",
            "classification": "NOT_INDEPENDENT",
            "guest_input_authorized": False,
            "independent_attestation_verified": False,
            "ak_trust_status": "AK_TRUST_UNVERIFIED",
            "measured_boot_status": "MEASURED_BOOT_POLICY_UNVERIFIED",
            "vm_binding_status": "VM_BINDING_UNVERIFIED",
            "execution_domain_status": "EXECUTION_DOMAIN_UNVERIFIED",
            "transaction_id": context.transaction_id,
            "session_id": context.session_id,
            "request_id": context.request_id,
            "nonce": nonce,
            "vm_uuid": context.vm_uuid,
            "distribution_id": context.distribution_id,
            "distribution_version": distro["version"],
            "iso_sha256": context.iso_sha256,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_sha256": policy_sha256,
            "trust_anchor_id": trust_anchor_id,
            "request_sha256": _hash_json(request),
            "response_sha256": _hash_json(response),
            "quote_sha256": hashlib.sha256(evidence.attest).hexdigest(),
            "signature_sha256": hashlib.sha256(evidence.signature).hexdigest(),
            "challenge_sha256": hashlib.sha256(make_challenge(context)).hexdigest(),
            "issued_at": response["issued_at"],
            "expires_at": response["expires_at"],
        }
        _BINDING_VALIDATOR.validate(proposal)
        return proposal
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        if isinstance(exc, AttestationRefused):
            raise
        raise AttestationRefused("BINDING_INVALID") from exc


def verify_quote_binding(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    proposal: Mapping[str, Any],
    evidence: QuoteEvidence,
    expected_context: QuoteContext,
    *,
    remote_verifier: RemoteResponseVerifier,
    quote_verifier: OfflineQuoteVerifier,
    deadline: datetime,
    now: datetime,
) -> LocalBindingAssessment:
    """Verify the signed v1 envelope + TPM quote + durable consumption.

    NO signing or trust elevation is implied by an unsigned proposal. The
    two replay ledgers commit independently; a partial failure is terminal.
    """
    require(isinstance(proposal, Mapping), "BINDING_INVALID")
    require(
        isinstance(quote_verifier.replay_guard, DurableQuoteReplayGuard),
        "BINDING_DURABLE_REPLAY_REQUIRED",
    )
    policy = quote_verifier.policy
    require(policy is not None, "TRUST_STORE_MISSING")
    expected = propose_quote_binding(
        request,
        response,
        evidence,
        expected_context,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_sha256=policy.policy_sha256,
        trust_anchor_id=policy.trust_anchor_id,
    )
    try:
        _BINDING_VALIDATOR.validate(dict(proposal))
        require(_hash_json(dict(proposal)) == _hash_json(expected), "BINDING_PROPOSAL_MISMATCH")
    except (ValidationError, TypeError, ValueError) as exc:
        if isinstance(exc, AttestationRefused):
            raise
        raise AttestationRefused("BINDING_PROPOSAL_INVALID") from exc
    try:
        verified = remote_verifier.verify(request, response, deadline=deadline, now=now)
    except VerificationRefused as exc:
        raise AttestationRefused("BINDING_REMOTE_RESPONSE_REFUSED") from exc
    require(verified.controller_signature_verified, "BINDING_REMOTE_SIGNATURE_MISSING")
    require(
        verified.transaction_id == expected_context.transaction_id
        and verified.request_id == expected_context.request_id
        and verified.session_id == expected_context.session_id
        and verified.distribution_id == expected_context.distribution_id
        and verified.iso_sha256 == expected_context.iso_sha256,
        "BINDING_REMOTE_CONTEXT_MISMATCH",
    )
    quote_result = quote_verifier.verify(evidence, expected_context=expected_context, now=now)
    require(quote_result.classification == "NOT_INDEPENDENT", "BINDING_ASSURANCE_ESCALATION")
    require(not quote_result.independent_attestation_verified, "BINDING_ASSURANCE_ESCALATION")
    return LocalBindingAssessment(
        controller_signature_valid=True,
        quote_signature_valid=quote_result.quote_signature_valid,
        challenge_valid=quote_result.challenge_valid,
        pcr_digest_valid=quote_result.pcr_digest_valid,
        replay_consumed_durably=True,
        binding_consistency_valid=True,
    )
