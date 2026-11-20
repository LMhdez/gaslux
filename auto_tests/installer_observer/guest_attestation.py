"""Strict offline TPM 2.0 Quote gate. Not a broker, guest input, or trust anchor.

Wire fields are TPM 2.0 TPMS_ATTEST and TPMT_SIGNATURE (not invented quote
formats). A correct quote only demonstrates cryptographic consistency: AK/EK
provenance, event-log provenance, VM binding, and independent execution remain
UNVERIFIED until separate independent verifiers exist.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

DOMAIN = b"GASLUX-OBSERVER-TPM2-QUOTE-CHALLENGE-v1\x00"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")


class AttestationRefused(ValueError):
    """Fail-closed gate with a stable reason code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(ok: bool, code: str) -> None:
    if not ok:
        raise AttestationRefused(code)


def bounded(value: bytes, maximum: int, code: str) -> bytes:
    require(isinstance(value, bytes) and 0 < len(value) <= maximum, code)
    return value


def digest(value: str) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def ident(value: str) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


@dataclass(frozen=True)
class QuoteContext:
    nonce: bytes
    transaction_id: str
    session_id: str
    request_id: str
    vm_uuid: str
    distribution_id: str
    iso_sha256: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    trust_anchor_id: str


def make_challenge(context: QuoteContext) -> bytes:
    """Unambiguous 32-byte SHA256 challenge with domain and length prefixes."""
    require(isinstance(context, QuoteContext), "CONTEXT_INVALID")
    require(isinstance(context.nonce, bytes) and len(context.nonce) == 32, "NONCE_INVALID")
    require(digest(context.iso_sha256) and digest(context.policy_sha256), "CONTEXT_INVALID")
    fields = (
        context.transaction_id,
        context.session_id,
        context.request_id,
        context.vm_uuid,
        context.distribution_id,
        context.policy_id,
        context.policy_version,
        context.trust_anchor_id,
    )
    require(all(ident(value) for value in fields), "CONTEXT_INVALID")
    encoded = b"".join(
        len(value).to_bytes(2, "big") + value.encode("ascii")
        for value in fields
    )
    return hashlib.sha256(
        DOMAIN + context.nonce + encoded
        + bytes.fromhex(context.iso_sha256) + bytes.fromhex(context.policy_sha256)
    ).digest()


@dataclass(frozen=True)
class OfflineTrustPolicy:
    """Pins must arrive independently of the response and runner.

    Does not certify AK/EK, validate measured boot event logs, or identify
    QEMU processes. All such conclusions remain explicitly unverified.
    """

    policy_id: str
    policy_version: str
    policy_sha256: str
    trust_anchor_id: str
    vm_uuid: str
    distribution_id: str
    iso_sha256: str
    ak_id: str
    ak_spki_sha256: str
    qualified_signer_hex: str
    signature_algorithm: str
    pcrs: Mapping[int, str]
    valid_from: datetime
    valid_until: datetime
    revoked_ak_ids: frozenset[str] = frozenset()

    def __post_init__(self):
        object.__setattr__(self, "pcrs", MappingProxyType(dict(self.pcrs)))
        require(
            all(digest(getattr(self, name)) for name in (
                "policy_sha256", "iso_sha256", "ak_spki_sha256"
            )), "POLICY_INVALID"
        )
        require(
            all(ident(getattr(self, name)) for name in (
                "policy_id", "policy_version", "trust_anchor_id",
                "vm_uuid", "distribution_id", "ak_id"
            )), "POLICY_INVALID"
        )
        require(self.signature_algorithm in ("ecdsa-sha256", "rsassa-sha256"),
                "ALGORITHM_NOT_ALLOWED")
        require(bool(self.pcrs) and all(
            type(index) is int and 0 <= index < 24 and digest(value)
            for index, value in self.pcrs.items()
        ), "POLICY_INVALID")
        require(
            isinstance(self.qualified_signer_hex, str)
            and len(self.qualified_signer_hex) % 2 == 0
            and len(self.qualified_signer_hex) <= 136
            and re.fullmatch("[0-9a-f]*", self.qualified_signer_hex) is not None,
            "POLICY_INVALID"
        )
        require(
            isinstance(self.valid_from, datetime)
            and isinstance(self.valid_until, datetime)
            and self.valid_from.tzinfo is not None
            and self.valid_until.tzinfo is not None
            and self.valid_from < self.valid_until,
            "POLICY_INVALID"
        )


@dataclass(frozen=True)
class QuoteEvidence:
    attest: bytes  # raw TPMS_ATTEST (without outer TPM2B length)
    signature: bytes  # TPMT_SIGNATURE
    ak_spki_der: bytes  # candidate key: only usable after pin matching
    ak_id: str
    context: QuoteContext
    pcrs: Mapping[int, bytes]
    event_log: bytes | None = None
    ek_ak_credential_proof: bytes | None = None


@dataclass(frozen=True)
class QuoteAssessment:
    quote_signature_valid: bool
    challenge_valid: bool
    ak_pin_matches: bool
    pcr_selection_valid: bool
    pcr_digest_valid: bool
    pcr_reference_matches: bool
    ak_trust_status: str = "AK_TRUST_UNVERIFIED"
    measured_boot_status: str = "MEASURED_BOOT_POLICY_UNVERIFIED"
    vm_binding_status: str = "VM_BINDING_UNVERIFIED"
    execution_domain_status: str = "EXECUTION_DOMAIN_UNVERIFIED"
    independent_attestation_verified: bool = False
    classification: str = "NOT_INDEPENDENT"


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.cursor = 0

    def take(self, size: int) -> bytes:
        require(size >= 0 and self.cursor + size <= len(self.data), "QUOTE_TRUNCATED")
        value = self.data[self.cursor:self.cursor + size]
        self.cursor += size
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def tpm2b(self, maximum: int) -> bytes:
        size = self.u16()
        require(size <= maximum, "QUOTE_FIELD_OVERSIZED")
        return self.take(size)

    def done(self):
        require(self.cursor == len(self.data), "QUOTE_TRAILING_BYTES")


def parse_quote(attest: bytes) -> tuple[bytes, bytes, list[int], bytes]:
    """TPMS_ATTEST/TPMS_QUOTE_INFO according to TCG TPM 2.0 Part 2."""
    r = Reader(bounded(attest, 8192, "QUOTE_OVERSIZED"))
    require(r.u32() == 0xFF544347, "QUOTE_MAGIC_INVALID")
    require(r.u16() == 0x8018, "QUOTE_TYPE_INVALID")
    signer = r.tpm2b(68)
    extra = r.tpm2b(64)
    r.take(17)  # clock, resetCount, restartCount, safe
    r.take(8)  # firmwareVersion
    require(r.u32() == 1, "PCR_SELECTION_UNSUPPORTED")
    require(r.u16() == 0x000B, "ALGORITHM_NOT_ALLOWED")
    require(r.u8() == 3, "PCR_SELECTION_UNSUPPORTED")
    bits = r.take(3)
    selected = [i for i in range(24) if bits[i // 8] & (1 << (i % 8))]
    require(bool(selected), "PCR_SELECTION_INVALID")
    committed = r.tpm2b(32)
    require(len(committed) == 32, "PCR_DIGEST_INVALID")
    r.done()
    return signer, extra, selected, committed


def verify_signature(key: object, attest: bytes, signature: bytes, algorithm: str):
    r = Reader(bounded(signature, 1024, "SIGNATURE_OVERSIZED"))
    signature_alg = r.u16()
    require(r.u16() == 0x000B, "ALGORITHM_NOT_ALLOWED")
    try:
        if algorithm == "ecdsa-sha256":
            require(
                signature_alg == 0x0018
                and isinstance(key, ec.EllipticCurvePublicKey)
                and isinstance(key.curve, ec.SECP256R1), "ALGORITHM_NOT_ALLOWED"
            )
            a, b = r.tpm2b(32), r.tpm2b(32)
            require(bool(a and b), "SIGNATURE_INVALID")
            r.done()
            key.verify(
                utils.encode_dss_signature(int.from_bytes(a, "big"), int.from_bytes(b, "big")),
                attest, ec.ECDSA(hashes.SHA256())
            )
        elif algorithm == "rsassa-sha256":
            require(
                signature_alg == 0x0014
                and isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048,
                "ALGORITHM_NOT_ALLOWED"
            )
            raw = r.tpm2b(512)
            r.done()
            key.verify(raw, attest, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise AttestationRefused("ALGORITHM_NOT_ALLOWED")
    except InvalidSignature as exc:
        raise AttestationRefused("QUOTE_SIGNATURE_INVALID") from exc


class OfflineQuoteVerifier:
    """Gate for quote mathematics only; always marks independent trust unverified."""

    def __init__(self, policy: OfflineTrustPolicy | None, replay_guard: object | None):
        self.policy = policy
        self.replay_guard = replay_guard

    def verify(self, evidence: QuoteEvidence, *, expected_context: QuoteContext,
               now: datetime) -> QuoteAssessment:
        policy = self.policy
        require(policy is not None, "TRUST_STORE_MISSING")
        require(self.replay_guard is not None, "REPLAY_GUARD_MISSING")
        require(isinstance(now, datetime) and now.tzinfo is not None, "TIME_INVALID")
        time = now.astimezone(UTC)
        require(
            policy.valid_from.astimezone(UTC) <= time < policy.valid_until.astimezone(UTC),
            "POLICY_EXPIRED"
        )
        require(policy.ak_id not in policy.revoked_ak_ids, "AK_REVOKED")
        require(isinstance(evidence, QuoteEvidence), "EVIDENCE_INVALID")
        # Event-log replay, EK/AK credential activation and certificate chains
        # are deliberately NOT implemented: never silently accept a claimed proof.
        require(evidence.event_log is None, "EVENT_LOG_UNVERIFIED")
        require(evidence.ek_ak_credential_proof is None, "AK_TRUST_UNVERIFIED")
        require(evidence.ak_id == policy.ak_id and ident(evidence.ak_id), "AK_ID_MISMATCH")
        require(isinstance(expected_context, QuoteContext), "CONTEXT_INVALID")
        require(evidence.context == expected_context, "CONTEXT_MISMATCH")
        for field in (
            "vm_uuid", "distribution_id", "iso_sha256", "policy_id", "policy_version",
            "policy_sha256", "trust_anchor_id"
        ):
            require(getattr(expected_context, field) == getattr(policy, field),
                    "CONTEXT_MISMATCH")
        challenge = make_challenge(expected_context)
        require(
            isinstance(evidence.pcrs, Mapping)
            and 0 < len(evidence.pcrs) <= 24
            and all(type(k) is int and 0 <= k < 24
                    and isinstance(v, bytes) and len(v) == 32
                    for k, v in evidence.pcrs.items()),
            "PCR_VALUES_INVALID"
        )
        attest = bounded(evidence.attest, 8192, "QUOTE_OVERSIZED")
        signature = bounded(evidence.signature, 1024, "SIGNATURE_OVERSIZED")
        key_bytes = bounded(evidence.ak_spki_der, 4096, "AK_PUBLIC_KEY_OVERSIZED")
        require(
            hmac.compare_digest(hashlib.sha256(key_bytes).hexdigest(), policy.ak_spki_sha256),
            "AK_PUBLIC_KEY_UNTRUSTED"
        )
        try:
            key = serialization.load_der_public_key(key_bytes)
        except (ValueError, TypeError) as exc:
            raise AttestationRefused("AK_PUBLIC_KEY_INVALID") from exc
        signer, extra, selected, committed = parse_quote(attest)
        require(signer.hex() == policy.qualified_signer_hex, "AK_QUALIFIED_SIGNER_MISMATCH")
        require(hmac.compare_digest(extra, challenge), "CHALLENGE_MISMATCH")
        require(selected == sorted(policy.pcrs), "PCR_SELECTION_MISMATCH")
        require(selected == sorted(evidence.pcrs), "PCR_SELECTION_MISMATCH")
        verify_signature(key, attest, signature, policy.signature_algorithm)
        calculated = hashlib.sha256(b"".join(evidence.pcrs[i] for i in selected)).digest()
        require(hmac.compare_digest(calculated, committed), "PCR_DIGEST_MISMATCH")
        require(
            all(hmac.compare_digest(evidence.pcrs[i].hex(), policy.pcrs[i])
                for i in selected), "PCR_POLICY_MISMATCH"
        )
        # An independent caller must supply a durable atomic replay ledger.
        guard = self.replay_guard
        require(callable(getattr(guard, "consume_challenge", None)), "REPLAY_GUARD_INVALID")
        try:
            guard.consume_challenge(challenge)
        except AttestationRefused:
            raise
        except Exception as exc:
            raise AttestationRefused("REPLAY_GUARD_UNAVAILABLE") from exc
        return QuoteAssessment(True, True, True, True, True, True)


class LaboratoryReplayGuard:
    """For disposable tests only: no process-restart or external replay protection."""

    def __init__(self):
        self.seen: set[bytes] = set()

    def consume_challenge(self, challenge: bytes):
        if challenge in self.seen:
            raise AttestationRefused("CHALLENGE_REPLAY")
        self.seen.add(challenge)
