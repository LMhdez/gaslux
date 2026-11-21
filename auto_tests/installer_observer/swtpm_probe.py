"""Disposable swtpm/tpm2-tools integration probe; never a production trust oracle."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from auto_tests.installer_observer.guest_attestation import (
    AttestationRefused,
    LaboratoryReplayGuard,
    OfflineQuoteVerifier,
    OfflineTrustPolicy,
    QuoteContext,
    QuoteEvidence,
    make_challenge,
    parse_quote,
)

_PCR_PATTERN = re.compile(r"\s*(0|7)\s*:\s*0x([0-9a-fA-F]{64})\s*")


def load_pcrs(path: Path) -> dict[int, bytes]:
    """Read only the two selected values from tpm2_pcrread textual output."""
    values: dict[int, bytes] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        match = _PCR_PATTERN.fullmatch(line)
        if match:
            index = int(match.group(1))
            if index in values:
                raise ValueError("Duplicate PCR value in tpm2_pcrread output")
            values[index] = bytes.fromhex(match.group(2))
    if set(values) != {0, 7}:
        raise ValueError("Expected exactly PCR 0 and PCR 7 in the SHA256 bank")
    return values


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(work: Path) -> None:
    """Use an ephemeral AK; all policies and credentials remain lab-controlled."""
    now = datetime.now(UTC)
    context = QuoteContext(
        nonce=secrets.token_bytes(32),
        transaction_id="swtpm-transaction",
        session_id="swtpm-session",
        request_id="swtpm-request",
        vm_uuid="no-vm-swtpm-only",
        distribution_id="synthetic",
        iso_sha256="0" * 64,
        policy_id="runner-test-only",
        policy_version="1",
        policy_sha256="1" * 64,
        trust_anchor_id="untrusted-ci-runner",
    )
    challenge = make_challenge(context)
    subprocess.run(
        [
            "tpm2_quote",
            "-c",
            str(work / "ak.ctx"),
            "-l",
            "sha256:0,7",
            "-g",
            "sha256",
            "-q",
            challenge.hex(),
            "-m",
            str(work / "quote.msg"),
            "-s",
            str(work / "quote.sig"),
            "-f",
            "tss",
        ],
        check=True,
        timeout=30,
    )
    quote = (work / "quote.msg").read_bytes()
    signature = (work / "quote.sig").read_bytes()
    signer, quoted_challenge, selection, _ = parse_quote(quote)
    if quoted_challenge != challenge or selection != [0, 7]:
        raise ValueError("Unexpected TPM quote challenge or PCR selection")
    public_key = serialization.load_pem_public_key((work / "ak.pem").read_bytes())
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pcrs = load_pcrs(work / "pcrs.txt")
    policy = OfflineTrustPolicy(
        policy_id=context.policy_id,
        policy_version=context.policy_version,
        policy_sha256=context.policy_sha256,
        trust_anchor_id=context.trust_anchor_id,
        vm_uuid=context.vm_uuid,
        distribution_id=context.distribution_id,
        iso_sha256=context.iso_sha256,
        ak_id="swtpm-lab-ak",
        ak_spki_sha256=hashlib.sha256(spki).hexdigest(),
        qualified_signer_hex=signer.hex(),
        signature_algorithm="ecdsa-sha256",
        pcrs={index: value.hex() for index, value in pcrs.items()},
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(minutes=5),
    )
    evidence = QuoteEvidence(
        attest=quote,
        signature=signature,
        ak_spki_der=spki,
        ak_id=policy.ak_id,
        context=context,
        pcrs=pcrs,
    )
    guard = LaboratoryReplayGuard()
    verifier = OfflineQuoteVerifier(policy, guard)
    result = verifier.verify(evidence, expected_context=context, now=now)
    if not (
        result.quote_signature_valid
        and result.challenge_valid
        and result.pcr_digest_valid
        and result.pcr_reference_matches
        and not result.independent_attestation_verified
        and result.classification == "NOT_INDEPENDENT"
    ):
        raise ValueError("Invalid swtpm laboratory assurance classification")

    try:
        verifier.verify(evidence, expected_context=context, now=now)
    except AttestationRefused as exc:
        if exc.code != "CHALLENGE_REPLAY":
            raise
    else:
        raise ValueError("Replay of genuine swtpm quote was not refused")

    corrupted = replace(evidence, signature=signature[:-1] + bytes([signature[-1] ^ 1]))
    try:
        OfflineQuoteVerifier(policy, LaboratoryReplayGuard()).verify(
            corrupted, expected_context=context, now=now
        )
    except AttestationRefused as exc:
        if exc.code != "QUOTE_SIGNATURE_INVALID":
            raise
    else:
        raise ValueError("Invalid swtpm quote signature was accepted")

    manifest = {
        "source": "real-swtpm-lab-no-qemu",
        "quote_format": "TPMS_ATTEST",
        "signature_format": "TPMT_SIGNATURE",
        "quote_sha256": sha256(work / "quote.msg"),
        "signature_sha256": sha256(work / "quote.sig"),
        "ak_public_sha256": sha256(work / "ak.pem"),
        "pcr_readout_sha256": sha256(work / "pcrs.txt"),
        "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
        "quote_signature_valid": True,
        "challenge_valid": True,
        "pcr_digest_valid": True,
        "replay_refused": True,
        "tampered_signature_refused": True,
        "ak_trust_status": result.ak_trust_status,
        "measured_boot_status": result.measured_boot_status,
        "vm_binding_status": result.vm_binding_status,
        "execution_domain_status": result.execution_domain_status,
        "guest_attestation_verified_locally": False,
        "independent_attestation_verified": False,
        "classification": "NOT_INDEPENDENT",
        "fixture_keys_and_policy_owned_by_runner": True,
        "guest_input_count": 0,
        "disk_writes": "none outside swtpm ephemeral state and lab files",
    }
    (work / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m auto_tests.installer_observer.swtpm_probe LAB_DIR")
    main(Path(sys.argv[1]))
