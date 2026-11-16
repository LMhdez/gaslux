"""Ed25519 signed lab-handoff negative tests; no production signer or disk writes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_candidate_handoff import (  # noqa: E402
    CandidateHandoffError,
    canonical_json,
    verify_handoff,
)


@pytest.fixture
def bound(tmp_path):
    private = Ed25519PrivateKey.generate()
    pub = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_path = tmp_path / "pub"
    public_path.write_bytes(pub)
    payload = {
        "schemaVersion": 1,
        "distributionId": "popos",
        "backend": "system76",
        "runId": "test-run-12345678",
        "firmwareLayout": "uefi/gpt",
        "isoSha256": "a" * 64,
        "isoSizeBytes": 100000,
        "windowsDiskProofSha256": "b" * 64,
        "windowsBootProofSha256": "c" * 64,
        "targetRootUuid": "12345678-1234-1234-1234-123456789abc",
        "espUuid": "ABCD-1234",
        "rootFilesystem": "ext4",
        "operation": "read-only",
        "guestOnly": True,
    }
    payload_path = tmp_path / "payload.json"
    signature_path = tmp_path / "signature"

    def write(p):
        raw = canonical_json(p)
        payload_path.write_bytes(raw)
        signature_path.write_bytes(private.sign(raw))

    write(payload)
    expected = {
        k: payload[k]
        for k in (
            "runId",
            "distributionId",
            "backend",
            "isoSha256",
            "isoSizeBytes",
            "windowsDiskProofSha256",
            "windowsBootProofSha256",
            "targetRootUuid",
            "espUuid",
            "firmwareLayout",
        )
    }
    return {
        "payload": payload,
        "expected": expected,
        "write": write,
        "payload_path": payload_path,
        "signature_path": signature_path,
        "trusted_key_path": public_path,
        "trusted_key_sha256": hashlib.sha256(pub).hexdigest(),
    }


def check(bound, **change):
    args = {
        k: bound[k]
        for k in (
            "payload_path",
            "signature_path",
            "trusted_key_path",
            "trusted_key_sha256",
            "expected",
        )
    }
    args.update(change)
    return verify_handoff(
        args.pop("payload_path"), args.pop("signature_path"), args.pop("trusted_key_path"), **args
    )


def test_valid_lab_signed_context_is_explicitly_non_installable(bound):
    result = check(bound)
    assert result["signatureVerified"] is True
    assert result["installationAuthorized"] is False
    assert result["antiReplayDurableStateVerified"] is False


@pytest.mark.parametrize(
    "distro,backend,layout,root,esp",
    [
        ("popos", "system76", "uefi/gpt", "ext4", "ABCD-1234"),
        ("q4os", "q4os-native", "bios/mbr", "ext4", "none"),
        ("bazzite", "fedora-atomic", "uefi/gpt", "btrfs", "ABCD-1234"),
    ],
)
def test_independent_backend_policy(bound, distro, backend, layout, root, esp):
    values = dict(
        bound["payload"],
        distributionId=distro,
        backend=backend,
        firmwareLayout=layout,
        rootFilesystem=root,
        espUuid=esp,
    )
    bound["write"](values)
    bound["expected"] = {key: values[key] for key in bound["expected"]}
    assert check(bound)["installationAuthorized"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("backend", "debian-squashfs"),
        ("operation", "install"),
        ("guestOnly", False),
        ("rootFilesystem", "ext4-wrong"),
        ("espUuid", "wrong"),
        ("isoSha256", "xyz"),
        ("isoSizeBytes", True),
        ("runId", "../etc"),
        ("firmwareLayout", "uefi/mbr"),
    ],
)
def test_signed_but_unsafe_payload_rejected(bound, field, value):
    values = dict(bound["payload"], **{field: value})
    bound["write"](values)
    with pytest.raises(CandidateHandoffError):
        check(bound)


def test_altered_signature_and_untrusted_anchor_rejected(bound):
    bound["signature_path"].write_bytes(b"X" * 64)
    with pytest.raises(CandidateHandoffError):
        check(bound)
    bound["write"](bound["payload"])
    with pytest.raises(CandidateHandoffError, match="trust-anchor"):
        check(bound, trusted_key_sha256="f" * 64)


def test_signed_wrong_run_and_windows_boot_proof_rejected(bound):
    changed = dict(bound["payload"], runId="other-run-12345678")
    bound["write"](changed)
    with pytest.raises(CandidateHandoffError, match="Trusted handoff"):
        check(bound)
    changed = dict(bound["payload"], windowsBootProofSha256="f" * 64)
    bound["write"](changed)
    with pytest.raises(CandidateHandoffError, match="Trusted handoff"):
        check(bound)


def test_incomplete_context_and_replay_impersonation_rejected(bound):
    with pytest.raises(CandidateHandoffError, match="incomplete"):
        check(bound, expected={"runId": bound["payload"]["runId"]})
    with pytest.raises(CandidateHandoffError, match="Trusted handoff"):
        check(bound, expected=dict(bound["expected"], runId="replay-12345678"))


def test_json_duplicate_and_noncanonical_rejected(bound):
    raw = bound["payload_path"].read_bytes()
    bad = raw[:-1] + b',"runId":"evil-12345678"}'
    bound["payload_path"].write_bytes(bad)
    with pytest.raises(CandidateHandoffError):
        check(bound)
    bound["payload_path"].write_bytes(json.dumps(bound["payload"]).encode("utf-8"))
    with pytest.raises(CandidateHandoffError):
        check(bound)


def test_symlinked_payload_and_key_refused(bound, tmp_path):
    alias = tmp_path / "link"
    alias.symlink_to(bound["payload_path"])
    with pytest.raises(CandidateHandoffError):
        check(bound, payload_path=alias)
    key_alias = tmp_path / "key-link"
    key_alias.symlink_to(bound["trusted_key_path"])
    with pytest.raises(CandidateHandoffError):
        check(bound, trusted_key_path=key_alias)


def test_bazzite_mbr_rejected_even_with_valid_signature(bound):
    p = dict(
        bound["payload"],
        distributionId="bazzite",
        backend="fedora-atomic",
        firmwareLayout="bios/mbr",
        espUuid="none",
        rootFilesystem="btrfs",
    )
    bound["write"](p)
    with pytest.raises(CandidateHandoffError, match="Backend/layout"):
        check(bound)
