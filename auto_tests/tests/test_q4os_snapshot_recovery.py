"""Tests for signed Q4OS snapshot manifests and restored GPT identity."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))
sys.path.insert(0, str(ROOT / "assets" / "live"))

from gaslux_q4os_snapshot_manifest import (  # noqa: E402
    Q4osSnapshotRecoveryRefusal,
    canonical_manifest,
    sign_manifest,
    verify_signed_manifest,
)
from gaslux_q4os_snapshot_recovery_lab import (  # noqa: E402
    Q4osSnapshotLabRefusal,
    verify_restored_gpt,
)

PLAN = {
    "diskGuid": "a1234567-1111-4111-8111-abcdefabcdef",
    "espGuid": "12345678-1234-4123-8123-123456789abc",
    "espStartLba": 2048,
    "espEndLba": 1050623,
    "espName": "GASLUX-LAB-ESP",
}

MANIFEST = {
    "schemaVersion": 1,
    "operation": "self-contained-read-only-snapshot",
    "runId": "q4os-actions-example-1234",
    "nonce": "0123456789abcdef0123456789abcdef",
    "planSha256": "a" * 64,
    "snapshotFilename": "q4os-recovery-snapshot.qcow2",
    "snapshotSha256": "b" * 64,
    "snapshotFileSizeBytes": 1024,
    "snapshotFormat": "qcow2",
    "snapshotVirtualSizeBytes": 32 * 1024**3,
    "snapshotBackingFile": None,
    "snapshotSelfContained": True,
    "snapshotIntegrityVerified": True,
    "snapshotDurableForRunnerJob": True,
    "snapshotArtifactPrepared": True,
    "artifactRetentionDays": 7,
    "restorePerformed": True,
    "restoreTargetFilename": "q4os-restored.raw",
    "restoreTargetIsNewHostFile": True,
    "restoreCompareVerified": True,
    "restoredGptVerified": True,
    "restoredDiskGuid": PLAN["diskGuid"],
    "restoredEspGuid": PLAN["espGuid"],
    "restoredEspStartLba": PLAN["espStartLba"],
    "restoredEspEndLba": PLAN["espEndLba"],
    "restoredEspLabel": PLAN["espName"],
    "baseImageSparseSha256Before": "c" * 64,
    "baseImageSparseSha256After": "c" * 64,
    "baseImageUnchanged": True,
    "manifestSigned": True,
    "planSignatureVerified": True,
    "gptMetadataVerified": True,
    "guestBooted": False,
    "guestDiskWrites": False,
    "diskWritesAuthorized": False,
    "installationAuthorized": False,
    "calamaresJobsAuthorized": False,
    "windowsEspWritesAuthorized": False,
    "rollbackVerified": False,
}


def signed(item=None):
    value = MANIFEST.copy() if item is None else item
    key = Ed25519PrivateKey.generate()
    raw, signature, public, fingerprint = sign_manifest(value, key)
    return raw, signature, public, fingerprint


def test_manifest_signature_and_read_only_policy():
    raw, signature, public, fingerprint = signed()
    result = verify_signed_manifest(raw, signature, public, fingerprint)
    assert result == MANIFEST
    assert len(public) == 32
    assert len(signature) == 64


def test_manifest_is_canonical_and_deterministic():
    assert canonical_manifest(MANIFEST) == canonical_manifest(MANIFEST)


def test_manifest_signature_rejects_tampered_snapshot_hash():
    raw, signature, public, fingerprint = signed()
    tampered = raw.replace(
        b'"snapshotSha256":"' + b"b" * 64,
        b'"snapshotSha256":"' + b"d" * 64,
    )
    with pytest.raises(Q4osSnapshotRecoveryRefusal):
        verify_signed_manifest(tampered, signature, public, fingerprint)


def test_manifest_rejects_duplicate_properties():
    raw, signature, public, fingerprint = signed()
    duplicate = raw.rstrip()[:-1] + b',"rollbackVerified":false}\n'
    with pytest.raises(Q4osSnapshotRecoveryRefusal, match="Duplicate"):
        verify_signed_manifest(duplicate, signature, public, fingerprint)


def test_manifest_rejects_wrong_public_key_fingerprint():
    raw, signature, public, fingerprint = signed()
    with pytest.raises(Q4osSnapshotRecoveryRefusal, match="fingerprint"):
        verify_signed_manifest(raw, signature, public, "0" * 64)


@pytest.mark.parametrize(
    "field,value",
    [
        ("diskWritesAuthorized", True),
        ("installationAuthorized", True),
        ("calamaresJobsAuthorized", True),
        ("windowsEspWritesAuthorized", True),
        ("guestDiskWrites", True),
        ("guestBooted", True),
        ("rollbackVerified", True),
        ("snapshotBackingFile", "base.raw"),
        ("snapshotSelfContained", False),
        ("restoreCompareVerified", False),
        ("baseImageSparseSha256After", "d" * 64),
    ],
)
def test_manifest_rejects_unsafe_claims(field, value):
    item = MANIFEST.copy()
    item[field] = value
    with pytest.raises(Q4osSnapshotRecoveryRefusal):
        signed(item)


def test_manifest_rejects_oversize_payload():
    raw, signature, public, fingerprint = signed()
    with pytest.raises(Q4osSnapshotRecoveryRefusal, match="size limit"):
        verify_signed_manifest(raw + b" " * 17000, signature, public, fingerprint)


def test_restored_gpt_accepts_exact_signed_plan():
    gpt = {
        "diskGuid": PLAN["diskGuid"],
        "partitions": [
            {
                "number": 1,
                "startLba": PLAN["espStartLba"],
                "endLba": PLAN["espEndLba"],
                "typeGuid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                "partGuid": PLAN["espGuid"],
                "label": PLAN["espName"],
                "filesystem": "vfat",
            }
        ],
    }
    result = verify_restored_gpt(PLAN, gpt)
    assert result["restoredDiskGuid"] == PLAN["diskGuid"]
    assert result["restoredEspGuid"] == PLAN["espGuid"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda item: item.update(diskGuid="ffffffff-ffff-ffff-ffff-ffffffffffff"),
        lambda item: item["partitions"][0].update(startLba=2049),
        lambda item: item["partitions"][0].update(endLba=1050622),
        lambda item: item["partitions"][0].update(typeGuid="0fc63daf-8483-4772-8e79-3d69d8477de4"),
        lambda item: item["partitions"][0].update(partGuid="ffffffff-ffff-ffff-ffff-ffffffffffff"),
        lambda item: item["partitions"][0].update(label="WINDOWS-ESP"),
        lambda item: item["partitions"][0].update(filesystem="ntfs"),
    ],
)
def test_restored_gpt_rejects_mismatch(mutation):
    gpt = {
        "diskGuid": PLAN["diskGuid"],
        "partitions": [
            {
                "number": 1,
                "startLba": PLAN["espStartLba"],
                "endLba": PLAN["espEndLba"],
                "typeGuid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                "partGuid": PLAN["espGuid"],
                "label": PLAN["espName"],
                "filesystem": "vfat",
            }
        ],
    }
    mutation(gpt)
    with pytest.raises(Q4osSnapshotLabRefusal):
        verify_restored_gpt(PLAN, gpt)


def test_restored_gpt_rejects_extra_partition():
    gpt = {
        "diskGuid": PLAN["diskGuid"],
        "partitions": [
            {
                "number": 1,
                "startLba": PLAN["espStartLba"],
                "endLba": PLAN["espEndLba"],
                "typeGuid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                "partGuid": PLAN["espGuid"],
                "label": PLAN["espName"],
                "filesystem": "vfat",
            },
            {
                "number": 2,
                "startLba": 2000000,
                "endLba": 2001000,
                "typeGuid": "0fc63daf-8483-4772-8e79-3d69d8477de4",
                "partGuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "label": "FOREIGN",
                "filesystem": "ext4",
            },
        ],
    }
    with pytest.raises(Q4osSnapshotLabRefusal):
        verify_restored_gpt(PLAN, gpt)
