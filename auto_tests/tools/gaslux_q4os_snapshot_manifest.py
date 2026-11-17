"""Ed25519-signed, host-only Q4OS snapshot evidence; never grants disk-write authority."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b"GASLUX-Q4OS-DURABLE-SNAPSHOT-V1\n"
MAX_MANIFEST_BYTES = 16384
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
SNAPSHOT_NAME = "q4os-recovery-snapshot.qcow2"
RESTORE_NAME = "q4os-restored.raw"
DISK_BYTES = 32 * 1024**3


class Q4osSnapshotRecoveryRefusal(RuntimeError):
    """Raised when snapshot evidence is malformed or violates the safety contract."""


def canonical_manifest(value: dict[str, Any]) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise Q4osSnapshotRecoveryRefusal("Snapshot manifest is not canonical JSON") from exc
    return (encoded + "\n").encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Q4osSnapshotRecoveryRefusal("Duplicate manifest JSON property: " + key)
        result[key] = value
    return result


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Q4osSnapshotRecoveryRefusal(reason)


def _validate_manifest(value: dict[str, Any]) -> None:
    fields = {
        "schemaVersion", "operation", "runId", "nonce", "planSha256",
        "snapshotFilename", "snapshotSha256", "snapshotFileSizeBytes",
        "snapshotFormat", "snapshotVirtualSizeBytes", "snapshotBackingFile",
        "snapshotSelfContained", "snapshotIntegrityVerified",
        "snapshotDurableForRunnerJob", "snapshotArtifactPrepared", "artifactRetentionDays", "restorePerformed",
        "restoreTargetFilename", "restoreTargetIsNewHostFile", "restoreCompareVerified",
        "restoredGptVerified", "restoredDiskGuid", "restoredEspGuid",
        "restoredEspStartLba", "restoredEspEndLba", "restoredEspLabel",
        "baseImageSparseSha256Before", "baseImageSparseSha256After",
        "baseImageUnchanged", "manifestSigned", "planSignatureVerified",
        "gptMetadataVerified", "guestBooted", "guestDiskWrites",
        "diskWritesAuthorized", "installationAuthorized", "calamaresJobsAuthorized",
        "windowsEspWritesAuthorized", "rollbackVerified",
    }
    _require(set(value) == fields, "Snapshot manifest fields differ from contract")
    _require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1, "Unsupported snapshot manifest schema")
    _require(value["operation"] == "self-contained-read-only-snapshot", "Unexpected snapshot operation")
    _require(isinstance(value["runId"], str) and 12 <= len(value["runId"]) <= 100, "Invalid run ID")
    _require(isinstance(value["nonce"], str) and NONCE_RE.fullmatch(value["nonce"]) is not None, "Invalid nonce")
    for field in ("planSha256", "snapshotSha256", "baseImageSparseSha256Before", "baseImageSparseSha256After"):
        _require(isinstance(value[field], str) and HASH_RE.fullmatch(value[field]) is not None, f"Invalid {field}")
    _require(value["snapshotFilename"] == SNAPSHOT_NAME, "Unexpected snapshot filename")
    _require(value["restoreTargetFilename"] == RESTORE_NAME, "Unexpected restore target filename")
    _require(value["snapshotFormat"] == "qcow2", "Snapshot is not qcow2")
    _require(value["snapshotBackingFile"] is None, "Snapshot must not depend on a backing file")
    _require(type(value["snapshotFileSizeBytes"]) is int and value["snapshotFileSizeBytes"] > 0, "Invalid snapshot file size")
    _require(type(value["snapshotVirtualSizeBytes"]) is int and value["snapshotVirtualSizeBytes"] == DISK_BYTES, "Snapshot virtual size mismatch")
    _require(type(value["artifactRetentionDays"]) is int and value["artifactRetentionDays"] == 7, "Unexpected artifact retention")
    _require(type(value["restoredEspStartLba"]) is int and value["restoredEspStartLba"] == 2048, "Restored ESP start mismatch")
    _require(type(value["restoredEspEndLba"]) is int and value["restoredEspEndLba"] == 1050623, "Restored ESP end mismatch")
    try:
        uuid.UUID(value["restoredDiskGuid"])
        uuid.UUID(value["restoredEspGuid"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise Q4osSnapshotRecoveryRefusal("Malformed restored GPT GUID") from exc
    _require(value["restoredEspLabel"] == "GASLUX-LAB-ESP", "Restored ESP label mismatch")
    true_fields = (
        "snapshotSelfContained", "snapshotIntegrityVerified", "snapshotDurableForRunnerJob", "snapshotArtifactPrepared",
        "restorePerformed", "restoreTargetIsNewHostFile", "restoreCompareVerified",
        "restoredGptVerified", "baseImageUnchanged", "manifestSigned",
        "planSignatureVerified", "gptMetadataVerified",
    )
    false_fields = (
        "guestBooted", "guestDiskWrites", "diskWritesAuthorized", "installationAuthorized",
        "calamaresJobsAuthorized", "windowsEspWritesAuthorized", "rollbackVerified",
    )
    for field in true_fields:
        _require(value[field] is True, f"{field} must be true")
    for field in false_fields:
        _require(value[field] is False, f"{field} must remain false")
    _require(value["baseImageSparseSha256Before"] == value["baseImageSparseSha256After"], "Base image changed during snapshot/restore")


def sign_manifest(
    manifest: dict[str, Any], private_key: Ed25519PrivateKey
) -> tuple[bytes, bytes, bytes, str]:
    _validate_manifest(manifest)
    raw = canonical_manifest(manifest)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signature = private_key.sign(DOMAIN + raw)
    fingerprint = hashlib.sha256(public_key).hexdigest()
    return raw, signature, public_key, fingerprint


def verify_signed_manifest(
    raw: bytes, signature: bytes, public_key: bytes, fingerprint: str
) -> dict[str, Any]:
    _require(len(raw) <= MAX_MANIFEST_BYTES, "Snapshot manifest exceeds size limit")
    _require(len(signature) == 64, "Invalid Ed25519 signature length")
    _require(len(public_key) == 32, "Invalid Ed25519 public key length")
    _require(
        isinstance(fingerprint, str)
        and HASH_RE.fullmatch(fingerprint) is not None
        and hashlib.sha256(public_key).hexdigest() == fingerprint,
        "Snapshot public-key fingerprint mismatch",
    )
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Q4osSnapshotRecoveryRefusal("Malformed snapshot manifest JSON") from exc
    _require(isinstance(value, dict), "Snapshot manifest must be an object")
    _validate_manifest(value)
    _require(canonical_manifest(value) == raw, "Snapshot manifest is not canonical")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, DOMAIN + raw)
    except (InvalidSignature, ValueError) as exc:
        raise Q4osSnapshotRecoveryRefusal("Snapshot manifest signature verification failed") from exc
    return value
