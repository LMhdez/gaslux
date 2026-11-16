#!/usr/bin/env python3
"""Read-only Ed25519 candidate handoff verifier (NOT an installer authorization).

An independently trusted public-key digest and expected run identity MUST be
provided by the laboratory harness, never taken from the signed document.
No production trust key is included. No installer or disk command is invoked.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_FAT_UUID = re.compile(r"[0-9A-F]{4}-[0-9A-F]{4}\Z")
_RUN = re.compile(r"[A-Za-z0-9_-]{12,100}\Z")
_LAYOUTS = {"bios/mbr", "uefi/gpt"}
_PROFILES = {
    "popos": ("system76", {"bios/mbr", "uefi/gpt"}, "ext4"),
    "q4os": ("q4os-native", {"bios/mbr", "uefi/gpt"}, "ext4"),
    "bazzite": ("fedora-atomic", {"uefi/gpt"}, "btrfs"),
}
_KEYS = frozenset({
    "schemaVersion", "distributionId", "backend", "runId",
    "firmwareLayout", "isoSha256", "isoSizeBytes",
    "windowsDiskProofSha256", "windowsBootProofSha256",
    "targetRootUuid", "espUuid", "rootFilesystem",
    "operation", "guestOnly",
})


class CandidateHandoffError(ValueError):
    """An untrusted, altered, or unsupported diagnostic handoff was refused."""


def canonical_json(payload: dict) -> bytes:
    """Canonical encoding required by this lab protocol (not generic RFC 8785)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CandidateHandoffError("Duplicate JSON property")
        result[key] = value
    return result


def _read_file(path: Path, max_len: int) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise CandidateHandoffError("Missing, relative or symlinked evidence")
    if path.stat().st_size > max_len or path.stat().st_size == 0:
        raise CandidateHandoffError("Invalid evidence length")
    return path.read_bytes()


def _validate_payload(payload: object) -> dict:
    if type(payload) is not dict or set(payload) != _KEYS:
        raise CandidateHandoffError("Missing or extra handoff properties")
    if type(payload["schemaVersion"]) is not int or payload["schemaVersion"] != 1:
        raise CandidateHandoffError("Unrecognized handoff version")
    distro = payload["distributionId"]
    if type(distro) is not str or distro not in _PROFILES:
        raise CandidateHandoffError("Unknown candidate distribution")
    backend, layouts, fs = _PROFILES[distro]
    if (payload["backend"] != backend or payload["firmwareLayout"] not in layouts
            or payload["rootFilesystem"] != fs):
        raise CandidateHandoffError("Backend/layout/root filesystem mismatch")
    if type(payload["runId"]) is not str or not _RUN.fullmatch(payload["runId"]):
        raise CandidateHandoffError("Invalid transaction ID")
    for field in ("isoSha256", "windowsDiskProofSha256", "windowsBootProofSha256"):
        if type(payload[field]) is not str or not _SHA.fullmatch(payload[field]):
            raise CandidateHandoffError("Invalid digest: " + field)
    if (type(payload["isoSizeBytes"]) is not int or
            not 80 * 1024 <= payload["isoSizeBytes"] <= 16 * 1024**3):
        raise CandidateHandoffError("Invalid ISO size")
    if (type(payload["targetRootUuid"]) is not str or
            not _UUID.fullmatch(payload["targetRootUuid"])):
        raise CandidateHandoffError("Invalid root UUID")
    esp = payload["espUuid"]
    if payload["firmwareLayout"] == "uefi/gpt":
        if type(esp) is not str or not _FAT_UUID.fullmatch(esp):
            raise CandidateHandoffError("Invalid ESP UUID")
    elif esp != "none":
        raise CandidateHandoffError("BIOS handoff cannot claim a UEFI ESP")
    if payload["operation"] != "read-only" or payload["guestOnly"] is not True:
        raise CandidateHandoffError("Disk-writing or production operation is prohibited")
    return payload


def verify_handoff(
    payload_path: Path,
    signature_path: Path,
    trusted_key_path: Path,
    *,
    trusted_key_sha256: str,
    expected: dict[str, object],
) -> dict:
    """Verify a non-production read-only handoff against independently pinned expectations."""
    if type(trusted_key_sha256) is not str or not _SHA.fullmatch(trusted_key_sha256):
        raise CandidateHandoffError("Missing independently pinned trust-anchor digest")
    if type(expected) is not dict or not expected or any(k not in _KEYS for k in expected):
        raise CandidateHandoffError("Missing trusted context")
    if not {"runId", "distributionId", "backend", "isoSha256", "isoSizeBytes",
            "windowsDiskProofSha256", "windowsBootProofSha256",
            "targetRootUuid", "espUuid", "firmwareLayout"} <= expected.keys():
        raise CandidateHandoffError("Independent binding context is incomplete")

    pub = _read_file(trusted_key_path, 32)
    if len(pub) != 32 or hashlib.sha256(pub).hexdigest() != trusted_key_sha256:
        raise CandidateHandoffError("Lab trust-anchor mismatch")
    signature = _read_file(signature_path, 64)
    if len(signature) != 64:
        raise CandidateHandoffError("Invalid signature length")
    data = _read_file(payload_path, 4096)
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        _validate_payload(payload)
        if canonical_json(payload) != data:
            raise CandidateHandoffError("Non-canonical signed data")
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, data)
    except (UnicodeError, json.JSONDecodeError, InvalidSignature, ValueError, TypeError) as exc:
        raise CandidateHandoffError("Invalid or unauthenticated candidate handoff") from exc
    for field, value in expected.items():
        if type(payload[field]) is not type(value) or payload[field] != value:
            raise CandidateHandoffError("Trusted handoff binding mismatch: " + field)

    return {
        "signatureVerified": True,
        "contextBindingVerified": True,
        "distributionId": payload["distributionId"],
        "runId": payload["runId"],
        "operation": "read-only",
        "guestOnly": True,
        "trustedPublicKeySha256": trusted_key_sha256,
        "installationAuthorized": False,
        "windowsRecoveryVerified": False,
        "linuxBootVerified": False,
        "antiReplayDurableStateVerified": False,
    }
