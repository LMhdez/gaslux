#!/usr/bin/env python3
"""Verify a signed per-installation CachyOS Archiso handoff (read-only).

This is an experimental LAB component. It does not authenticate the original
Windows firmware/BCD chain, authorize a partition write or prove rollback.
The boot-argument trust anchors MUST be inserted by an independently verified
Windows stage: if an attacker may replace the EFI loader and kernel cmdline,
they may replace all anchors and this verifier cannot restore that trust.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

KEYS = frozenset({
    "schemaVersion", "backend", "distribution", "runId", "bootNonce",
    "firmware", "partitionStyle", "secureBootEnabled", "isoSha256",
    "isoSizeBytes", "isoStorageUuid", "rootUuid", "targetDiskId",
    "windowsEspUuid", "windowsLoaderSha256",
})
ARGS = frozenset({
    "gaslux.run", "gaslux.nonce", "gaslux.plan_sha256", "gaslux.key_sha256"
})
SHA = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
RUN = re.compile(r"[A-Za-z0-9_-]{12,100}\Z")
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
FAT_UUID = re.compile(r"[0-9A-F]{4}-[0-9A-F]{4}\Z")
ISO_UUID = re.compile(r"(?:[0-9A-F]{16}|[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})\Z")
DISK_ID = re.compile(r"[A-Za-z0-9_:.+-]{12,128}\Z")


class AuthError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise AuthError(reason)


def canonical(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def parse_cmdline(cmdline: str) -> dict[str, str]:
    require(len(cmdline) < 8192, "kernel cmdline too long")
    found: dict[str, str] = {}
    for word in cmdline.split():
        key, sep, value = word.partition("=")
        if not key.startswith("gaslux."):
            continue
        require(sep == "=" and key in ARGS and key not in found and bool(value),
                "unexpected or repeated Gaslux boot argument")
        found[key] = value
    require(set(found) == ARGS, "required authenticated boot arguments missing")
    require(bool(RUN.fullmatch(found["gaslux.run"])), "invalid boot transaction")
    require(bool(NONCE.fullmatch(found["gaslux.nonce"])), "invalid boot nonce")
    for key in ("gaslux.plan_sha256", "gaslux.key_sha256"):
        require(bool(SHA.fullmatch(found[key])), "invalid authenticated boot digest")
    return found


def validate_document(doc: dict[str, Any]) -> None:
    require(isinstance(doc, dict) and set(doc) == KEYS,
            "unexpected or missing handoff document fields")
    require(type(doc["schemaVersion"]) is int and doc["schemaVersion"] == 1,
            "unsupported handoff version")
    require(doc["backend"] == "archiso-cachyos" and doc["distribution"] == "cachyos",
            "wrong distro/backend")
    require(doc["firmware"] == "uefi" and doc["partitionStyle"] == "gpt" and
            doc["secureBootEnabled"] is False,
            "unsupported firmware, partition table or Secure Boot policy")
    for key, regex in (
        ("runId", RUN), ("bootNonce", NONCE),
        ("isoSha256", SHA), ("rootUuid", UUID),
        ("isoStorageUuid", ISO_UUID), ("windowsEspUuid", FAT_UUID),
        ("windowsLoaderSha256", SHA), ("targetDiskId", DISK_ID)
    ):
        require(isinstance(doc[key], str) and regex.fullmatch(doc[key]) is not None,
                "invalid " + key)
    require(type(doc["isoSizeBytes"]) is int and
            doc["isoSizeBytes"] >= 500_000_000 and
            doc["isoSizeBytes"] <= 12_000_000_000,
            "unexpected ISO size")
    # This is a syntax check, not proof of physical-disk identity.
    require(doc["isoStorageUuid"] != doc["rootUuid"],
            "source ISO and target root must not share a filesystem UUID")


def load_regular(path: Path, *, max_bytes: int) -> bytes:
    require(path.is_file() and not path.is_symlink(), "missing or symlinked handoff artifact")
    size = path.stat().st_size
    require(0 < size <= max_bytes, "handoff artifact size invalid")
    return path.read_bytes()


def verify(
    envelope: Path,
    signature: Path,
    public_key: Path,
    cmdline: str,
    *,
    expected_run_id: str,
    expected_root_uuid: str,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    boot = parse_cmdline(cmdline)
    require(bool(RUN.fullmatch(expected_run_id)) and
            bool(UUID.fullmatch(expected_root_uuid)),
            "invalid independent expected transaction/root")
    raw = load_regular(envelope, max_bytes=16_384)
    sig = load_regular(signature, max_bytes=64)
    require(len(sig) == 64, "detached Ed25519 signature must be exactly 64 bytes")
    key = load_regular(public_key, max_bytes=4_096)
    require(hashlib.sha256(key).hexdigest() == boot["gaslux.key_sha256"],
            "signer public key fingerprint differs from trusted boot arguments")
    require(hashlib.sha256(raw).hexdigest() == boot["gaslux.plan_sha256"],
            "handoff bytes differ from trusted boot arguments")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise AuthError("malformed handoff JSON") from error
    validate_document(doc)
    require(canonical(doc) == raw, "handoff JSON is not canonical")
    require(doc["runId"] == boot["gaslux.run"] == expected_run_id,
            "installation transaction differs from boot identity")
    require(doc["bootNonce"] == boot["gaslux.nonce"],
            "nonce differs from boot identity")
    require(doc["rootUuid"] == expected_root_uuid,
            "target root UUID differs from independent transaction state")
    try:
        result = run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
             "-sigfile", str(signature), "-rawin", "-in", str(envelope)],
            capture_output=True, text=True, check=False, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AuthError("cannot verify the handoff Ed25519 signature") from error
    require(result.returncode == 0, "handoff signature verification failed")
    return {
        "verified": True,
        "runId": expected_run_id,
        "rootUuid": expected_root_uuid,
        "isoSha256": doc["isoSha256"],
        "windowsEspUuid": doc["windowsEspUuid"],
        "windowsLoaderSha256": doc["windowsLoaderSha256"],
        "signedPlanSha256": boot["gaslux.plan_sha256"],
        "signerSha256": boot["gaslux.key_sha256"],
        "writesStorage": False,
        "windowsRecoveryVerified": False,
        "independentBootChainVerified": False,
        "productionReady": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root-uuid", required=True)
    options = parser.parse_args(argv)
    try:
        # Never accept a kernel command-line override from a user argument.
        cmdline = Path("/proc/cmdline").read_text(encoding="utf-8")
        outcome = verify(
            options.envelope, options.signature, options.public_key, cmdline,
            expected_run_id=options.run_id, expected_root_uuid=options.root_uuid,
        )
    except (AuthError, OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"verified": False, "reason": str(error)}))
        return 1
    print(json.dumps(outcome, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
