#!/usr/bin/env python3
"""Render a boot-bound CachyOS Archiso GRUB entry from an Ed25519-signed plan.

Read-only, QEMU laboratory only. The trusted signer SHA-256 and expected
transaction/target UUID MUST originate from Windows' independently validated,
recovery-armed state. If an attacker controls those inputs, authorization
cannot be proven. Does not modify ESP/BCD/NVRAM and does not install an OS.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def _import(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTH = _import("gaslux_boot_auth", "cachyos-handoff-auth.py")
ISO = _import("gaslux_iso_handoff", "cachyos-archiso-handoff.py")
SHA = re.compile(r"[0-9a-f]{64}\Z")


class SignedBootError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise SignedBootError(reason)


def bind_archiso_entry(
    unsigned_iso_plan: dict[str, object], *,
    envelope: Path,
    signature: Path,
    public_key: Path,
    trusted_signer_sha256: str,
    expected_run_id: str,
    expected_root_uuid: str,
    storage_root: Path,
    iso_root: Path,
    inspect_runner: Any = subprocess.run,
    mount_runner: Any = subprocess.run,
    require_mounted_iso: bool = True,
) -> dict[str, object]:
    """Authenticate plan and actual ISO before rendering deterministic GRUB."""
    require(isinstance(trusted_signer_sha256, str) and
            SHA.fullmatch(trusted_signer_sha256) is not None,
            "expected signer fingerprint is missing")
    key_bytes = AUTH.load_regular(public_key, max_bytes=4096)
    require(hashlib.sha256(key_bytes).hexdigest() == trusted_signer_sha256,
            "signer is not the independently approved Windows signer")
    raw = AUTH.load_regular(envelope, max_bytes=16_384)
    plan_digest = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise SignedBootError("malformed signed JSON document") from error
    AUTH.validate_document(document)
    require(AUTH.canonical(document) == raw, "signed JSON is not canonical")
    nonce = document["bootNonce"]
    bootargs = (
        "gaslux.run=" + expected_run_id
        + " gaslux.nonce=" + nonce
        + " gaslux.plan_sha256=" + plan_digest
        + " gaslux.key_sha256=" + trusted_signer_sha256
    )
    verified = AUTH.verify(
        envelope, signature, public_key, bootargs,
        expected_run_id=expected_run_id, expected_root_uuid=expected_root_uuid,
    )
    require(verified["verified"] is True, "handoff signature not verified")
    require(isinstance(unsigned_iso_plan, dict), "invalid ISO handoff plan")
    bindings = (
        "runId", "isoSha256", "isoSizeBytes", "isoStorageUuid",
        "isoStorageFilesystem", "isoRelativePath", "firmware", "secureBootEnabled"
    )
    for field in bindings:
        require(type(document[field]) is type(unsigned_iso_plan.get(field)) and
                document[field] == unsigned_iso_plan.get(field),
                "ISO source plan differs from signed Windows handoff: " + field)
    iso = ISO.prepare(
        unsigned_iso_plan,
        storage_root=storage_root, iso_root=iso_root,
        runner=inspect_runner, mount_runner=mount_runner,
        require_mounted_iso=require_mounted_iso,
    )
    script = iso["grubEntry"]
    lines = script.splitlines(keepends=True)
    candidates = [i for i, line in enumerate(lines) if line.startswith("    linux (gaslux_iso)/")]
    require(len(candidates) == 1, "cannot bind unexpected GRUB kernel invocation")
    index = candidates[0]
    require(lines[index].endswith("\n"), "GRUB kernel line is malformed")
    lines[index] = lines[index][:-1] + " " + bootargs + "\n"
    return {
        "signedSourceVerified": True,
        "signedHandoffRunId": expected_run_id,
        "trustedSignerSha256": trusted_signer_sha256,
        "planSha256": plan_digest,
        "grubEntry": "".join(lines),
        "isoIntegrityVerified": iso["isoSha256Verified"],
        "sourceMountVerified": iso["isoMountedFromVerifiedSource"],
        "efiChainAuthenticated": False,
        "windowsRecoveryVerified": False,
        "productionInstallerReady": False,
        "writesStorage": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso-plan", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--trusted-signer-sha256", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root-uuid", required=True)
    parser.add_argument("--storage-root", type=Path, required=True)
    parser.add_argument("--iso-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        iso_plan = json.loads(args.iso_plan.read_text(encoding="utf-8"))
        result = bind_archiso_entry(
            iso_plan, envelope=args.envelope, signature=args.signature,
            public_key=args.public_key,
            trusted_signer_sha256=args.trusted_signer_sha256,
            expected_run_id=args.run_id,
            expected_root_uuid=args.root_uuid,
            storage_root=args.storage_root, iso_root=args.iso_root,
            require_mounted_iso=True,
        )
    except (AUTH.AuthError, ISO.HandoffError, SignedBootError, OSError,
            TypeError, UnicodeError, KeyError, ValueError) as error:
        print(json.dumps({"verified": False, "reason": str(error)}))
        return 1
    print(json.dumps({"verified": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
