#!/usr/bin/env python3
"""Sign and verify a Q4OS *read-only* GPT proposal in a disposable Actions job.

A freshly generated Ed25519 signer belongs to this lab invocation ONLY;
its public key is not a production release trust anchor. No private key
is saved. This CLI never creates partitions, formats or modifies the image.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))

from gaslux_q4os_vm_target_plan import (  # noqa: E402
    Q4osPlanRefusal,
    canonical_json,
    inspect_owned_vm_disk,
    propose_read_only_plan,
    verify_signed_plan_against_disk,
)

DOMAIN = b"GASLUX-Q4OS-VM-READONLY-TARGET-V1\n"


def _create_private_file(folder: Path, name: str, payload: bytes) -> None:
    target = folder / name
    if target.exists() or target.is_symlink():
        raise Q4osPlanRefusal("Refusing to overwrite target-plan lab evidence")
    with target.open("xb") as writer:
        writer.write(payload)
        writer.flush()
        os.fsync(writer.fileno())
    target.chmod(0o600)


def run_lab(workspace: Path, output: Path, *, run_id: str) -> dict:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise Q4osPlanRefusal("Requires explicit GitHub Actions disposable VM lab context")
    if not workspace.is_absolute() or not output.is_absolute():
        raise Q4osPlanRefusal("Require absolute Q4OS lab directories")
    if output.exists() or output.is_symlink():
        raise Q4osPlanRefusal("Refuse existing evidence destination")
    observed = inspect_owned_vm_disk(workspace, workspace / "efi-disk.img")
    nonce = secrets.token_hex(16)
    plan = propose_read_only_plan(observed, run_id=run_id, nonce=nonce)
    raw = canonical_json(plan)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = key.sign(DOMAIN + raw)
    # Independent verification performs a fresh GPT read from the same exact
    # regular file and binds the signed plan to its host inode and GPT digests.
    result = verify_signed_plan_against_disk(
        workspace,
        workspace / "efi-disk.img",
        raw,
        signature,
        public,
        trusted_public_key_sha256=hashlib.sha256(public).hexdigest(),
        independently_expected_run_id=run_id,
        independently_expected_nonce=nonce,
    )
    if result["diskWritesAuthorized"] or result["installationAuthorized"]:
        raise Q4osPlanRefusal("Read-only proposal unexpectedly allowed installation")
    output.mkdir(mode=0o700)
    if output.lstat().st_uid != os.getuid() or not stat.S_ISDIR(output.lstat().st_mode):
        raise Q4osPlanRefusal("Output directory not transaction-owned")
    _create_private_file(output, "q4os-vm-plan.json", raw)
    _create_private_file(output, "q4os-vm-plan.ed25519", signature)
    _create_private_file(output, "q4os-vm-lab-public-key.bin", public)
    _create_private_file(
        output,
        "q4os-vm-key-sha256.txt",
        (hashlib.sha256(public).hexdigest() + "\n").encode("ascii"),
    )
    _create_private_file(
        output,
        "q4os-vm-verification.json",
        (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print("REFUSED: usage: q4os_vm_target_plan_lab.py WORKSPACE EVIDENCE_DIR", file=sys.stderr)
        return 2
    run_id = "q4os-actions-" + os.environ.get("GITHUB_RUN_ID", "")
    try:
        result = run_lab(Path(sys.argv[1]), Path(sys.argv[2]), run_id=run_id)
    except (Q4osPlanRefusal, OSError, ValueError) as exc:
        print(f"GASLUX_Q4OS_VM_TARGET_REFUSED={exc}", file=sys.stderr)
        return 1
    print("GASLUX_Q4OS_VM_SIGNED_PLAN_VERIFIED=1")
    print("GASLUX_Q4OS_VM_GPT_CRC_AND_OWNERSHIP_VERIFIED=1")
    print("GASLUX_Q4OS_VM_INSTALLATION_AUTHORIZED=0")
    print("GASLUX_Q4OS_VM_WINDOWS_ESP_WRITES_AUTHORIZED=0")
    print("GASLUX_Q4OS_VM_ROLLBACK_VERIFIED=0")
    print("GASLUX_Q4OS_VM_PLAN_SHA256=" + result["evidenceSha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
