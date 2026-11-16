#!/usr/bin/env python3
"""CI-only signed handoff against actual SHA-pinned CachyOS ISO contents.

Signs a disposable mock Windows transaction with a NEW TEMPORARY Ed25519 key,
then invokes the same PR #10 signed source binding and REAL PR #11 CachyOS
Archiso inspection. No firmware/Windows/target-disk writes. Generated keys
are NOT production trust roots; the source filesystem UUID and Windows ESP
hash below are LAB FIXTURES, never verified physical identities.

This is an integration contract, NOT authorization to install on a real disk.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SOURCE = Path(__file__).resolve().parents[2] / "assets/live/cachyos-signed-grub-handoff.py"
PINNED_SHA256 = "959f6577f45e25ee9fd8c220fd221b08e4ea79412c7315c0f922dd6d86d5e33c"
PINNED_IMAGE_VERSION = "2026.08.09"
RUN_ID = "lab-real-iso-signed-20261116"
ROOT_UUID = "01234567-89ab-cdef-0123-456789abcdef"
LAB_SOURCE_UUID = "fedcba98-7654-4321-aaaa-111111111111"
WINDOWS_ESP_FIXTURE_UUID = "AB12-CD34"


def load_bridge() -> Any:
    spec = importlib.util.spec_from_file_location("gaslux_real_signed_iso_bridge", SOURCE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as file:
        while block := file.read(4 << 20):
            sha.update(block)
    return sha.hexdigest()


def run(*args: str) -> None:
    subprocess.run(list(args), capture_output=True, text=True, check=True, timeout=30)


def bind_real_signed_iso(iso: Path, mounted_iso: Path, out: Path) -> dict[str, Any]:
    # The workflow must have independently verified this hash BEFORE invoking
    # this test. Re-check here to detect a changed or confused source file.
    if iso.name != "cachyos.iso" or iso.is_symlink() or not iso.is_file():
        raise ValueError("expected plain official ISO file named cachyos.iso")
    if iso.stat().st_size < 500_000_000 or digest(iso) != PINNED_SHA256:
        raise ValueError("official CachyOS ISO has wrong size or SHA-256")
    if mounted_iso.is_symlink() or not mounted_iso.is_dir() or mounted_iso.resolve() == iso.parent.resolve():
        raise ValueError("CachyOS ISO mount directory invalid")
    # No user-supplied trust anchors or guest disk identifiers are accepted.
    # These lab fixture values deliberately do NOT authorize real storage writes.
    import secrets
    nonce = secrets.token_hex(16)
    plan = {
        "schemaVersion": 1, "firmware": "uefi", "secureBootEnabled": False,
        "runId": RUN_ID, "isoStorageFilesystem": "ext4",
        "isoStorageUuid": LAB_SOURCE_UUID, "isoRelativePath": "/cachyos.iso",
        "isoSha256": PINNED_SHA256, "isoSizeBytes": iso.stat().st_size,
    }
    doc = {
        **plan, "backend": "archiso-cachyos", "distribution": "cachyos",
        "bootNonce": nonce, "partitionStyle": "gpt", "rootUuid": ROOT_UUID,
        "targetDiskId": "QEMU-SYNTHETIC-TRANSACTION-ONLY",
        "windowsEspUuid": WINDOWS_ESP_FIXTURE_UUID,
        "windowsLoaderSha256": "0" * 64,
    }
    bridge = load_bridge()
    auth = bridge.AUTH
    auth.validate_document(doc)
    if out.exists():
        raise ValueError("refuse to replace existing evidence directory")
    out.mkdir(mode=0o700, parents=True)
    with tempfile.TemporaryDirectory(prefix="gaslux-ephemeral-test-key-") as private_dir:
        priv = Path(private_dir) / "test-only-private.pem"
        public = out / "test-only-public.pem"
        signature = out / "test-only-handoff.sig"
        envelope = out / "test-only-handoff.json"
        run("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(priv))
        run("openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(public))
        envelope.write_bytes(auth.canonical(doc))
        run("openssl", "pkeyutl", "-sign", "-inkey", str(priv), "-rawin",
            "-in", str(envelope), "-out", str(signature))
        signer_digest = digest(public)
        result = bridge.bind_archiso_entry(
            plan,
            envelope=envelope,
            signature=signature,
            public_key=public,
            trusted_signer_sha256=signer_digest,
            expected_run_id=RUN_ID,
            expected_root_uuid=ROOT_UUID,
            storage_root=iso.parent,
            iso_root=mounted_iso,
            require_mounted_iso=False,
        )
        # Tampering with the source outside signed data MUST NOT reach real ISO
        # preparation, even when that source has a valid absolute path.
        wrong = {**plan, "isoRelativePath": "/other-cachyos.iso"}
        try:
            bridge.bind_archiso_entry(
                wrong, envelope=envelope, signature=signature,
                public_key=public, trusted_signer_sha256=signer_digest,
                expected_run_id=RUN_ID, expected_root_uuid=ROOT_UUID,
                storage_root=iso.parent, iso_root=mounted_iso,
                require_mounted_iso=False,
            )
        except bridge.SignedBootError:
            pass
        else:
            raise ValueError("signature binding accepted changed ISO path")
        # Ensure a wrong independently supplied signer is never accepted.
        try:
            bridge.bind_archiso_entry(
                plan, envelope=envelope, signature=signature,
                public_key=public, trusted_signer_sha256="0" * 64,
                expected_run_id=RUN_ID, expected_root_uuid=ROOT_UUID,
                storage_root=iso.parent, iso_root=mounted_iso,
                require_mounted_iso=False,
            )
        except bridge.SignedBootError:
            pass
        else:
            raise ValueError("unexpected signer accepted")
    grub = result["grubEntry"]
    expected_kernel = "linux (gaslux_iso)/arch/boot/x86_64/vmlinuz-linux-cachyos-lts"
    expected_initrd = "initrd (gaslux_iso)/arch/boot/x86_64/initramfs-linux-cachyos-lts.img"
    if expected_kernel not in grub or expected_initrd not in grub:
        raise ValueError("real ISO did not produce the official LTS live boot pair")
    for key in ("gaslux.run=", "gaslux.nonce=", "gaslux.plan_sha256=", "gaslux.key_sha256="):
        if grub.count(key) != 1:
            raise ValueError("signed boot argument is missing or repeated: " + key)
    entry = out / "test-only-grub.cfg"
    entry.write_text(grub, encoding="utf-8")
    run("grub-script-check", str(entry))
    attestation = {
        "schemaVersion": 1,
        "realOfficialIsoSha256Verified": True,
        "realOfficialIsoLayoutVerified": True,
        "officialIsoSha256": PINNED_SHA256,
        "officialIsoVersion": PINNED_IMAGE_VERSION,
        "signedPlanVerified": result["signedSourceVerified"] is True,
        "signedGrubEntrySha256": digest(entry),
        "ephemeralTestSignerPublicKeySha256": digest(public),
        "sourceMountVerified": False,
        "windowsPhysicalDiskIdentityVerified": False,
        "windowsBootChainAuthenticated": False,
        "windowsRecoveryVerified": False,
        "installedLinuxBootVerified": False,
        "stableForPhysicalDisks": False,
        "note": "synthetic source UUID/Windows ESP; ephemeral CI key is NOT a production authority",
    }
    if not all((attestation["realOfficialIsoSha256Verified"],
                attestation["realOfficialIsoLayoutVerified"],
                attestation["signedPlanVerified"])):
        raise ValueError("integrity check was not completed")
    (out / "attestation.json").write_text(
        json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Ship individual artifact hashes for independent review; private test
    # signing key remains ONLY in tempdir and is already deleted.
    with (out / "SHA256SUMS").open("w", encoding="ascii") as listing:
        for item in sorted(out.iterdir()):
            if item.is_file() and item.name != "SHA256SUMS":
                listing.write(digest(item) + "  " + item.name + "\n")
    return attestation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--mounted-iso", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = bind_real_signed_iso(args.iso, args.mounted_iso, args.output)
    except (OSError, ValueError, subprocess.SubprocessError, TypeError, KeyError) as error:
        print(json.dumps({"ok": False, "reason": str(error)}))
        return 1
    print(json.dumps({"ok": True, **output}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
