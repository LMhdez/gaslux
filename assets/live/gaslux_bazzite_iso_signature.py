#!/usr/bin/env python3
"""Read-only Bazzite live-ISO blob signature gate; never authorizes installation.

This verifies a local ISO blob against a caller-pinned digest/length and a
detached Cosign signature. The signing key digest must come from a separately
trusted source, not from the ISO or its download directory. It does NOT inspect
the native installer, prove a boot, or authenticate the Windows installation plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

from gaslux_lab_media_probe import ProbeRefusal, verify_iso_header_and_hash

_ISO_NAME = re.compile(r"bazzite(?:-[a-z0-9]+)*-(?:stable|testing|unstable)-live-amd64\.iso\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")


def _read_small_file(path: Path, maximum: int) -> bytes:
    if not path.is_absolute() or ".." in path.parts:
        raise ProbeRefusal("Trust material path must be absolute and local")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
                raise ProbeRefusal("Trust material must be a bounded regular file")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        current = path.lstat()
    except OSError as exc:
        raise ProbeRefusal("Trust material is unavailable or unsafe") from exc
    if (
        len(data) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise ProbeRefusal("Trust material changed during inspection")
    return data


def verify_bazzite_iso_blob(
    *,
    iso_path: Path,
    signature_path: Path,
    public_key_path: Path,
    trusted_key_sha256: str,
    expected_iso_sha256: str,
    expected_iso_size: int,
    firmware: str,
    partition_style: str,
    secure_boot_enabled: bool,
    cosign_binary: str | None = None,
) -> dict:
    """Fail closed on unsupported layout, missing pins or unsigned media.

    Cosign detached-key verification can work without Rekor; therefore this
    establishes signature authenticity, NOT transparency-log provenance.
    """
    if firmware != "uefi" or partition_style != "gpt":
        raise ProbeRefusal("Bazzite is UEFI/GPT-only; BIOS/MBR is forbidden")
    if type(secure_boot_enabled) is not bool or secure_boot_enabled:
        raise ProbeRefusal("Unattended Secure Boot enrollment is not supported")
    if (
        type(trusted_key_sha256) is not str
        or not _SHA.fullmatch(trusted_key_sha256)
        or type(expected_iso_sha256) is not str
        or not _SHA.fullmatch(expected_iso_sha256)
    ):
        raise ProbeRefusal("An independently pinned key and ISO SHA-256 are required")
    iso = Path(iso_path)
    signature = Path(signature_path)
    pubkey = Path(public_key_path)
    if not iso.is_absolute() or ".." in iso.parts or not _ISO_NAME.fullmatch(iso.name):
        raise ProbeRefusal("Unsupported Bazzite live ISO filename")
    if signature != iso.with_name(iso.name + ".sig"):
        raise ProbeRefusal("Signature must match the exact ISO filename")
    key_data = _read_small_file(pubkey, 16384)
    _read_small_file(signature, 16384)
    if hashlib.sha256(key_data).hexdigest() != trusted_key_sha256:
        raise ProbeRefusal("Upstream signing-key digest mismatch")

    verified = verify_iso_header_and_hash(str(iso), expected_iso_size, expected_iso_sha256)

    program = cosign_binary or shutil.which("cosign")
    if not program or not Path(program).is_absolute() or not Path(program).is_file():
        raise ProbeRefusal("Trusted Cosign verifier is missing")
    try:
        result = subprocess.run(
            [
                str(program),
                "verify-blob",
                "--insecure-ignore-tlog=true",
                "--key",
                str(pubkey),
                "--signature",
                str(signature),
                str(iso),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeRefusal("Cosign signature verification could not complete") from exc
    if result.returncode != 0:
        raise ProbeRefusal("Bazzite ISO detached signature is invalid")

    # A second complete read catches ordinary mutation/replacement during Cosign.
    again = verify_iso_header_and_hash(str(iso), expected_iso_size, expected_iso_sha256)
    if again != verified:
        raise ProbeRefusal("ISO changed between digest and signature verification")
    return {
        "distributionId": "bazzite",
        "sourceFormat": "fedora-atomic-iso",
        "isoSha256": verified["sha256"],
        "isoSizeBytes": verified["sizeBytes"],
        "upstreamKeySha256": trusted_key_sha256,
        "detachedSignatureVerified": True,
        "transparencyAttestationVerified": False,
        "installerIdentityVerified": False,
        "nativeInstallationVerified": False,
        "installationAuthorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--trusted-key-sha256", required=True)
    parser.add_argument("--expected-iso-sha256", required=True)
    parser.add_argument("--expected-iso-size", type=int, required=True)
    parser.add_argument("--firmware", required=True)
    parser.add_argument("--partition-style", required=True)
    parser.add_argument("--secure-boot-enabled", action="store_true")
    args = parser.parse_args()
    try:
        evidence = verify_bazzite_iso_blob(
            iso_path=args.iso,
            signature_path=args.signature,
            public_key_path=args.public_key,
            trusted_key_sha256=args.trusted_key_sha256,
            expected_iso_sha256=args.expected_iso_sha256,
            expected_iso_size=args.expected_iso_size,
            firmware=args.firmware,
            partition_style=args.partition_style,
            secure_boot_enabled=args.secure_boot_enabled,
        )
    except ProbeRefusal as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
