#!/usr/bin/env python3
"""Independently validate bounded evidence for the copied Mint live-SquashFS direct-kernel COW boot.

This proves only that the copied Mint live-SquashFS root reached a serial login
from the fifth partition of the disposable Windows COW. It does not prove an
installed Mint system, native GRUB/ESP dual-boot installation, updates, or rollback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import uuid
from pathlib import Path

MINT_SHA256 = "a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4"
MINT_BYTES = 3091660800
MAX_PROOF_BYTES = 16 * 1024
MAX_SERIAL_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024
MAX_FOURTH_PROOF_BYTES = 16 * 1024
MAX_FOURTH_SERIAL_BYTES = 512_000

# Exact witnesses generated inside Windows by the VM-only protected startup
# task; repeated, merged, out-of-order, or absent lines must fail closed.
WINDOWS_FOURTH_MARKERS = (
    b"GASLUX_COW_WIN10_REBOOT_LIVE=1",
    b"GASLUX_COW_WIN10_REBOOT_BUILD=19045",
    b"GASLUX_COW_WIN10_REBOOT_ESP=1",
    b"GASLUX_COW_WIN10_REBOOT_BCD=1",
    b"GASLUX_COW_WIN10_REBOOT_WINRE=1",
    b"GASLUX_COW_WIN10_REBOOT_FIFTH_GPT=1",
)
WINDOWS_BOOT_MANAGER = re.compile(
    rb'BdsDxe: starting Boot[0-9A-Fa-f]{4} "Windows Boot Manager"'
)



class MintBootEvidenceError(ValueError):
    """Evidence is missing, malformed, contradictory, or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MintBootEvidenceError(message)


def has_orderly_shutdown_witness(serial_bytes: bytes) -> bool:
    """Require a complete, line-anchored systemd or kernel poweroff witness."""
    witnesses = (
        rb"^systemd-shutdown\[\d+\]: Powering off\.$",
        rb"^\[\s*OK\s*\]\s+Finished systemd-poweroff\.service - System Power Off\.$",
        rb"^\[\s*\d+(?:\.\d+)?\s*\]\s+reboot: Power down$",
    )
    return any(re.search(pattern, serial_bytes, re.MULTILINE) for pattern in witnesses)


def read_regular(directory: Path, name: str, maximum: int) -> tuple[Path, bytes]:
    require(directory.is_dir() and not directory.is_symlink(),
            "Mint evidence directory is missing or unsafe")
    path = directory / name
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MintBootEvidenceError(f"missing evidence file: {name}") from exc
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
            f"evidence is not a regular file: {name}")
    require(0 < metadata.st_size <= maximum,
            f"evidence size is outside the allowed bound: {name}")
    return path, path.read_bytes()


def validate_fourth_windows_evidence(evidence_dir: Path, profile: str, report: dict) -> dict:
    """Require a separate, hash-bound fourth Windows boot after fifth-GPT staging.

    This is a synthetic COW audit, not evidence of a native Mint installation.
    """
    fourth_path, fourth_bytes = read_regular(
        evidence_dir, f"{profile}-fourth-post-ext4.json", MAX_FOURTH_PROOF_BYTES)
    fourth_serial, fourth_serial_bytes = read_regular(
        evidence_dir, f"{profile}-fourth-boot-serial.log", MAX_FOURTH_SERIAL_BYTES)
    fourth_sidecar, fourth_sidecar_bytes = read_regular(
        evidence_dir, f"{profile}-fourth-boot-serial.sha256", 256)
    try:
        fourth = json.loads(fourth_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MintBootEvidenceError("fourth Windows proof is invalid JSON") from exc
    require(type(fourth) is dict, "fourth Windows proof must be a JSON object")

    # Do not infer EFI/BCD/WinRE preservation from a booleans-only report:
    # bind the fourth Windows guest's complete log, sidecar and JSON proof.
    fourth_hash = hashlib.sha256(fourth_bytes).hexdigest()
    require(report.get("windowsBootAfterExt4Verified") is True
            and report.get("thirdBootBcdWinreEspVerified") is True
            and report.get("fourthPostExt4EvidenceSha256") == fourth_hash,
            "Windows result is not bound to the genuine fourth-boot BCD/WinRE proof")
    for field in (
        "windowsBootAfterExt4Verified",
        "windowsBcdWinreEspAfterExt4Verified",
        "fourthGuestCleanShutdownVerified",
        "fifthExt4UuidSurvivedWindowsBoot",
        "windowsGptUnchangedAfterExt4Boot",
        "windowsBackingUnchangedAfterExt4Boot",
        "originalWindowsUefiUnchangedAfterExt4Boot",
    ):
        require(fourth.get(field) is True,
                f"fourth Windows boot has no verified guest/ESP/BCD/WinRE witness: {field}")
    for field in ("sameDiskDualBootVerified", "rollbackProven", "releaseEligible",
                  "storageWritesAuthorized", "windowsRecoveryAfterLinuxVerified"):
        require(fourth.get(field) is False,
                f"fourth Windows boot overstates a capability: {field}")
    fourth_serial_hash = hashlib.sha256(fourth_serial_bytes).hexdigest()
    require(fourth.get("fourthGuestSerialSha256") == fourth_serial_hash,
            "fourth Windows COM1 digest disagrees with the fourth boot proof")
    require(fourth_sidecar_bytes == (
        f"{fourth_serial_hash}  {fourth_serial.name}\n".encode("ascii")),
        "fourth Windows COM1 sidecar SHA-256 mismatch")
    require(len(WINDOWS_BOOT_MANAGER.findall(fourth_serial_bytes)) == 1
            and b"UEFI QEMU DVD-ROM" not in fourth_serial_bytes
            and b"GASLUX_COW_WIN10_REBOOT_FAIL=1" not in fourth_serial_bytes,
            "fourth Windows guest booted from DVD, rebooted, or reported audit failure")
    lines = fourth_serial_bytes.splitlines()
    require(all(lines.count(line) == 1 for line in WINDOWS_FOURTH_MARKERS),
            "fourth Windows COM1 lacks unique ESP/BCD/WinRE and fifth-GPT markers")

    return {
        "fourthWindowsProofSha256": fourth_hash,
        "fourthWindowsSerialSha256": fourth_serial_hash,
        "windowsEspBcdWinreFourthBootVerified": True,
    }


def validate_mint_cow_boot_evidence(evidence_dir: Path, profile: str) -> dict:
    require(re.fullmatch(r"[a-z0-9_]{1,64}", profile) is not None,
            "invalid Windows evidence profile")

    proof_path, proof_bytes = read_regular(
        evidence_dir, "mint-same-windows-cow.json", MAX_PROOF_BYTES)
    serial_path, serial_bytes = read_regular(
        evidence_dir, "mint-same-windows-cow-serial.log", MAX_SERIAL_BYTES)
    sidecar_path, sidecar_bytes = read_regular(
        evidence_dir, "mint-same-windows-cow-serial.sha256", 256)
    report_path, report_bytes = read_regular(
        evidence_dir, f"{profile}-result.json", MAX_REPORT_BYTES)

    try:
        proof = json.loads(proof_bytes)
        report = json.loads(report_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MintBootEvidenceError("Mint proof or Windows report is invalid JSON") from exc
    require(type(proof) is dict and type(report) is dict,
            "Mint proof and Windows report must be JSON objects")

    require(proof.get("mintIsoSha256") == MINT_SHA256
            and proof.get("mintIsoBytes") == MINT_BYTES,
            "Mint proof does not identify the pinned ISO")
    root_uuid = proof.get("mintRootUuid")
    try:
        canonical_uuid = str(uuid.UUID(root_uuid))
    except (ValueError, TypeError, AttributeError) as exc:
        raise MintBootEvidenceError("Mint proof has an invalid root UUID") from exc
    require(root_uuid == canonical_uuid, "Mint root UUID is not canonical")
    kernel = proof.get("mintKernel")
    require(type(kernel) is str
            and re.fullmatch(r"vmlinuz-[A-Za-z0-9.+_-]{1,128}", kernel) is not None,
            "Mint kernel identity is missing or malformed")

    true_fields = (
        "mintSquashfsRootCopiedToWindowsCOWPartition5",
        "mintFirstBootFromSameWindowsCOWVerified",
        "windowsFourPartitionSha256Unchanged",
        "windowsBackingQcow2Unchanged",
        "windowsOriginalNvramUnchanged",
    )
    false_fields = (
        "nativeGrubDualBootVerified",
        "sameDiskDualBootVerified",
        "updatesVerified",
        "rollbackVerified",
        "releaseEligible",
    )
    for field in true_fields:
        require(proof.get(field) is True, f"Mint proof is missing positive witness: {field}")
    for field in false_fields:
        require(proof.get(field) is False, f"Mint proof overstates an untested capability: {field}")

    partition_hashes = proof.get("windowsPartitionSha256")
    require(type(partition_hashes) is list and len(partition_hashes) == 4
            and all(type(value) is str
                    and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                    for value in partition_hashes),
            "Mint proof must retain all four Windows partition SHA-256 digests")
    for field in ("windowsBackingQcow2Sha256", "windowsOriginalNvramSha256",
                  "windowsOvmfTrialVarsSha256"):
        require(type(proof.get(field)) is str
                and re.fullmatch(r"[0-9a-f]{64}", proof[field]) is not None,
                f"Mint proof is missing a valid baseline digest: {field}")

    # Reject the old misleading name rather than silently accepting evidence
    # that calls a copied live SquashFS root a complete Mint installation.
    require("mintInstalledIntoWindowsCOWPartition5" not in proof,
            "legacy installation claim is not accepted; use the SquashFS staging field")

    serial_hash = hashlib.sha256(serial_bytes).hexdigest()
    require(re.fullmatch(r"[0-9a-f]{64}", str(proof.get("mintSerialSha256", ""))) is not None
            and proof["mintSerialSha256"] == serial_hash,
            "Mint serial log SHA-256 does not match the proof")
    expected_sidecar = f"{serial_hash}  {serial_path.name}\n".encode("ascii")
    require(sidecar_bytes == expected_sidecar,
            "Mint serial SHA-256 sidecar is inconsistent")

    require(b"Linux version " in serial_bytes,
            "Mint serial evidence has no Linux kernel boot witness")
    command_line = re.compile(
        rb"(?:Kernel command line|Command line):[^\r\n]*root=UUID="
        + re.escape(root_uuid.encode("ascii"))
    )
    require(command_line.search(serial_bytes) is not None,
            "Mint serial evidence does not show the authenticated root UUID")
    require(b"GASLUXMINT login:" in serial_bytes,
            "Mint live-SquashFS root did not reach the serial login prompt")
    require(has_orderly_shutdown_witness(serial_bytes),
            "Mint guest has no orderly shutdown witness")

    proof_hash = hashlib.sha256(proof_bytes).hexdigest()
    require(report.get("mintSquashfsRootCopiedIntoWindowsCow") is True,
            "Windows report lacks the truthful Mint SquashFS staging flag")
    require(report.get("mintFirstBootFromSameWindowsCowVerified") is True,
            "Windows report lacks the Mint firstboot flag")
    require(report.get("windowsBootAfterMintRootVerified") is True
            and report.get("sameDiskBothOperatingSystemsBootVerified") is True,
            "Windows report lacks the independent Windows reboot after Mint root boot")
    require(report.get("mintCowEvidenceSha256") == proof_hash,
            "Windows report does not bind the exact Mint proof JSON")
    # A fourth-boot claim is never accepted from report booleans alone.
    # Older test profiles without a fourth boot remain explicitly unproven.
    fourth_claim_fields = (
        "windowsBootAfterExt4Verified",
        "thirdBootBcdWinreEspVerified",
        "fourthPostExt4EvidenceSha256",
    )
    fourth_files = (
        f"{profile}-fourth-post-ext4.json",
        f"{profile}-fourth-boot-serial.log",
        f"{profile}-fourth-boot-serial.sha256",
    )
    fourth_details = {}
    if any(field in report for field in fourth_claim_fields):
        fourth_details = validate_fourth_windows_evidence(
            evidence_dir, profile, report)
    else:
        require(not any((evidence_dir / name).exists() for name in fourth_files),
                "unbound fourth Windows boot evidence is not accepted")

    require(report.get("nativeGrubDualBootVerified") is False
            and report.get("sameDiskDualBootVerified") is False
            and report.get("updatesVerified") is False
            and report.get("rollbackVerified") is False,
            "Windows report overstates native dual boot, updates, or rollback")

    return {
        "proofSha256": proof_hash,
        "serialSha256": serial_hash,
        "windowsEspBcdWinreFourthBootVerified": bool(fourth_details),
        **fourth_details,
        "rootUuid": canonical_uuid,
        "kernel": kernel,
        "nativeGrubDualBootVerified": False,
        "updatesVerified": False,
        "rollbackVerified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_mint_cow_boot_evidence(args.evidence_dir, args.profile)
    except (MintBootEvidenceError, OSError) as exc:
        print(f"FAIL: Mint COW boot evidence rejected: {exc}")
        return 1
    print("PASS: independent Mint SquashFS direct-kernel boot evidence validated")
    print(json.dumps(result, sort_keys=True))
    print("LIMIT: native GRUB dual boot, updates and rollback remain unproven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
