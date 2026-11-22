#!/usr/bin/env python3
"""Independently validate bounded evidence for the Mint direct-kernel COW boot.

This proves only that the copied Mint SquashFS root reached a serial login and
shut down from the fifth partition of the disposable Windows COW. It does not
prove a native GRUB/ESP dual-boot installation, updates, or rollback.
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
ZORIN_SHA256 = "44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5"
ZORIN_BYTES = 3909091328
MAX_PROOF_BYTES = 16 * 1024
MAX_SERIAL_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024


class MintBootEvidenceError(ValueError):
    """Evidence is missing, malformed, contradictory, or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MintBootEvidenceError(message)


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


def validate_mint_cow_boot_evidence(evidence_dir: Path, profile: str,
                                    distribution: str = "mint") -> dict:
    require(distribution in ("mint", "zorin"), "unsupported Ubuntu-family evidence ID")
    pinned_sha = MINT_SHA256 if distribution == "mint" else ZORIN_SHA256
    pinned_bytes = MINT_BYTES if distribution == "mint" else ZORIN_BYTES
    hostname = "GASLUXMINT" if distribution == "mint" else "GASLUXZORIN"
    require(re.fullmatch(r"[a-z0-9_]{1,64}", profile) is not None,
            "invalid Windows evidence profile")

    proof_path, proof_bytes = read_regular(
        evidence_dir, f"{distribution}-same-windows-cow.json", MAX_PROOF_BYTES)
    serial_path, serial_bytes = read_regular(
        evidence_dir, f"{distribution}-same-windows-cow-serial.log", MAX_SERIAL_BYTES)
    sidecar_path, sidecar_bytes = read_regular(
        evidence_dir, f"{distribution}-same-windows-cow-serial.sha256", 256)
    report_path, report_bytes = read_regular(
        evidence_dir, f"{profile}-result.json", MAX_REPORT_BYTES)

    try:
        proof = json.loads(proof_bytes)
        report = json.loads(report_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MintBootEvidenceError("Mint proof or Windows report is invalid JSON") from exc
    require(type(proof) is dict and type(report) is dict,
            "Mint proof and Windows report must be JSON objects")

    require(proof.get(f"{distribution}IsoSha256") == pinned_sha
            and proof.get(f"{distribution}IsoBytes") == pinned_bytes,
            "Mint proof does not identify the pinned ISO")
    root_uuid = proof.get(f"{distribution}RootUuid")
    try:
        canonical_uuid = str(uuid.UUID(root_uuid))
    except (ValueError, TypeError, AttributeError) as exc:
        raise MintBootEvidenceError("Mint proof has an invalid root UUID") from exc
    require(root_uuid == canonical_uuid, "Mint root UUID is not canonical")
    kernel = proof.get(f"{distribution}Kernel")
    require(type(kernel) is str
            and re.fullmatch(r"vmlinuz-[A-Za-z0-9.+_-]{1,128}", kernel) is not None,
            "Mint kernel identity is missing or malformed")

    true_fields = (
        f"{distribution}SquashfsRootCopiedToWindowsCOWPartition5",
        f"{distribution}FirstBootFromSameWindowsCOWVerified",
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
    # This verifier is deliberately limited to direct-kernel SquashFS boots.
    # A forged self-assertion for a stronger capability must never be upgraded
    # to evidence, even when all hashes in this limited proof match.
    forbidden_positive_claims = (
        "nativeInstallerInvoked",
        "nativeInstallerVerified",
        "nativeBootloaderVerified",
        "windowsBcdVerified",
        "windowsWinreVerified",
        "windowsRecoveryVerified",
        "kernelPackageUpdateVerified",
        "bootloaderUpdateVerified",
        "postUpdateZorinBootVerified",
        "postUpdateWindowsBootVerified",
        "rollbackRestorationVerified",
        "windowsRollbackVerified",
    )
    for document_name, document in (("proof", proof), ("report", report)):
        for field in forbidden_positive_claims:
            require(document.get(field) is not True,
                    f"{document_name} overstates an unverified capability: {field}")

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
    require(f"{distribution}InstalledIntoWindowsCOWPartition5" not in proof,
            "legacy installation claim is not accepted; use the SquashFS staging field")

    serial_hash = hashlib.sha256(serial_bytes).hexdigest()
    require(re.fullmatch(r"[0-9a-f]{64}", str(proof.get(f"{distribution}SerialSha256", ""))) is not None
            and proof[f"{distribution}SerialSha256"] == serial_hash,
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
    require((hostname + " login:").encode("ascii") in serial_bytes,
            "Mint did not reach the installed-root serial login prompt")
    if distribution == "zorin":
        from zorin_shutdown_witness import (
            ZorinShutdownWitnessError, verify_zorin_shutdown_serial,
        )
        try:
            witness = verify_zorin_shutdown_serial(serial_bytes)
        except ZorinShutdownWitnessError as exc:
            raise MintBootEvidenceError(
                "Zorin has no independently verified orderly shutdown: " + str(exc)
            ) from exc
        _, qmp_bytes = read_regular(
            evidence_dir, "zorin-qmp-powerdown-request.json", MAX_PROOF_BYTES)
        _, diagnostic_bytes = read_regular(
            evidence_dir, "zorin-shutdown-diagnostics.json", MAX_PROOF_BYTES)
        try:
            qmp = json.loads(qmp_bytes)
            diagnostic = json.loads(diagnostic_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MintBootEvidenceError("Zorin QMP or shutdown diagnostic is invalid") from exc
        require(type(qmp) is dict and type(diagnostic) is dict,
                "Zorin QMP and shutdown diagnostic must be objects")
        require(qmp.get("qmpCommandAcknowledged") is True
                and qmp.get("qmpPowerdownEventObserved") is True
                and qmp.get("requestType") == "ACPI-system_powerdown"
                and qmp.get("orderlyGuestShutdownProven") is False
                and qmp.get("nativeBootloaderProven") is False,
                "Zorin QMP ACK/event evidence missing, invalid or overstated")
        require(diagnostic.get("qmpCommandAcknowledged") is True
                and diagnostic.get("qmpPowerdownEventObserved") is True
                and type(diagnostic.get("qemuExitCode")) is int
                and diagnostic["qemuExitCode"] == 0
                and diagnostic.get("linuxOrderlyShutdownWitness") is True
                and diagnostic.get("failure") is None
                and diagnostic.get("serialSha256") == serial_hash
                and diagnostic.get("vmSessionRootUuid") == root_uuid
                and diagnostic.get("shutdownWitnessLines")
                    == witness["witnessLineIndices"],
                "Zorin QEMU/serial shutdown diagnostic does not bind this boot")
        require(type(diagnostic.get("vmSessionQemuPid")) is int
                and diagnostic["vmSessionQemuPid"] > 0
                and type(diagnostic.get("vmSessionQmpSocketInode")) is int
                and diagnostic["vmSessionQmpSocketInode"] > 0
                and type(diagnostic.get("vmSessionCowPathSha256")) is str
                and re.fullmatch(
                    r"[0-9a-f]{64}", diagnostic["vmSessionCowPathSha256"]
                ) is not None
                and diagnostic.get("qmpPidFdBindingIndependentlyAuthenticated") is False
                and diagnostic.get("nativeBootloaderVerified") is False
                and diagnostic.get("sameDiskDualBootVerified") is False,
                "Zorin diagnostic session metadata missing or overclaims identity")
    else:
        require(b"systemd-shutdown" in serial_bytes or b"Powering off" in serial_bytes,
                "Mint guest has no orderly shutdown witness")

    proof_hash = hashlib.sha256(proof_bytes).hexdigest()
    require(report.get(f"{distribution}SquashfsRootCopiedIntoWindowsCow") is True,
            "Windows report lacks the truthful Mint SquashFS staging flag")
    require(report.get(f"{distribution}FirstBootFromSameWindowsCowVerified") is True,
            "Windows report lacks the Mint firstboot flag")
    require(report.get(f"windowsBootAfter{distribution.capitalize()}RootVerified") is True
            and report.get("sameDiskBothOperatingSystemsBootVerified") is True,
            "Windows report lacks the independent Windows reboot after Mint root boot")
    require(report.get(f"{distribution}CowEvidenceSha256") == proof_hash,
            "Windows report does not bind the exact Mint proof JSON")
    require(report.get("nativeGrubDualBootVerified") is False
            and report.get("sameDiskDualBootVerified") is False
            and report.get("updatesVerified") is False
            and report.get("rollbackVerified") is False,
            "Windows report overstates native dual boot, updates, or rollback")

    return {
        "proofSha256": proof_hash,
        "serialSha256": serial_hash,
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
    parser.add_argument("--distribution", choices=("mint", "zorin"), default="mint")
    args = parser.parse_args(argv)
    try:
        result = validate_mint_cow_boot_evidence(args.evidence_dir, args.profile,
                                                distribution=args.distribution)
    except (MintBootEvidenceError, OSError) as exc:
        print(f"FAIL: Mint COW boot evidence rejected: {exc}")
        return 1
    print(f"PASS: independent {args.distribution} SquashFS direct-kernel boot evidence validated")
    print(json.dumps(result, sort_keys=True))
    print("LIMIT: native GRUB dual boot, updates and rollback remain unproven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
