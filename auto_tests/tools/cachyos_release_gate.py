#!/usr/bin/env python3
"""Fail-closed evidence gate for a future physical-disk CachyOS installer.

Checks an externally reviewer-signed, artifact-backed Windows 10/11 Proxmox
campaign. An attested test report is NECESSARY but not SUFFICIENT for release:
the installer and Windows-to-Archiso transaction must also be implemented,
reviewed and approved. No disk writes are performed by this tool.

The reviewer public key is pinned to .github/trust/cachyos-lab-reviewer.pem.
Without that key, a signed report and ALL required cases, the CLI fails.
Never generate or accept a trusted key automatically in this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
PINNED_REVIEWER_KEY = REPO / ".github/trust/cachyos-lab-reviewer.pem"
CASES = {
    "nominal-windows-first": {
        "windows_boot", "linux_boot", "windows_return", "bcd_healthy",
        "winre_healthy", "esp_loader_unchanged",
    },
    "nominal-linux-first": {
        "windows_boot", "linux_boot", "linux_return", "bcd_healthy",
        "winre_healthy", "esp_loader_unchanged",
    },
    "kernel-update-crossboot": {
        "kernel_update_boot", "linux_boot", "windows_boot", "bcd_healthy",
    },
    "failure-network-rollback": {
        "fault_injected", "original_gpt_restored", "bcd_restored",
        "winre_healthy", "windows_boot", "efi_entries_restored",
    },
    "failure-packages-rollback": {
        "fault_injected", "original_gpt_restored", "bcd_restored",
        "winre_healthy", "windows_boot", "efi_entries_restored",
    },
    "failure-efi-write-rollback": {
        "fault_injected", "original_gpt_restored", "bcd_restored",
        "winre_healthy", "windows_boot", "efi_entries_restored",
    },
    "failure-powercut-rollback": {
        "fault_injected", "original_gpt_restored", "bcd_restored",
        "winre_healthy", "windows_boot", "efi_entries_restored",
    },
    "postinstall-rollback": {
        "original_gpt_restored", "bcd_restored", "winre_healthy",
        "windows_boot", "efi_entries_restored",
    },
    "secureboot-refusal": {
        "secure_boot_enabled", "no_disk_mutation", "windows_boot",
    },
    "bitlocker-refusal": {
        "bitlocker_enabled", "no_disk_mutation", "windows_boot",
    },
}
PROFILES = {"windows10-uefi", "windows11-uefi"}
_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REL = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,99}$")


class GateError(ValueError):
    """A required piece of external laboratory evidence is missing/invalid."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise GateError(message)


def canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def verify_reviewer_signature(report: Path, signature: Path, public_key: Path, *, run=subprocess.run) -> dict[str, Any]:
    require(public_key.is_file() and not public_key.is_symlink(),
            "trusted reviewer key has not been installed in the repository")
    require(report.is_file() and not report.is_symlink() and
            signature.is_file() and not signature.is_symlink(),
            "report and detached Ed25519 signature must be regular files")
    require(report.stat().st_size < 2_000_000 and signature.stat().st_size == 64,
            "report or Ed25519 signature size is invalid")
    raw = report.read_bytes()
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise GateError("invalid report JSON") from error
    require(isinstance(data, dict) and canonical_json(data) == raw,
            "report is not canonical JSON")
    try:
        outcome = run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
             "-sigfile", str(signature), "-rawin", "-in", str(report)],
            capture_output=True, text=True, check=False, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GateError("OpenSSL reviewer verification is unavailable") from error
    require(outcome.returncode == 0, "independent reviewer signature rejected")
    return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def check_report(data: dict[str, Any], *, artifacts: Path, expected_commit: str) -> dict[str, Any]:
    require(set(data) == {"schemaVersion", "repository", "sourceCommit", "installerSha256", "labs"},
            "report has unexpected or missing fields")
    require(type(data["schemaVersion"]) is int and data["schemaVersion"] == 1,
            "invalid evidence schema")
    require(data["repository"] == "LMhdez/gaslux", "wrong repository in evidence report")
    commit = data["sourceCommit"]
    require(isinstance(commit, str) and _COMMIT.fullmatch(commit) is not None and
            commit == expected_commit, "evidence does not match exact source commit")
    require(isinstance(data["installerSha256"], str) and
            _SHA.fullmatch(data["installerSha256"]) is not None,
            "missing installer binary SHA-256")
    labs = data["labs"]
    require(isinstance(labs, list) and len(labs) == len(PROFILES),
            "Windows 10 and Windows 11 UEFI guest evidence are both required")
    require(artifacts.is_dir() and not artifacts.is_symlink(),
            "evidence artifacts directory is missing")
    root = artifacts.resolve()
    completed = set()
    seen_vms: set[int] = set()
    used_artifacts: set[str] = set()
    for lab in labs:
        require(isinstance(lab, dict) and set(lab) == {"profile", "vmId", "snapshot", "cases"},
                "invalid VM profile record")
        profile = lab["profile"]
        require(profile in PROFILES and profile not in completed, "duplicated/unsupported Windows profile")
        completed.add(profile)
        vm = lab["vmId"]
        require(type(vm) is int and vm > 0 and vm not in seen_vms,
                "invalid or duplicated lab VM ID")
        seen_vms.add(vm)
        require(isinstance(lab["snapshot"], str) and _ID.fullmatch(lab["snapshot"]) is not None,
                "missing trusted pre-install VM snapshot identifier")
        cases = lab["cases"]
        require(isinstance(cases, dict) and set(cases) == set(CASES),
                "missing or unexpected destructive scenario; complete matrix required")
        for case, required_checks in CASES.items():
            row = cases[case]
            require(isinstance(row, dict) and set(row) == {"status", "runId", "checks", "artifacts"},
                    "invalid case evidence structure")
            require(row["status"] == "passed", f"{profile}/{case} did not pass")
            require(isinstance(row["runId"], str) and _ID.fullmatch(row["runId"]) is not None,
                    "invalid lab run identifier")
            checks = row["checks"]
            require(isinstance(checks, dict) and set(checks) == required_checks and
                    all(value is True for value in checks.values()),
                    f"{profile}/{case}: missing independently checked disk/boot/rollback evidence")
            files = row["artifacts"]
            require(isinstance(files, list) and len(files) >= 2,
                    f"{profile}/{case}: at least two independent artifacts required")
            for item in files:
                require(isinstance(item, dict) and set(item) == {"path", "sha256"},
                        "invalid evidence artifact")
                rel, sha = item["path"], item["sha256"]
                require(isinstance(rel, str) and _REL.fullmatch(rel) is not None and
                        ".." not in rel.split("/") and rel not in used_artifacts,
                        "duplicate/unsafe artifact path")
                used_artifacts.add(rel)
                require(isinstance(sha, str) and _SHA.fullmatch(sha) is not None,
                        "invalid artifact hash")
                destination = root / rel
                require(destination.is_file() and not destination.is_symlink() and
                        destination.resolve().is_relative_to(root),
                        f"missing or linked evidence file: {rel}")
                require(0 < destination.stat().st_size <= 200_000_000,
                        f"empty/excessively large evidence artifact: {rel}")
                require(sha256_file(destination) == sha,
                        f"evidence artifact hash mismatch: {rel}")
    return {
        "verifiedLaboratoryProfiles": sorted(completed),
        "verifiedScenarios": len(PROFILES) * len(CASES),
        "validatedArtifactFiles": len(used_artifacts),
        "sourceCommit": commit,
        "reviewerSignatureValid": True,
        # A reviewer signature is NOT proof of integration of the installer.
        "realDiskInstallerReleased": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    options = parser.parse_args(argv)
    try:
        require(isinstance(options.source_commit, str) and
                _COMMIT.fullmatch(options.source_commit) is not None,
                "source commit must be a complete SHA-1 Git object identifier")
        data = verify_reviewer_signature(
            options.report, options.signature, PINNED_REVIEWER_KEY
        )
        result = check_report(data, artifacts=options.artifacts,
                              expected_commit=options.source_commit)
    except (GateError, OSError, TypeError, KeyError) as error:
        print(json.dumps({"ready": False, "reason": str(error)}))
        return 1
    print(json.dumps({"ready": False, "labEvidenceVerified": True,
                      **result, "reason": "Linux installer integration, signed catalog, independent Windows recovery review and real-hardware qualification are still required."}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
