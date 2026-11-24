#!/usr/bin/env python3
"""Proof-based Gaslux Windows+Mint lab checkpoints. No release authority.

Only verified evidence collected by this workflow is considered. Higher-risk
guest installation/boot/recovery claims require distinct independent proof and
are ALWAYS blocked here; no synthetic fixture can promote them.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

STAGES = (
    ("private_ext4_enospc", "Scaled hard quota, actual ENOSPC and restored overlay"),
    ("full_60gib_physical_quota", "Preallocated full-size quota + QCOW2 baseline/overlay"),
    ("windows_iso_exact_microsoft_hash", "Windows ISO bytes match reviewed Microsoft SHA"),
    ("installed_windows_authenticated", "Windows guest authentic GPT/ESP/NTFS/MSR/WinRE/BCD"),
    ("gaslux_windows_plan_handoff", "Validated native Gaslux v5 Windows-to-Linux plan"),
    ("gaslux_installer_real_run", "Real guest installation using Gaslux installer"),
    ("mint_installed_first_boot", "Independent installed Mint first boot"),
    ("windows_return_boot", "Same disk booted Windows again with integrity checks"),
    ("mint_update_second_boot", "Installed Mint updated and rebooted"),
    ("gaslux_uninstall_windows_integrity", "Uninstall followed by intact Windows"),
    ("failure_injection_windows_rollback", "Independently measured failure recovery"),
)


def readiness(quota: dict, scaled: dict, media: dict) -> dict:
    if any(type(v) is not dict for v in (quota, scaled, media)):
        raise ValueError("Missing or invalid evidence report")
    if (quota.get("schema") != "gaslux-private-60gib-quota-readiness-v1" or
        scaled.get("schema") != "gaslux-private-ext4-quota-fixture-v1" or
        media.get("schema") != "gaslux-windows-media-source-intake-v1"):
        raise ValueError("Evidence schema mismatch; refuse all guest admission")
    scaled_ok = all(scaled.get(k) is True for k in (
        "loop_source_exact_verified", "ext4_capacity_bound_tested",
        "qemu_io_enospc_observed", "baseline_unchanged_after_enospc",
        "overlay_recreated_and_canary_restored",
    )) and scaled.get("lab_writer_admitted") is False
    quota_ok = all(quota.get(k) is True for k in (
        "exact_private_loop_mount_verified",
        "same_size_60gib_backing_overlay_chain_verified",
        "qemu_io_actual_overlay_write_verified",
        "baseline_integrity_and_reset_verified",
    )) and (
        quota.get("status") == "PRIVATE_60GIB_QUOTA_AND_QCOW2_VERIFIED"
        and quota.get("private_quota_exact_file_bytes") == 60 * 1024**3
        and quota.get("physical_preallocation_proven_bytes", 0) >=
            60 * 1024**3 * 99 // 100
        and quota.get("guest_writer_admitted") is False
    )
    media_ok = all(media.get(k) is True for k in (
        "file_verified", "official_pinned_hash_matched",
        "iso9660_pvd_verified",
    )) and media.get("status") == "PINNED_WINDOWS_ISO_BYTES_VERIFIED"
    if (quota.get("windows_guest_booted") is not False or
        quota.get("mint_guest_installed") is not False or
        media.get("guest_writer_admitted") is not False or
        media.get("windows_guest_booted") is not False):
        raise ValueError("Unsafe guest attestation detected in preinstall evidence")
    verified = [scaled_ok, quota_ok, media_ok] + [False] * (len(STAGES) - 3)
    checkpoints = [
        {"gate": gate, "description": description,
         "state": "verified" if passed else "blocked"}
        for (gate, description), passed in zip(STAGES, verified)
    ]
    count = sum(verified)
    return {
        "schema": "gaslux-windows-mint-lab-checkpoints-v1",
        "evidence_verified_count": count,
        "evidence_required_count": len(STAGES),
        "evidence_progress_percent": count * 100 // len(STAGES),
        "next_blocking_gate": next(
            checkpoint["gate"] for checkpoint in checkpoints
            if checkpoint["state"] == "blocked"
        ),
        "checkpoints": checkpoints,
        "guest_writer_admitted": False,
        "installation_verified": False,
        "windows_return_verified": False,
        "release_eligible": False,
    }


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("--scaled", required=True, type=Path)
    cli.add_argument("--quota", required=True, type=Path)
    cli.add_argument("--media", required=True, type=Path)
    cli.add_argument("--report", required=True, type=Path)
    args = cli.parse_args()
    result = readiness(
        json.loads(args.quota.read_text()),
        json.loads(args.scaled.read_text()),
        json.loads(args.media.read_text()),
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
