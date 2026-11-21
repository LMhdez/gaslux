#!/usr/bin/env python3
"""Fail-closed byte budget for standalone Mint A/B QEMU QCOW2 forensics.

The QEMU 'fully-allocated' measure is deliberately used, NOT a compressed
or sparse-image guess. No physical disk, guest boot, cleanup or storage writes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any

from windows_cachyos_qcow2_gpt_readonly import VIRTUAL_BYTES

GiB = 1024 ** 3
EARLY_IMAGES = 6  # Windows backing, staged overlay, 3 standalone, one restore temp
LATE_IMAGES = 4   # 3 standalone plus 1 full-size atomic restore temporary
EARLY_RESERVE = 40 * GiB  # pinned ISO, Windows setup media, Mint unpack/chroot & runtime
LATE_RESERVE = 8 * GiB    # non-image guest/scratch + growing runner services

class CapacityError(RuntimeError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise CapacityError(reason)


def qemu_fully_allocated_bytes(virtual_bytes: int = VIRTUAL_BYTES) -> int:
    require(type(virtual_bytes) is int and virtual_bytes == VIRTUAL_BYTES,
            "unsupported A/B virtual capacity")
    p = subprocess.run(
        ["qemu-img", "measure", "--output=json", "-O", "qcow2",
         "--size", str(virtual_bytes)],
        capture_output=True, text=True, check=True, timeout=60,
    )
    report = json.loads(p.stdout)
    full = report.get("fully-allocated")
    required = report.get("required")
    require(type(full) is int and full >= virtual_bytes
            and type(required) is int and 0 <= required <= full,
            "unavailable or incomplete QEMU fully-allocated size estimate")
    return full


def _regular_stats(path: Path, expected_parent: Path) -> dict[str, int]:
    require(path.parent == expected_parent and not path.is_symlink(),
            "foreign source image path")
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
            and s.st_nlink == 1 and s.st_size > 0,
            "unsafe image identity for space measurement")
    return {"apparentBytes": s.st_size, "allocatedBytes": s.st_blocks * 512}


def measure_capacity(*, directory: Path, phase: str,
                     full_allocated_bytes: int,
                     base: Path | None = None, overlay: Path | None = None,
                     quota_remaining_bytes: int | None = None) -> dict[str, Any]:
    require(phase in ("early", "late"), "unsupported A/B capacity phase")
    require(type(full_allocated_bytes) is int
            and full_allocated_bytes >= VIRTUAL_BYTES,
            "unproved fully-allocated QCOW2 bound")
    require(directory.is_dir() and not directory.is_symlink(),
            "missing private capacity destination")
    fs = os.statvfs(directory)
    require(fs.f_frsize > 0 and fs.f_blocks > 0,
            "unknown target volume capacity")
    available = fs.f_bavail * fs.f_frsize  # user-writable, not root-reserved bytes
    filesystem_free = fs.f_bfree * fs.f_frsize
    require(type(quota_remaining_bytes) in (int, type(None))
            and (quota_remaining_bytes is None or quota_remaining_bytes >= 0),
            "invalid user quota measurement")
    effective = available if quota_remaining_bytes is None else min(
        available, quota_remaining_bytes)
    is_late = phase == "late"
    observed = {}
    if is_late:
        require(base is not None and overlay is not None,
                "missing completed source images for late capacity audit")
        require(base.parent == overlay.parent.parent
                or base.parent == overlay.parent,
                "unexpected A/B source workspace relationship")
        require(base.stat().st_dev == overlay.stat().st_dev
                == directory.stat().st_dev,
                "A/B source and destination are on different filesystems")
        observed = {
            "windowsBacking": _regular_stats(base, base.parent),
            "preparedMintOverlay": _regular_stats(overlay, overlay.parent),
        }
    # This is a gross upper-bound reservation for FULL image expansion, not
    # a promise that qcow2 -c will compress to a previous measured size.
    images = LATE_IMAGES if is_late else EARLY_IMAGES
    reserve = LATE_RESERVE if is_late else EARLY_RESERVE
    required = images * full_allocated_bytes + reserve
    ok = effective >= required
    return {
        "schema": "gaslux-mint-ab-capacity-v1",
        "phase": phase, "result": "PASS" if ok else "BLOCKED_CAPACITY",
        "virtualDiskBytes": VIRTUAL_BYTES,
        "qemuFullyAllocatedImageBytes": full_allocated_bytes,
        "worstCaseRemainingStandaloneImagesAndRestores": images,
        "nonImageReserveBytes": reserve,
        "minimumFreeBytesRequired": required,
        "filesystemTotalBytes": fs.f_blocks * fs.f_frsize,
        "filesystemFreeBytes": filesystem_free,
        "processAvailableBytes": available,
        "quotaRemainingBytes": quota_remaining_bytes,
        "quotaStatus": "measured" if quota_remaining_bytes is not None else "not-observable",
        "effectiveAvailableBytes": effective,
        "capacityShortfallBytes": max(0, required-effective),
        "existingOwnedImageStats": observed,
        "destinationVolumeMatchesSources": True if is_late else None,
        "compressionAssumedForCapacity": False,
        "checkpointReadyForReview": False,
        "windowsGuestBootsAuthorized": False,
        "productionInstallAuthorized": False,
        "releaseEligible": False,
    }


def evidence(path: Path, data: dict) -> None:
    require(path.parent.is_dir() and not path.parent.is_symlink()
            and path.name in ("mint-ab-capacity-early.json",
                              "mint-ab-capacity-late.json")
            and not path.exists() and not path.is_symlink()
            and path.parent.stat().st_uid == os.getuid(),
            "unsafe capacity evidence destination")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as out:
        out.write((json.dumps(data, indent=2, sort_keys=True)+"\n").encode())
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def early_cli() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--early", action="store_true", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("RUNNER_TEMP") == str(args.root)
            and args.root == Path("/home/runner/work/_temp")
            and os.environ.get("GITHUB_REF")
                == "refs/heads/test/mint-cow-ab-checkpoint-20261120"
            and args.evidence.is_dir()
            and args.evidence.resolve() == args.evidence,
            "early A/B capacity proof restricted to isolated hosted CI")
    report = measure_capacity(directory=args.root, phase="early",
                              full_allocated_bytes=qemu_fully_allocated_bytes())
    report["githubRunId"] = os.environ.get("GITHUB_RUN_ID")
    report["sourceCommit"] = os.environ.get("GITHUB_SHA")
    require(type(report["githubRunId"]) is str
            and report["githubRunId"].isdigit()
            and type(report["sourceCommit"]) is str
            and len(report["sourceCommit"]) == 40,
            "missing same-run GitHub capacity identity")
    evidence(args.evidence/"mint-ab-capacity-early.json", report)
    print("GASLUX_MINT_AB_CAPACITY_EARLY_JSON=" + json.dumps(report, sort_keys=True),
          flush=True)
    require(report["result"] == "PASS",
            "insufficient runner space BEFORE Windows install; refer to bounded byte diagnostic")


if __name__ == "__main__":
    early_cli()
