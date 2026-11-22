#!/usr/bin/env python3
"""Provision a private disposable 60-GiB QEMU/OVMF target for the compact lab.

REAL sparse qcow2 allocation and qemu-img identity verification. This is NOT
Windows boot, Windows installation, Mint install, dual boot or rollback proof.
No guest may receive write access to this image until separate Windows media,
ownership, snapshot/restore and actual workspace quota gates are established.
Never accepts /dev paths, a caller-controlled image path or existing outputs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


GIB = 1024 ** 3
VIRTUAL_GIB = 60
MEDIA_GIB = 4
SNAPSHOT_GIB = 8
RESERVE_GIB = 8
MAX_PHYSICAL_BUDGET_GIB = 85
MAX_BYTES = (1 << 63) - 1


def trusted_parent(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("RUNNER_TEMP path must be absolute")
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise ValueError("RUNNER_TEMP or ancestor is a symlink")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ValueError("RUNNER_TEMP is missing or inaccessible") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("RUNNER_TEMP is not a directory")
    path = path.resolve(strict=True)
    if str(path) == "/" or str(path).startswith("/dev/") or str(path) == "/dev":
        raise ValueError("Cannot create a lab below root or host device directory")
    return path


def plan(*, available_bytes: int, disk_gib: int = VIRTUAL_GIB,
         media_gib: int = MEDIA_GIB, snapshot_gib: int = SNAPSHOT_GIB,
         reserve_gib: int = RESERVE_GIB) -> dict:
    values = (disk_gib, media_gib, snapshot_gib, reserve_gib)
    if any(type(x) is not int or x < 0 or x > MAX_PHYSICAL_BUDGET_GIB
           for x in values) or not disk_gib or not reserve_gib:
        raise ValueError("Budget components must be bounded integer GiB")
    if type(available_bytes) is not int or not 0 <= available_bytes <= MAX_BYTES:
        raise ValueError("Measured free bytes invalid")
    total = sum(values)
    if total > MAX_PHYSICAL_BUDGET_GIB:
        raise ValueError("Compact lab exceeds 85-GiB planning ceiling")
    required = total * GIB
    can_allocate = available_bytes >= required
    return {
        "phase": "SPARSE_TARGET_ONLY",
        "status": "CAPACITY_ONLY_OK" if can_allocate else "BLOCKED_STORAGE",
        "virtual_disk_bytes": disk_gib * GIB,
        "disk_virtual_gib": disk_gib,
        "media_budget_gib": media_gib,
        "snapshot_budget_gib": snapshot_gib,
        "reserve_gib": reserve_gib,
        "max_physical_budget_gib": MAX_PHYSICAL_BUDGET_GIB,
        "planned_peak_bytes": required,
        "measured_available_bytes": available_bytes,
        "deficit_bytes": max(0, required - available_bytes),
        "lab_writer_admitted": False,
        "windows_guest_booted": False,
        "mint_guest_installed": False,
        "dual_boot_verified": False,
        "snapshot_restore_verified": False,
        "windows_recovery_verified": False,
        "reason": (
            "A sparse qcow2 and estimated budget do not enforce a physical "
            "write quota or prove provenance, Windows identity, installation, "
            "guest boot, snapshot restore, or rollback."
        ),
    }


def inspect_qcow2(path: Path, *, qemu_img: str = "qemu-img") -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Candidate must be a regular, non-symlink file")
    info = subprocess.run(
        [qemu_img, "info", "--output=json", str(path)],
        check=True, text=True, capture_output=True, timeout=30,
    )
    metadata = json.loads(info.stdout)
    if metadata.get("format") != "qcow2" or metadata.get("virtual-size") != VIRTUAL_GIB * GIB:
        raise ValueError("Wrong sparse qcow2 type or virtual size")
    if metadata.get("backing-filename") or metadata.get("full-backing-filename"):
        raise ValueError("Backing chain is forbidden")
    if metadata.get("encrypted") is True:
        raise ValueError("Encrypted qcow2 is not a supported lab medium")
    if metadata.get("actual-size", 0) > 128 * 1024**2:
        raise ValueError("Fresh qcow2 unexpectedly preallocated")
    return {
        "format": "qcow2",
        "virtual_size_bytes": metadata["virtual-size"],
        "initial_actual_size_bytes": metadata.get("actual-size"),
        "backing_file_present": False,
    }


def provision(parent: Path, *, qemu_img: str = "qemu-img") -> dict:
    parent = trusted_parent(parent)
    space = shutil.disk_usage(parent)
    admission = plan(available_bytes=space.free)
    if admission["status"] != "CAPACITY_ONLY_OK":
        return admission
    # A freshly exclusive private directory makes the disk path unguessable.
    # qemu-img is never directed to a caller-controlled existing file.
    work = Path(tempfile.mkdtemp(prefix="gaslux-compact-ovmf-", dir=parent))
    os.chmod(work, 0o700)
    disk = work / "target.qcow2"
    try:
        subprocess.run(
            [qemu_img, "create", "-f", "qcow2", "-o", "preallocation=off",
             str(disk), f"{VIRTUAL_GIB}G"],
            check=True, text=True, capture_output=True, timeout=35,
        )
        metadata = inspect_qcow2(disk, qemu_img=qemu_img)
        admission["disk_created"] = True
        admission["disk_path"] = str(disk)
        admission["qemu_img"] = metadata
        admission["exclusive_lab_directory"] = str(work)
        admission["writer_enabled"] = False
        return admission
    except BaseException:
        shutil.rmtree(work)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--create", action="store_true",
                        help="create a private sparse qcow2; does NOT start QEMU")
    args = parser.parse_args()
    parent = trusted_parent(args.workspace)
    if args.report.is_symlink():
        raise ValueError("Report may not be a symlink")
    if args.create:
        result = provision(parent)
    else:
        result = plan(available_bytes=shutil.disk_usage(parent).free)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0  # Blocked storage is evidence, not a failing runner.


if __name__ == "__main__":
    raise SystemExit(main())
