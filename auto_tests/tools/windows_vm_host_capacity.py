#!/usr/bin/env python3
"""Read-only host-storage admission for disposable Windows/QEMU test laboratories.

This checks *real filesystem free bytes*, rather than mistaking sparse QCOW2
virtual size for physical backing capacity. It NEVER admits a Windows guest:
media provenance, independently witnessed boot, snapshot and restore are
separate mandatory gates. It does not create disks, start QEMU or install OSes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Callable


HISTORICAL_MINT_AB_REQUIRED_BYTES = 867_710_795_776
HISTORICAL_ACTIONS_AVAILABLE_BYTES = 91_273_920_512
MAX_BYTES = (1 << 63) - 1


def _positive_bytes(value: int, name: str, *, allow_zero: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer byte count")
    if value < (0 if allow_zero else 1) or value > MAX_BYTES:
        raise ValueError(f"{name} is out of the supported byte range")


def _checked_add(left: int, right: int) -> int:
    _positive_bytes(left, "required_bytes")
    _positive_bytes(right, "reserve_bytes", allow_zero=True)
    if left > MAX_BYTES - right:
        raise ValueError("required_bytes + reserve_bytes exceeds signed 64-bit range")
    return left + right


def _trusted_directory(path: Path) -> Path:
    """Reject symlinks and non-directories, without touching any disk content."""
    if not path.is_absolute():
        raise ValueError("workspace must be an absolute path")
    # Path.resolve() by itself follows symlinks and would hide the alias.
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError("workspace or an ancestor is a symlink")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ValueError("workspace is missing or inaccessible") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("workspace must be a regular directory")
    return path.resolve(strict=True)


def assess_capacity(
    workspace: Path,
    required_bytes: int,
    reserve_bytes: int = 0,
    *,
    statvfs: Callable[[str], os.statvfs_result] = os.statvfs,
) -> dict:
    """Return a capacity observation; NEVER a Windows guest admission claim."""
    required_with_reserve = _checked_add(required_bytes, reserve_bytes)
    root = _trusted_directory(Path(workspace))
    try:
        observation = statvfs(str(root))
        available_blocks = observation.f_bavail
        block_bytes = observation.f_frsize
    except (OSError, AttributeError) as exc:
        raise ValueError("host filesystem free space is not measurable") from exc
    if (not isinstance(available_blocks, int) or
            not isinstance(block_bytes, int) or
            available_blocks < 0 or block_bytes <= 0 or
            available_blocks > MAX_BYTES // block_bytes):
        raise ValueError("invalid/overflowed filesystem free-space measurement")
    available_bytes = available_blocks * block_bytes
    deficit_bytes = max(0, required_with_reserve - available_bytes)
    return {
        "schema_version": 1,
        "kind": "host-storage-capacity-only",
        "workspace": str(root),
        "required_bytes": required_bytes,
        "reserve_bytes": reserve_bytes,
        "required_with_reserve_bytes": required_with_reserve,
        "measured_available_bytes": available_bytes,
        "deficit_bytes": deficit_bytes,
        "resource_status": (
            "BLOCKED_STORAGE" if deficit_bytes else "CAPACITY_ONLY_OK"
        ),
        "windows_lab_admitted": False,
        "windows_guest_boot_verified": False,
        "snapshot_restore_verified": False,
        "windows_recovery_verified": False,
        "next_gate": (
            "obtain sufficient real host backing storage" if deficit_bytes
            else "verify owned disposable VM disk, trusted Windows media, guest boot, snapshot AND restore"
        ),
        "assurance": (
            "Read-only host free-space check. A green job or sparse virtual disk "
            "does not prove a Windows guest, Windows coexistence or recovery."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--required-bytes", type=int,
                        default=HISTORICAL_MINT_AB_REQUIRED_BYTES)
    parser.add_argument("--reserve-bytes", type=int, default=0)
    parser.add_argument("--report", type=Path, default=Path("evidence/windows-vm-capacity.json"))
    args = parser.parse_args(argv)
    try:
        report = assess_capacity(args.workspace, args.required_bytes, args.reserve_bytes)
    except (ValueError, OverflowError) as exc:
        print(f"WINDOWS_VM_RESOURCE_PREFLIGHT_REJECTED: {exc}", file=sys.stderr)
        return 2
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    # BLOCKED_STORAGE is a valid negative observation, not a CI software failure.
    # There is no follow-on Windows installer job in this workflow.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
