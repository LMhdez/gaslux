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
import hashlib
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


def _hash_private_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _owned_regular(path: Path, parent: Path) -> None:
    metadata = path.lstat()
    if (path.parent != parent or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid() or metadata.st_nlink != 1):
        raise ValueError("unowned, aliased, or non-regular fixture image")


def _run_qemu(args: list[str]) -> str:
    result = subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=45
    )
    return result.stdout


def _assert_overlay_backing(
    overlay: Path, baseline: Path, *, qemu_img: str = "qemu-img"
) -> None:
    metadata = json.loads(_run_qemu([
        qemu_img, "info", "--output=json", "--backing-chain", str(overlay)
    ]))
    if (not isinstance(metadata, list) or len(metadata) != 2
            or metadata[0].get("format") != "qcow2"
            or metadata[1].get("format") != "qcow2"
            or metadata[0].get("full-backing-filename") != str(baseline)
            or Path(metadata[1].get("filename", "")).resolve() != baseline
            or metadata[0].get("virtual-size") != 16 * 1024**2
            or metadata[1].get("virtual-size") != 16 * 1024**2):
        raise ValueError("overlay backing identity/geometry differs from pinned baseline")


def prove_restore_fixture(
    parent: Path, ovmf_vars: Path, *,
    qemu_img: str = "qemu-img", qemu_io: str = "qemu-io"
) -> dict:
    """Prove disposable QCOW2 and firmware-vars reset, NOT Windows recovery.

    All writes are confined to a fresh private temporary directory. No QEMU
    guest, host block device, production writer, or network endpoint is used.
    """
    parent = trusted_parent(parent)
    source_vars = ovmf_vars.resolve(strict=True)
    if (not source_vars.is_file() or not 64 * 1024 <= source_vars.stat().st_size
            <= 8 * 1024**2 or str(source_vars).startswith("/dev/")):
        raise ValueError("untrusted OVMF_VARS source")
    work = Path(tempfile.mkdtemp(prefix="gaslux-compact-restore-", dir=parent))
    os.chmod(work, 0o700)
    baseline = work / "baseline.qcow2"
    overlay = work / "write-overlay.qcow2"
    firmware_base = work / "ovmf-vars-baseline.fd"
    firmware_write = work / "ovmf-vars-working.fd"
    def run_io(path: Path, command: str, *, readonly: bool = False) -> None:
        _run_qemu([qemu_io, "-f", "qcow2", *(["-r"] if readonly else []),
                   "-c", command, str(path)])
    def create_overlay(backing: Path, output: Path) -> None:
        _run_qemu([qemu_img, "create", "-f", "qcow2", "-F", "qcow2",
                   "-b", str(backing), str(output)])
        _owned_regular(output, work)
    try:
        _run_qemu([qemu_img, "create", "-f", "qcow2", str(baseline), "16M"])
        _owned_regular(baseline, work)
        run_io(baseline, "write -P 0xa5 0 4096")
        expected_baseline = _hash_private_file(baseline)
        os.chmod(baseline, 0o400)
        create_overlay(baseline, overlay)
        _assert_overlay_backing(overlay, baseline, qemu_img=qemu_img)
        run_io(overlay, "read -P 0xa5 0 4096", readonly=True)
        run_io(overlay, "write -P 0x5a 0 4096")
        run_io(overlay, "read -P 0x5a 0 4096", readonly=True)
        run_io(baseline, "read -P 0xa5 0 4096", readonly=True)
        if _hash_private_file(baseline) != expected_baseline:
            raise ValueError("overlay write modified immutable baseline")
        _owned_regular(overlay, work)
        overlay.unlink()
        create_overlay(baseline, overlay)
        _assert_overlay_backing(overlay, baseline, qemu_img=qemu_img)
        run_io(overlay, "read -P 0xa5 0 4096", readonly=True)
        if _hash_private_file(baseline) != expected_baseline:
            raise ValueError("baseline changed during overlay reset")

        shutil.copyfile(source_vars, firmware_base)
        _owned_regular(firmware_base, work)
        expected_vars = _hash_private_file(firmware_base)
        os.chmod(firmware_base, 0o400)
        shutil.copyfile(firmware_base, firmware_write)
        _owned_regular(firmware_write, work)
        with firmware_write.open("r+b") as mutable:
            first = mutable.read(1)
            if len(first) != 1:
                raise ValueError("empty firmware variables image")
            mutable.seek(0)
            mutable.write(bytes([first[0] ^ 0xff]))
            mutable.flush()
            os.fsync(mutable.fileno())
        if (_hash_private_file(firmware_write) == expected_vars
                or _hash_private_file(firmware_base) != expected_vars):
            raise ValueError("firmware modification was not isolated")
        _owned_regular(firmware_write, work)
        firmware_write.unlink()
        shutil.copyfile(firmware_base, firmware_write)
        if (_hash_private_file(firmware_write) != expected_vars
                or _hash_private_file(firmware_base) != expected_vars):
            raise ValueError("firmware variables restoration failed")

        # Real QEMU rejection of a deliberately corrupt private overlay.
        _owned_regular(overlay, work)
        overlay.unlink()
        overlay.write_bytes(b"not-a-qcow2")
        damaged = subprocess.run(
            [qemu_img, "info", "--output=json", str(overlay)],
            capture_output=True, timeout=30, check=False
        )
        if damaged.returncode == 0:
            raise ValueError("corrupt overlay was accepted")
        _owned_regular(overlay, work)
        overlay.unlink()

        # Foreign backing and symlink swaps cannot satisfy exact identity.
        foreign = work / "foreign.qcow2"
        wrong = work / "foreign-overlay.qcow2"
        _run_qemu([qemu_img, "create", "-f", "qcow2", str(foreign), "16M"])
        create_overlay(foreign, wrong)
        try:
            _assert_overlay_backing(wrong, baseline, qemu_img=qemu_img)
        except ValueError:
            foreign_backing_rejected = True
        else:
            raise ValueError("foreign backing was accepted")
        swapped = work / "swapped.qcow2"
        swapped.symlink_to(baseline)
        try:
            _owned_regular(swapped, work)
        except ValueError:
            symlink_rejected = True
        else:
            raise ValueError("symlink swap was accepted")
        incomplete = work / "interrupted.qcow2"
        incomplete.write_bytes(b"QFI\xfb" + bytes(32))
        partial = subprocess.run(
            [qemu_img, "info", "--output=json", str(incomplete)],
            capture_output=True, timeout=30, check=False
        )
        if partial.returncode == 0:
            raise ValueError("interrupted incomplete overlay was accepted")
        if plan(available_bytes=0)["status"] != "BLOCKED_STORAGE":
            raise ValueError("insufficient capacity incorrectly accepted")
        return {
            "schema": "gaslux-compact-restore-fixture-v1",
            "source_commit": os.environ.get("GITHUB_SHA"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "runner_name": os.environ.get("RUNNER_NAME"),
            "fixture_virtual_bytes": 16 * 1024**2,
            "baseline_sha256_before": expected_baseline,
            "baseline_sha256_after": _hash_private_file(baseline),
            "ovmf_vars_sha256_before": expected_vars,
            "ovmf_vars_sha256_after": _hash_private_file(firmware_write),
            "ovmf_vars_source_sha256": _hash_private_file(source_vars),
            "ovmf_vars_bytes": source_vars.stat().st_size,
            "backing_chain_verified": True,
            "overlay_changed_without_baseline_mutation": True,
            "overlay_reset_restored_initial_bytes": True,
            "ovmf_vars_reset_verified": True,
            "corrupt_overlay_rejected": True,
            "foreign_backing_rejected": foreign_backing_rejected,
            "symlink_swap_rejected": symlink_rejected,
            "interrupted_overlay_rejected": True,
            "insufficient_capacity_rejected": True,
            "quota_verified": False,
            "lab_writer_admitted": False,
            "windows_guest_booted": False,
            "mint_guest_installed": False,
            "windows_recovery_verified": False,
            "evidence_level": "SYNTHETIC_DISK_RESTORE_ONLY",
        }
    finally:
        if work.parent != parent or not work.name.startswith("gaslux-compact-restore-"):
            raise ValueError("refusing unexpected fixture cleanup target")
        shutil.rmtree(work)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--verify-restoration", action="store_true",
                        help="prove private baseline/overlay and OVMF reset only")
    parser.add_argument("--ovmf-vars", type=Path,
                        help="installed OVMF_VARS firmware template for fixture")
    parser.add_argument("--create", action="store_true",
                        help="create a private sparse qcow2; does NOT start QEMU")
    args = parser.parse_args()
    parent = trusted_parent(args.workspace)
    if args.report.is_symlink():
        raise ValueError("Report may not be a symlink")
    if args.create and args.verify_restoration:
        parser.error("--create and --verify-restoration are mutually exclusive")
    if args.verify_restoration:
        if args.ovmf_vars is None:
            parser.error("--verify-restoration requires --ovmf-vars")
        result = prove_restore_fixture(parent, args.ovmf_vars)
    elif args.create:
        result = provision(parent)
    else:
        result = plan(available_bytes=shutil.disk_usage(parent).free)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0  # Blocked storage is evidence, not a failing runner.


if __name__ == "__main__":
    raise SystemExit(main())
