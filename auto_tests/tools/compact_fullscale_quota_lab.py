#!/usr/bin/env python3
"""Full-size 60-GiB private physical quota and QCOW2/OVMF fixture.

Not a Windows image, VM installation, recovery or production writer admission.
The *file* is preallocated before mounting ext4 so a sparse container can
never be confused with an independently reserved host capacity limit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from compact_qcow2_quota_lab import (
    MIB, safe_parent, digest, loop_mount_verified, run
)

GIB = 1024 ** 3
POOL_BYTES = 60 * GIB
HOST_RESERVE = 16 * GIB


def capacity_only(parent: Path, *, bytes_needed: int = POOL_BYTES,
                  reserve: int = HOST_RESERVE) -> dict:
    parent = safe_parent(parent)
    if type(bytes_needed) is not int or bytes_needed != POOL_BYTES:
        raise ValueError("Only exact 60-GiB disposable quota admitted")
    if type(reserve) is not int or reserve < HOST_RESERVE:
        raise ValueError("Required 16-GiB host reserve cannot be bypassed")
    available = shutil.disk_usage(parent).free
    return {
        "schema": "gaslux-private-60gib-quota-readiness-v1",
        "status": "CAPACITY_PREFLIGHT_OK" if available >= bytes_needed + reserve else "BLOCKED_STORAGE",
        "measured_host_available_bytes": available,
        "preallocate_bytes": bytes_needed,
        "required_post_preallocation_reserve_bytes": reserve,
        "deficit_bytes": max(0, bytes_needed + reserve - available),
        "real_windows_media_verified": False,
        "windows_guest_booted": False,
        "mint_guest_installed": False,
        "dual_boot_verified": False,
        "guest_writer_admitted": False,
        "windows_recovery_verified": False,
    }


def full_fixture(workspace: Path, *, preflight_only: bool = False) -> dict:
    parent = safe_parent(workspace)
    ready = capacity_only(parent)
    if preflight_only or ready["status"] != "CAPACITY_PREFLIGHT_OK":
        return ready
    if not hasattr(os, "posix_fallocate"):
        raise RuntimeError("Required real filesystem preallocation unavailable")
    for tool in ("mkfs.ext4", "sudo", "qemu-img", "qemu-io", "findmnt"):
        if shutil.which(tool) is None:
            raise RuntimeError("Missing physical capacity fixture dependency: " + tool)
    work = Path(tempfile.mkdtemp(prefix="gaslux-full-quota-", dir=parent))
    os.chmod(work, 0o700)
    volume = work / "fully-reserved-ext4.img"
    mountpoint = work / "private-ext4"
    mountpoint.mkdir(mode=0o700)
    mounted = False
    try:
        with volume.open("xb") as stream:
            os.posix_fallocate(stream.fileno(), 0, POOL_BYTES)
            os.fsync(stream.fileno())
        st = volume.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                or st.st_nlink != 1 or st.st_size != POOL_BYTES
                or st.st_blocks * 512 < POOL_BYTES * 99 // 100):
            raise RuntimeError("60-GiB backing image was not independently preallocated")
        after_reservation = shutil.disk_usage(parent).free
        if after_reservation < HOST_RESERVE:
            raise RuntimeError("Hard quota allocation exhausted independent host reserve")
        run(["mkfs.ext4", "-F", "-m", "0", "-E",
             "lazy_itable_init=0,lazy_journal_init=0", str(volume)], timeout=120)
        run(["sudo", "-n", "mount", "-t", "ext4", "-o",
             "loop,nodev,nosuid,noexec", str(volume), str(mountpoint)], timeout=65)
        mounted = True
        if not loop_mount_verified(volume, mountpoint):
            raise RuntimeError("Full-size ext4 quota not mounted from owned loop file")
        run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(mountpoint)])
        pool = shutil.disk_usage(mountpoint)
        if not 57 * GIB <= pool.total <= POOL_BYTES:
            raise RuntimeError("Unexpected private filesystem total capacity")
        before_free = pool.free

        baseline = mountpoint / "synthetic-60gib-baseline.qcow2"
        overlay = mountpoint / "trial-overlay.qcow2"
        run(["qemu-img", "create", "-f", "qcow2", str(baseline), "60G"], timeout=60)
        run(["qemu-io", "-f", "qcow2", "-c",
             "write -P 0xa5 0 4096", str(baseline)], timeout=60)
        pinned = digest(baseline)
        os.chmod(baseline, 0o400)

        def overlay_create() -> None:
            run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                 "-b", str(baseline), str(overlay)], timeout=60)
            chain = json.loads(run(
                ["qemu-img", "info", "--backing-chain", "--output=json", str(overlay)],
                timeout=60,
            ).stdout)
            if (not isinstance(chain, list) or len(chain) != 2 or
                chain[0].get("format") != "qcow2" or
                chain[0].get("virtual-size") != POOL_BYTES or
                chain[0].get("full-backing-filename") != str(baseline) or
                chain[1].get("format") != "qcow2" or
                chain[1].get("virtual-size") != POOL_BYTES):
                raise RuntimeError("60-GiB overlay does not match synthetic backing")
        overlay_create()
        run(["qemu-io", "-f", "qcow2", "-r", "-c",
             "read -P 0xa5 0 4096", str(overlay)])
        run(["qemu-io", "-f", "qcow2", "-c",
             "write -P 0x5a 8388608 1048576", str(overlay)])
        run(["qemu-io", "-f", "qcow2", "-r", "-c",
             "read -P 0x5a 8388608 1048576", str(overlay)])
        if digest(baseline) != pinned:
            raise RuntimeError("Writable synthetic overlay changed backing image")
        overlay.unlink()
        overlay_create()
        run(["qemu-io", "-f", "qcow2", "-r", "-c",
             "read -P 0xa5 0 4096", str(overlay)])
        if digest(baseline) != pinned:
            raise RuntimeError("Synthetic 60-GiB baseline changed after reset")
        if shutil.disk_usage(mountpoint).free > before_free:
            raise RuntimeError("Untrusted private quota accounting")
        return {
            **ready,
            "status": "PRIVATE_60GIB_QUOTA_AND_QCOW2_VERIFIED",
            "private_quota_exact_file_bytes": st.st_size,
            "physical_preallocation_proven_bytes": st.st_blocks * 512,
            "private_ext4_capacity_bytes": pool.total,
            "host_free_after_reservation_bytes": after_reservation,
            "exact_private_loop_mount_verified": True,
            "same_size_60gib_backing_overlay_chain_verified": True,
            "qemu_io_actual_overlay_write_verified": True,
            "baseline_integrity_and_reset_verified": True,
            "synthetic_baseline_sha256": pinned,
            "enospc_60gib_exhaustion_demonstrated": False,
            # 384-MiB separate real ENOSPC fixture proves error semantics.
            # No Windows identity or actual guest write authority is implied.
        }
    finally:
        if mounted or os.path.ismount(mountpoint):
            unmount = run(["sudo", "-n", "umount", str(mountpoint)],
                          timeout=90, allow_failure=True)
            if unmount.returncode != 0 or os.path.ismount(mountpoint):
                raise RuntimeError("Failed to detach private loop mount: refuse unsafe cleanup")
        if not os.path.ismount(mountpoint):
            shutil.rmtree(work)


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("--workspace", type=Path, required=True)
    cli.add_argument("--report", type=Path, required=True)
    cli.add_argument("--preflight-only", action="store_true")
    args = cli.parse_args()
    result = full_fixture(args.workspace, preflight_only=args.preflight_only)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    if result["status"] == "BLOCKED_STORAGE":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
