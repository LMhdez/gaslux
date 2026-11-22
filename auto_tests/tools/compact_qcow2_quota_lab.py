#!/usr/bin/env python3
"""Prove a private ext4 loop filesystem hard-stops QCOW2 on ENOSPC.

A scaled disposable filesystem fixture, NOT admission for a real Windows guest,
an installed Mint guest, a 60-GiB target or an authorized production writer.
Never accepts a host block device or an existing fixture image path.
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

MIB = 1024 * 1024
FIXTURE_MIB = 384
_ENOSPC = re.compile(r"No space left on device|ENOSPC", re.IGNORECASE)


def safe_parent(workspace: Path) -> Path:
    if not isinstance(workspace, Path) or not workspace.is_absolute():
        raise ValueError("Private runner workspace must be absolute")
    if any(p.is_symlink() for p in (workspace, *workspace.parents)):
        raise ValueError("Symlinked workspace/ancestor forbidden")
    s = workspace.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid():
        raise ValueError("Runner workspace must be an owned directory")
    canonical = workspace.resolve(strict=True)
    if canonical == Path("/") or canonical == Path("/dev") or str(canonical).startswith("/dev/"):
        raise ValueError("Host root and devices forbidden")
    return canonical


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(MIB), b""):
            h.update(block)
    return h.hexdigest()


def run(argv: list[str], *, timeout: int = 45, allow_failure: bool = False) -> subprocess.CompletedProcess:
    response = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    if response.returncode and not allow_failure:
        raise RuntimeError("Private quota fixture command failed: " +
                           argv[0] + ": " + (response.stderr or response.stdout)[-320:])
    return response


def assert_enospc(returncode: int, stdout: str, stderr: str) -> None:
    if type(returncode) is not int or returncode == 0:
        raise ValueError("QCOW2 writer did not fail at the physical quota")
    if not _ENOSPC.search(stdout + "\n" + stderr):
        raise ValueError("QCOW2 writer failed for a reason other than ENOSPC")


def loop_mount_verified(volume: Path, mountpoint: Path) -> bool:
    """Require one exact loopback source, ext4 target and owned image."""
    if not volume.is_file() or volume.is_symlink() or not mountpoint.is_dir():
        return False
    loops = run(["sudo", "losetup", "-j", str(volume)]).stdout.splitlines()
    linked = [
        re.match(r"^(/dev/loop[0-9]+):.*\((.*)\)\s*$", line)
        for line in loops
    ]
    loop_devices = [m.group(1) for m in linked if m and m.group(2) == str(volume)]
    if len(loop_devices) != 1:
        return False
    result = run(["findmnt", "-rn", "-M", str(mountpoint), "-o", "SOURCE,FSTYPE,TARGET"],
                 allow_failure=True)
    if result.returncode:
        return False
    fields = result.stdout.strip().split()
    return fields == [loop_devices[0], "ext4", str(mountpoint)]


def fixture(workspace: Path, *, qemu_img: str = "qemu-img", qemu_io: str = "qemu-io") -> dict:
    parent = safe_parent(workspace)
    for utility in (qemu_img, qemu_io, "mkfs.ext4", "findmnt", "sudo"):
        if shutil.which(utility) is None:
            raise RuntimeError("Missing verified laboratory dependency: " + utility)
    if shutil.disk_usage(parent).free < 2 * 1024**3:
        raise RuntimeError("Insufficient independent 2-GiB host space reserve")
    work = Path(tempfile.mkdtemp(prefix="gaslux-quota-lab-", dir=parent))
    os.chmod(work, 0o700)
    volume = work / "owned-volume.img"
    mountpoint = work / "owned-ext4"
    mountpoint.mkdir(mode=0o700)
    mounted = False
    try:
        # A regular sparse FILE, never a /dev device. Bounded at 384 MiB.
        with volume.open("xb") as out:
            out.truncate(FIXTURE_MIB * MIB)
        if volume.stat().st_nlink != 1 or volume.stat().st_uid != os.getuid():
            raise RuntimeError("Unowned or aliased loopback file")
        run(["mkfs.ext4", "-F", "-m", "0", "-E",
             "lazy_itable_init=0,lazy_journal_init=0", str(volume)], timeout=60)
        run(["sudo", "-n", "mount", "-t", "ext4", "-o",
             "loop,nodev,nosuid,noexec", str(volume), str(mountpoint)], timeout=45)
        mounted = True
        if not loop_mount_verified(volume, mountpoint):
            raise RuntimeError("Private mount does not match exact loopback file")
        run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(mountpoint)])
        baseline = mountpoint / "baseline.qcow2"
        overlay = mountpoint / "trial-overlay.qcow2"
        run([qemu_img, "create", "-f", "qcow2", str(baseline), "64M"])
        run([qemu_io, "-f", "qcow2", "-c", "write -P 0xa5 0 4096", str(baseline)])
        before = digest(baseline)
        os.chmod(baseline, 0o400)
        def recreate() -> None:
            run([qemu_img, "create", "-f", "qcow2", "-F", "qcow2",
                 "-b", str(baseline), str(overlay)])
        recreate()
        info = json.loads(run([qemu_img, "info", "--backing-chain",
                               "--output=json", str(overlay)]).stdout)
        if (not isinstance(info, list) or len(info) != 2 or
            info[0].get("full-backing-filename") != str(baseline) or
            info[0].get("format") != "qcow2" or
            info[1].get("format") != "qcow2"):
            raise RuntimeError("Foreign or missing private QCOW2 backing chain")
        run([qemu_io, "-f", "qcow2", "-r", "-c", "read -P 0xa5 0 4096",
             str(overlay)])
        free = shutil.disk_usage(mountpoint).free
        reserve = 3 * MIB
        if free <= reserve + 64 * MIB:
            raise RuntimeError("Unexpectedly small ext4 quota fixture")
        filler = mountpoint / "owned-quota-filler.bin"
        with filler.open("xb") as stream:
            os.posix_fallocate(stream.fileno(), 0, free - reserve)
            os.fsync(stream.fileno())
        remaining = shutil.disk_usage(mountpoint).free
        if remaining > 8 * MIB:
            raise RuntimeError("Quota allocation did not reduce guest filesystem space")
        attempt = run([qemu_io, "-f", "qcow2", "-c",
                       "write -P 0x5a 0 16777216", str(overlay)],
                      timeout=90, allow_failure=True)
        assert_enospc(attempt.returncode, attempt.stdout, attempt.stderr)
        if digest(baseline) != before:
            raise RuntimeError("ENOSPC mutated immutable backing bytes")
        overlay.unlink()
        filler.unlink()
        recreate()
        run([qemu_io, "-f", "qcow2", "-r", "-c",
             "read -P 0xa5 0 4096", str(overlay)])
        if digest(baseline) != before:
            raise RuntimeError("Reset modified backing bytes")
        # No Windows, recovery agent or installed guest was involved.
        return {
            "schema": "gaslux-private-ext4-quota-fixture-v1",
            "fixture_capacity_bytes": FIXTURE_MIB * MIB,
            "loop_source_exact_verified": True,
            "ext4_capacity_bound_tested": True,
            "qemu_io_enospc_observed": True,
            "baseline_unchanged_after_enospc": True,
            "overlay_recreated_and_canary_restored": True,
            "baseline_sha256": before,
            "real_60gib_quota_verified": False,
            "windows_guest_booted": False,
            "mint_guest_installed": False,
            "dual_boot_verified": False,
            "windows_recovery_verified": False,
            "lab_writer_admitted": False,
            "disk_writes_to_host_devices": 0,
        }
    finally:
        # Never remove a mounted directory. Leave it for runner teardown if
        # a privileged unmount unexpectedly fails, rather than deleting files
        # through an unverified mount.
        if mounted or os.path.ismount(mountpoint):
            unmount = run(["sudo", "-n", "umount", str(mountpoint)],
                          timeout=40, allow_failure=True)
            if unmount.returncode != 0 or os.path.ismount(mountpoint):
                raise RuntimeError("Private loop mount remained active: cleanup failed closed")
        if not os.path.ismount(mountpoint):
            shutil.rmtree(work)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = fixture(args.workspace)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
