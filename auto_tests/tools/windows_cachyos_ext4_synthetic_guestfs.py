#!/usr/bin/env python3
"""Hosted-only real libguestfs call validation on a newly created sparse raw file.

No Windows, ISO, QCOW2, physical device, mount of host partitions or boot.
This is NOT an installer or authorization to operate on user disks.
"""
from __future__ import annotations
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from windows_cachyos_overlay_ext4_only import format_only_fifth, VIRTUAL_BYTES, WINDOW_BYTES

CONSENT = "I_ACCEPT_SYNTHETIC_RAW_FILE_FIFTH_EXT4_ONLY"

def run() -> None:
    assert (os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
            and os.environ.get("GASLUX_SYNTHETIC_EXT4_CONSENT") == CONSENT
            and os.geteuid() != 0), "not authorized for isolated hosted synthetic test"
    with tempfile.TemporaryDirectory(
        prefix="gaslux-synthetic-fifth-ext4-",
        dir="/home/runner/work/_temp",
    ) as tmp:
        root = Path(tmp)
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        img = root / "entirely-synthetic-empty-gpt.raw"
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW
        fd = os.open(img, flags, 0o600)
        try:
            os.ftruncate(fd, VIRTUAL_BYTES)
            assert os.fstat(fd).st_size == VIRTUAL_BYTES
        finally:
            os.close(fd)
        assert img.is_file() and not img.is_symlink() and img.stat().st_nlink == 1
        # sgdisk operates ONLY on the explicitly created synthetic regular
        # file. No --clear, NBD host mapping or /dev paths.
        options = [
            "sgdisk", "-n", "1:2048:+100M", "-t", "1:ef00",
            "-n", "2:0:+16M", "-t", "2:0c01",
            # Compact synthetic Windows-style volumes to test the API without
            # hashing 72 GiB twice. Real Windows CI still hashes ALL actual
            # Windows partition bytes at their unchanged production geometry.
            "-n", "3:0:+256M", "-t", "3:0700",
            "-n", "4:0:+128M", "-t", "4:2700",
            "-n", "5:0:+24G", "-t", "5:8300",
            str(img),
        ]
        subprocess.run(options, check=True, timeout=45,
                       capture_output=True, text=True)
        subprocess.run(["sgdisk", "-v", str(img)], check=True,
                       capture_output=True, text=True, timeout=45)
        import guestfs
        guest = guestfs.GuestFS(python_return_dict=True)
        try:
            guest.add_drive_opts(str(img), format="raw", readonly=0)
            guest.launch()
            devices = guest.list_devices()
            assert len(devices) == 1 and guest.blockdev_getsize64(devices[0]) == VIRTUAL_BYTES
            front = guest.pread_device(devices[0], WINDOW_BYTES, 0)
            back = guest.pread_device(devices[0], WINDOW_BYTES, VIRTUAL_BYTES-WINDOW_BYTES)
            proof = format_only_fifth(guest, front, back)
            assert proof["filesystemType"] == "ext4"
            assert proof["allFourWindowsPartitionSha256Unchanged"] is True
            assert proof["gptMirrorsByteIdenticalAfterExt4"] is True
            assert len(proof["windowsFourPartitionSha256"]) == 4
            print("GASLUX_SYNTHETIC_GUESTFS_FIFTH_EXT4_ONLY_PASS=1", flush=True)
            # Explicit negative rerun: a formatted foreign partition can never
            # be silently reinitialized even in this disposable test.
            try:
                format_only_fifth(guest, front, back)
            except ValueError as exc:
                assert "foreign or already-formatted" in str(exc), str(exc)
            else:
                raise AssertionError("second ext4 format attempt was accepted")
            print("GASLUX_SYNTHETIC_GUESTFS_REFORMAT_REJECTED=1", flush=True)
        finally:
            try:
                guest.shutdown()
            finally:
                guest.close()
        # TemporaryDirectory removes the 128 GiB sparse synthetic raw and all
        # private guestfs/sgdisk metadata from this hosted runner.
    print("NO_Windows_Linux_install_dualboot_recovery_or_release_claim", flush=True)

if __name__ == "__main__":
    run()
