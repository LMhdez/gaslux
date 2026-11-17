#!/usr/bin/env python3
"""Synthetic GPT add/remove probe: NEVER a Windows or production disk writer.

Runs only on a freshly created sparse REGULAR FILE owned by a hosted
GitHub Actions job. No Linux filesystem, ESP write, Windows VM or real disk.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import uuid

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from test_windows_cachyos_qcow2_gpt_readonly import create_disk_windows
from tools.windows_cachyos_qcow2_gpt_readonly import (
    SECTOR, VIRTUAL_BYTES, WINDOW_BYTES, TYPES, inspect_gpt_windows,
)

LINUX_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
PART_GUID = str(uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-disposable-linux-partition"))


def check(ok: bool, reason: str) -> None:
    if not ok:
        raise RuntimeError(reason)


def run(*argv: str) -> None:
    subprocess.run(argv, check=True, capture_output=True, timeout=40)


def sections(disk: Path) -> tuple[bytes, bytes]:
    with disk.open("rb", buffering=0) as src:
        front = src.read(WINDOW_BYTES)
        src.seek(VIRTUAL_BYTES - WINDOW_BYTES)
        back = src.read(WINDOW_BYTES)
    check(len(front) == WINDOW_BYTES and len(back) == WINDOW_BYTES,
          "truncated GPT audit windows")
    return front, back


def owned_file(disk: Path, root: Path, device: int, inode: int) -> None:
    check(disk.parent == root and not disk.is_symlink(),
          "file escaped disposable directory")
    st = disk.lstat()
    check(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
          and st.st_dev == device and st.st_ino == inode
          and st.st_size == VIRTUAL_BYTES, "synthetic disk identity changed")


def partition_records(front: bytes) -> bytes:
    return front[2 * SECTOR:34 * SECTOR]


def backup_partition_records(back: bytes) -> bytes:
    return back[-33 * SECTOR:-SECTOR]


def markers(disk: Path, parts: list[dict]) -> dict[int, bytes]:
    markers = {}
    with disk.open("rb", buffering=0) as src:
        for p in parts:
            lba = p["firstLba"] + 8
            src.seek(lba * SECTOR)
            markers[lba] = src.read(SECTOR)
    return markers


def verify_markers(disk: Path, saved: dict[int, bytes]) -> None:
    with disk.open("rb", buffering=0) as src:
        for lba, expected in saved.items():
            src.seek(lba * SECTOR)
            check(src.read(SECTOR) == expected,
                  "synthetic Windows partition payload changed")


def one_synthetic_trial() -> None:
    check(os.environ.get("GITHUB_ACTIONS") == "true"
          and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
          and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
          and os.environ.get("GASLUX_SYNTHETIC_GPT_CONSENT")
              == "I_ACCEPT_SYNTHETIC_FILE_ONLY",
          "hosted-runner synthetic consent required")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    check(runner.is_dir() and not runner.is_symlink()
          and runner == Path("/home/runner/work/_temp"),
          "unexpected Actions scratch root")
    with tempfile.TemporaryDirectory(prefix="gaslux-gpt-synthetic-", dir=runner) as tmp:
        root = Path(tmp)
        disk = root / "new-synthetic-no-os.img"
        descriptor = os.open(disk, os.O_RDWR | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.ftruncate(descriptor, VIRTUAL_BYTES)
            st = os.fstat(descriptor)
            check(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                  "new synthetic image not unique regular file")
            original_front, original_back = create_disk_windows()
            os.pwrite(descriptor, original_front, 0)
            os.pwrite(descriptor, original_back, VIRTUAL_BYTES - WINDOW_BYTES)
            original = inspect_gpt_windows(original_front, original_back)
            # Fictional payload sentinels are not Windows filesystem contents.
            for p in original["windowsPartitions"]:
                lba = p["firstLba"] + 8
                os.pwrite(descriptor,
                          (f"SYNTHETIC_WINDOWS_PARTITION_{p['index']}".encode()
                           .ljust(SECTOR, b"\x00")), lba * SECTOR)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        owned_file(disk, root, st.st_dev, st.st_ino)
        before = sections(disk)
        baseline = inspect_gpt_windows(*before)
        check(baseline["storageWritesAuthorized"] is False,
              "candidate unexpectedly authorized writes")
        saved = markers(disk, baseline["windowsPartitions"])
        extent = baseline["observedPostWindowsFreeExtent"]
        start = extent["firstLba"]
        end = start + 10 * (1024 ** 3 // SECTOR) - 1
        check(end <= extent["lastLba"] and start > baseline["windowsPartitions"][-1]["lastLba"],
              "synthetic Linux entry would cross Windows or GPT bounds")
        # The only positive mutation is an extra GPT RECORD on this owned,
        # newly created raw file. There are no mkfs, mounts or boot writes.
        run("sgdisk", f"--new=5:{start}:{end}",
            "--typecode=5:8300", "--change-name=5:GASLUX-SYNTHETIC",
            f"--partition-guid=5:{PART_GUID}", str(disk))
        owned_file(disk, root, st.st_dev, st.st_ino)
        run("sgdisk", "--verify", str(disk))
        added_front, added_back = sections(disk)
        first_four = partition_records(before[0])[:4 * 128]
        check(partition_records(added_front)[:4 * 128] == first_four
              and backup_partition_records(added_back)[:4 * 128] == first_four,
              "Windows primary or backup GPT entries changed when adding Linux")
        entry5 = partition_records(added_front)[4 * 128:5 * 128]
        check(uuid.UUID(bytes_le=entry5[:16]) == uuid.UUID(LINUX_TYPE),
              "new synthetic Linux entry has wrong GPT type")
        check(uuid.UUID(bytes_le=entry5[16:32]) == uuid.UUID(PART_GUID),
              "new synthetic Linux entry has wrong identity")
        check(struct.unpack_from("<QQ", entry5, 32) == (start, end),
              "new synthetic entry outside observed free extent")
        verify_markers(disk, saved)
        print("GASLUX_SYNTHETIC_LINUX_GPT_ENTRY_ADDED=1")

        # Exercise rollback through the GPT utility, not a reported marker.
        run("sgdisk", "--delete=5", str(disk))
        owned_file(disk, root, st.st_dev, st.st_ino)
        run("sgdisk", "--verify", str(disk))
        rolled_front, rolled_back = sections(disk)
        after = inspect_gpt_windows(rolled_front, rolled_back)
        check(after["windowsPartitions"] == baseline["windowsPartitions"],
              "Windows GPT geometry/identity not recovered")
        check(after["observedPostWindowsFreeExtent"]
              == baseline["observedPostWindowsFreeExtent"],
              "aligned available extent not restored")
        check(after["storageWritesAuthorized"] is False
              and after["releaseEligible"] is False
              and after["sameDiskDualBootVerified"] is False,
              "synthetic test accidentally authorized release or disk writes")
        verify_markers(disk, saved)
        # Compare all GPT partition records (not merely labels/UUIDs).
        check(partition_records(rolled_front) == partition_records(before[0])
              and backup_partition_records(rolled_back) ==
                  backup_partition_records(before[1]),
              "entire GPT record arrays not restored")
        print("GASLUX_SYNTHETIC_GPT_WINDOWS_PARTITIONS_PRESERVED=1")
        print("GASLUX_SYNTHETIC_GPT_ENTRY_ROLLBACK_VERIFIED=1")
        print("GASLUX_SYNTHETIC_NO_WINDOWS_OR_LINUX_OS_BOOT=1")


if __name__ == "__main__":
    one_synthetic_trial()
