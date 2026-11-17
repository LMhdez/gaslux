#!/usr/bin/env python3
"""Hosted CI ONLY: recover an interrupted synthetic GPT entry transaction.

Never pass an actual disk, QCOW2 containing Windows, or a block device here.
Only a newly allocated disposable raw regular file in RUNNER_TEMP is accepted.
The checkpoint covers primary/backup GPT disk windows, NOT Windows filesystems,
ESP, BCD, WinRE, power-loss durability guarantees or real system rollback.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_windows_cachyos_qcow2_gpt_readonly import create_disk_windows
from tools.windows_cachyos_qcow2_gpt_readonly import (
    SECTOR, WINDOW_BYTES, VIRTUAL_BYTES, inspect_gpt_windows,
)

LAB_PREFIX = "gaslux-durable-gpt-"
LINUX_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le
LINUX_UUID = uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-interrupted-synthetic-linux").bytes_le


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise RuntimeError(msg)


def gate() -> Path:
    env = os.environ
    require(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and env.get("GASLUX_SYNTHETIC_GPT_CONSENT") == "I_ACCEPT_SYNTHETIC_FILE_ONLY",
        "not an authorized disposable hosted CI environment",
    )
    root = Path(env["RUNNER_TEMP"])
    require(root == Path("/home/runner/work/_temp") and root.is_dir()
            and not root.is_symlink(), "unexpected runner scratch root")
    return root


def scoped(path: Path, runner: Path) -> Path:
    require(path.parent.parent == runner and path.parent.name.startswith(LAB_PREFIX)
            and not path.parent.is_symlink()
            and path.name == "synthetic-no-os.img", "non-owned synthetic disk path")
    return path


def identity(path: Path) -> dict:
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
            and not path.is_symlink() and st.st_size == VIRTUAL_BYTES,
            "synthetic image must be unique 128-GiB regular file")
    return {"device": st.st_dev, "inode": st.st_ino, "size": st.st_size}


def windows(path: Path) -> tuple[bytes, bytes]:
    with path.open("rb", buffering=0) as f:
        front = f.read(WINDOW_BYTES)
        f.seek(VIRTUAL_BYTES - WINDOW_BYTES)
        back = f.read(WINDOW_BYTES)
    require(len(front) == WINDOW_BYTES and len(back) == WINDOW_BYTES,
            "truncated GPT evidence")
    return front, back


def save_atomic(root: Path, filename: str, data: bytes) -> None:
    target = root / filename
    require(not target.exists(), "checkpoint already exists")
    fd, tmp = tempfile.mkstemp(prefix=".checkpoint-", dir=root)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
        sync_dir(root)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def sync_dir(root: Path) -> None:
    handle = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def marker_bytes(i: int) -> bytes:
    return (f"SYNTHETIC-PARTITION-{i}".encode()).ljust(SECTOR, b"\x00")


def sentinel(path: Path, parts: list[dict]) -> None:
    with path.open("rb", buffering=0) as f:
        for p in parts:
            f.seek((p["firstLba"] + 8) * SECTOR)
            require(f.read(SECTOR) == marker_bytes(p["index"]),
                    "synthetic Windows sentinel changed")


def checkpoint(path: Path) -> dict:
    front, back = windows(path)
    report = inspect_gpt_windows(front, back)
    require(report["storageWritesAuthorized"] is False
            and report["sameDiskDualBootVerified"] is False,
            "read-only GPT unexpectedly authorized writes")
    sentinel(path, report["windowsPartitions"])
    extent = report["observedPostWindowsFreeExtent"]
    first = extent["firstLba"]
    last = first + 10 * (1024**3 // SECTOR) - 1
    require(last <= extent["lastLba"], "not enough observed free extent")
    record = {
        "version": 1, "identity": identity(path),
        "frontSha256": sha(front), "backSha256": sha(back),
        "first": first, "last": last,
        "windows": report["windowsPartitions"],
        "expectedLinuxGuid": str(uuid.UUID(bytes_le=LINUX_UUID)),
        "syntheticOnly": True,
    }
    root = path.parent
    # Snapshot BOTH GPT windows BEFORE any sgdisk call. Manifest appears
    # LAST: if interrupted earlier, no writer accepts incomplete checkpoint.
    save_atomic(root, "primary.snapshot", front)
    save_atomic(root, "backup.snapshot", back)
    save_atomic(root, "checkpoint.json", json.dumps(record, sort_keys=True).encode())
    return record


def load_checkpoint(path: Path) -> tuple[dict, bytes, bytes]:
    root = path.parent
    for name in ("checkpoint.json", "primary.snapshot", "backup.snapshot"):
        p = root / name
        st = p.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                and not p.is_symlink(), "checkpoint ownership invalid")
    record = json.loads((root / "checkpoint.json").read_text())
    front = (root / "primary.snapshot").read_bytes()
    back = (root / "backup.snapshot").read_bytes()
    require(record.get("version") == 1 and record.get("syntheticOnly") is True
            and record.get("identity") == identity(path)
            and len(front) == WINDOW_BYTES and len(back) == WINDOW_BYTES
            and sha(front) == record.get("frontSha256")
            and sha(back) == record.get("backSha256"),
            "durable checkpoint integrity/disk identity mismatch")
    report = inspect_gpt_windows(front, back)
    require(report["windowsPartitions"] == record["windows"]
            and report["observedPostWindowsFreeExtent"]["firstLba"]
               == record["first"]
            and record["last"] <= report["observedPostWindowsFreeExtent"]["lastLba"],
            "checkpoint GPT geometry inconsistent")
    sentinel(path, report["windowsPartitions"])
    return record, front, back


def entry(front: bytes, index: int) -> bytes:
    return front[2*SECTOR + (index - 1)*128:2*SECTOR + index*128]


def backup_entries(back: bytes) -> bytes:
    return back[-33 * SECTOR:-SECTOR]


def verify_mutation(path: Path, record: dict, original: bytes) -> None:
    front, back = windows(path)
    require(front[2*SECTOR:2*SECTOR+4*128] == original[2*SECTOR:2*SECTOR+4*128]
            and backup_entries(back)[:4*128] == original[2*SECTOR:2*SECTOR+4*128],
            "foreign Windows GPT mutation")
    fifth = entry(front, 5)
    require(fifth[:16] == LINUX_TYPE and fifth[16:32] == LINUX_UUID
            and struct.unpack_from("<QQ", fifth, 32) ==
                (record["first"], record["last"]),
            "unexpected synthetic Linux entry")
    require(all(not any(entry(front, i)) for i in range(6, 129)),
            "foreign extra GPT partition")
    require(backup_entries(back)[4*128:5*128] == fifth,
            "primary/backup Linux GPT entry mismatch")
    sentinel(path, record["windows"])


def write_windows(path: Path, record: dict, front: bytes, back: bytes) -> None:
    # The ONLY writable target is this private synthetic regular file.
    # Check identity immediately before writing, and synchronize both windows.
    require(identity(path) == record["identity"], "target swapped before recovery")
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                and st.st_dev == record["identity"]["device"]
                and st.st_ino == record["identity"]["inode"]
                and st.st_size == VIRTUAL_BYTES, "target identity mismatch")
        require(os.pwrite(fd, back, VIRTUAL_BYTES - WINDOW_BYTES) == WINDOW_BYTES,
                "backup GPT restore short write")
        os.fsync(fd)
        require(os.pwrite(fd, front, 0) == WINDOW_BYTES,
                "primary GPT restore short write")
        os.fsync(fd)
    finally:
        os.close(fd)


def recover(path: Path) -> None:
    record, original_front, original_back = load_checkpoint(path)
    front, back = windows(path)
    if front != original_front or back != original_back:
        # Allow either fully added GPT #5 or a partial restore of only the
        # backup window (the last durable checkpoint in the failpoint test).
        if back == original_back:
            current_front = front
            require(entry(current_front, 5)[:32] ==
                    LINUX_TYPE + LINUX_UUID, "unknown pending transaction")
            require(entry(current_front, 5)[32:48] ==
                    struct.pack("<QQ", record["first"], record["last"]),
                    "unexpected transaction range")
            require(current_front[2*SECTOR:2*SECTOR+4*128] ==
                    original_front[2*SECTOR:2*SECTOR+4*128],
                    "Windows GPT records changed")
            require(all(not any(entry(front, i)) for i in range(6, 129)),
                    "foreign partition in interrupted GPT")
        else:
            verify_mutation(path, record, original_front)
        write_windows(path, record, original_front, original_back)
    restored = windows(path)
    require(restored == (original_front, original_back),
            "GPT snapshot bytes not restored exactly")
    report = inspect_gpt_windows(*restored)
    require(report["windowsPartitions"] == record["windows"]
            and report["storageWritesAuthorized"] is False,
            "recovery evidence incomplete")
    sentinel(path, record["windows"])
    print("GASLUX_SYNTHETIC_DURABLE_GPT_RECOVERY_VERIFIED=1")


def worker(op: str, path: Path) -> None:
    runner = gate()
    scoped(path, runner)
    if op == "recover":
        recover(path)
    elif op == "partial-backup":
        record, orig_front, orig_back = load_checkpoint(path)
        verify_mutation(path, record, orig_front)
        fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_dev == record["identity"]["device"]
                    and st.st_ino == record["identity"]["inode"] and
                    st.st_size == VIRTUAL_BYTES,
                    "partial recovery target identity changed")
            require(os.pwrite(fd, orig_back, VIRTUAL_BYTES - WINDOW_BYTES)
                    == WINDOW_BYTES, "partial backup GPT write")
            os.fsync(fd)
        finally:
            os.close(fd)
        os._exit(74)
    elif op == "add":
        record, original_front, _ = load_checkpoint(path)
        require(windows(path)[0] == original_front, "already modified")
        subprocess.run(
            ["sgdisk", f"--new=5:{record['first']}:{record['last']}",
             "--typecode=5:8300", "--change-name=5:GASLUX-SYNTHETIC",
             f"--partition-guid=5:{record['expectedLinuxGuid']}", str(path)],
            check=True, capture_output=True, timeout=40,
        )
        verify_mutation(path, record, original_front)
        # Deliberate abrupt process termination, *not* an actual power cut.
        os._exit(73)
    else:
        raise RuntimeError("unknown worker operation")


def command(op: str, disk: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(Path(__file__).resolve()),
                           op, str(disk)], capture_output=True, text=True, timeout=90)


def orchestrate() -> None:
    runner = gate()
    for scenario in ("recovery", "partial_recovery", "tampered_checkpoint", "wrong_inode", "foreign_entry"):
        with tempfile.TemporaryDirectory(prefix=LAB_PREFIX, dir=runner) as tmp:
            root = Path(tmp)
            disk = root / "synthetic-no-os.img"
            fd = os.open(disk, os.O_RDWR | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.ftruncate(fd, VIRTUAL_BYTES)
                front, back = create_disk_windows()
                os.pwrite(fd, front, 0)
                os.pwrite(fd, back, VIRTUAL_BYTES - WINDOW_BYTES)
                report = inspect_gpt_windows(front, back)
                for p in report["windowsPartitions"]:
                    os.pwrite(fd, marker_bytes(p["index"]),
                              (p["firstLba"] + 8) * SECTOR)
                os.fsync(fd)
            finally:
                os.close(fd)
            checkpoint(disk)
            interrupted = command("add", disk)
            require(interrupted.returncode == 73,
                    "injected interruption not observed: " + interrupted.stderr[-500:])
            if scenario == "partial_recovery":
                partial = command("partial-backup", disk)
                require(partial.returncode == 74,
                        "partial backup-only restore failpoint not observed")
                resumed = command("recover", disk)
                require(resumed.returncode == 0, resumed.stderr[-1000:])
                again = command("recover", disk)
                require(again.returncode == 0,
                        "partial recovery not idempotent")
                print("GASLUX_SYNTHETIC_PARTIAL_GPT_RESTORE_RESUMED=1")
            elif scenario == "tampered_checkpoint":
                p = root / "backup.snapshot"
                with p.open("r+b") as f:
                    f.seek(512)
                    f.write(b"CORRUPT")
                    f.flush()
                    os.fsync(f.fileno())
                before = windows(disk)
                refused = command("recover", disk)
                require(refused.returncode != 0 and windows(disk) == before,
                        "corrupt checkpoint did not fail closed")
                print("GASLUX_SYNTHETIC_CORRUPT_CHECKPOINT_REJECTED=1")
            elif scenario == "wrong_inode":
                disk.unlink()
                fd = os.open(disk, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                os.ftruncate(fd, VIRTUAL_BYTES)
                os.close(fd)
                before = windows(disk)
                refused = command("recover", disk)
                require(refused.returncode != 0 and windows(disk) == before,
                        "foreign replacement target was modified")
                print("GASLUX_SYNTHETIC_WRONG_DISK_REJECTED=1")
            elif scenario == "foreign_entry":
                subprocess.run(["sgdisk", "--new=6:0:+128M", str(disk)],
                               check=True, capture_output=True, timeout=40)
                before = windows(disk)
                refused = command("recover", disk)
                require(refused.returncode != 0 and windows(disk) == before,
                        "foreign partition rollback was not blocked")
                print("GASLUX_SYNTHETIC_FOREIGN_GPT_REJECTED=1")
            else:
                restored = command("recover", disk)
                require(restored.returncode == 0, restored.stderr[-1000:])
                repeated = command("recover", disk)
                require(repeated.returncode == 0,
                        "rollback not idempotent: " + repeated.stderr[-1000:])
                print("GASLUX_SYNTHETIC_CRASH_AND_IDEMPOTENT_RECOVERY=1")
    print("GASLUX_SYNTHETIC_CHECKPOINT_FAULT_INJECTION_PASS=1")
    print("GASLUX_REAL_WINDOWS_RECOVERY_NOT_TESTED=1")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            orchestrate()
        elif len(sys.argv) == 3 and sys.argv[1] in ("add", "recover", "partial-backup"):
            worker(sys.argv[1], Path(sys.argv[2]))
        else:
            raise RuntimeError("invalid lab arguments")
    except Exception as exc:
        print(f"GASLUX_SYNTHETIC_LAB_FAILURE: {exc}", file=sys.stderr)
        sys.exit(1)
