#!/usr/bin/env python3
"""Real libguestfs tar-in smoke on a private synthetic Windows-shaped COW.

This creates neither real Windows nor a production Mint installation. Never
attach a physical disk; all writes are inside a newly created runner-owned file.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile

from windows_cachyos_overlay_ext4_only import VIRTUAL_BYTES, WINDOW_BYTES, format_only_fifth
from windows_mint_overlay_root import _import_tar_into_exact_owned_root

CONSENT = "I_ACCEPT_SYNTHETIC_RAW_FILE_FIFTH_EXT4_ONLY"


def main() -> None:
    assert (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
        and os.environ.get("GASLUX_SYNTHETIC_EXT4_CONSENT") == CONSENT
        and os.geteuid() != 0
    ), "synthetic root import requires explicit hosted-only test consent"

    import guestfs

    with tempfile.TemporaryDirectory(
        prefix="gaslux-mint-tar-guestfs-", dir=os.environ["RUNNER_TEMP"]
    ) as temporary:
        directory = Path(temporary)
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        backing = directory / "synthetic-no-windows.raw"
        overlay = directory / "synthetic-owned-cow.qcow2"
        tarball = directory / "mint-root.tar.gz"
        root = directory / "synthetic-root"
        root.mkdir(mode=0o700)

        fd = os.open(backing, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            os.ftruncate(fd, VIRTUAL_BYTES)
        finally:
            os.close(fd)
        subprocess.run([
            "sgdisk", "-n", "1:2048:+100M", "-t", "1:ef00",
            "-n", "2:0:+16M", "-t", "2:0c01",
            "-n", "3:0:+256M", "-t", "3:0700",
            "-n", "4:0:+128M", "-t", "4:2700",
            "-n", "5:0:+24G", "-t", "5:8300", str(backing),
        ], check=True, capture_output=True, timeout=60)
        subprocess.run([
            "qemu-img", "create", "-f", "qcow2", "-F", "raw",
            "-b", str(backing), str(overlay),
        ], check=True, capture_output=True, timeout=60)
        backing.chmod(0o400)
        backing_identity = backing.stat()
        assert stat.S_IMODE(backing_identity.st_mode) == 0o400
        with backing.open("rb") as stream:
            original_backing_hash = hashlib.sha256(stream.read(4 * 1024 * 1024)).hexdigest()
            stream.seek(VIRTUAL_BYTES - 4 * 1024 * 1024)
            original_tail_hash = hashlib.sha256(stream.read(4 * 1024 * 1024)).hexdigest()
        info = json.loads(subprocess.run(
            ["qemu-img", "info", "-f", "qcow2", "--output=json", str(overlay)],
            check=True, capture_output=True, text=True, timeout=60,
        ).stdout)
        assert info.get("backing-filename") == str(backing)
        assert info.get("backing-filename-format") == "raw"
        assert info.get("format") == "qcow2" and info.get("virtual-size") == VIRTUAL_BYTES
        # qcow2 is never attached alongside its backing as a writable QEMU disk.
        g = guestfs.GuestFS(python_return_dict=True)
        try:
            g.add_drive_opts(str(overlay), format="qcow2", readonly=0)
            g.launch()
            disk = g.list_devices()[0]
            assert g.blockdev_getsize64(disk) == VIRTUAL_BYTES
            front = g.pread_device(disk, WINDOW_BYTES, 0)
            back = g.pread_device(disk, WINDOW_BYTES, VIRTUAL_BYTES - WINDOW_BYTES)
            proof = format_only_fifth(g, front, back)
            assert proof["allFourWindowsPartitionSha256Unchanged"] is True
            part = disk + "5"
            uuid = g.vfs_uuid(part)
            expected_hashes = [g.checksum_device("sha256", disk + str(i)) for i in range(1, 5)]
        finally:
            try:
                g.shutdown()
            finally:
                g.close()

        # Uncompressible test payload forces a real libguestfs tar transfer.
        (root / "gaslux-smoke.txt").write_bytes(os.urandom(2 * 1024 * 1024))
        with tarfile.open(tarball, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            archive.add(root / "gaslux-smoke.txt", arcname="gaslux-smoke.txt")
        tarball.chmod(0o600)
        assert tarball.stat().st_size > 1024 * 1024
        _import_tar_into_exact_owned_root(overlay, tarball, uuid, expected_hashes)

        check = guestfs.GuestFS(python_return_dict=True)
        try:
            check.add_drive_opts(str(overlay), format="qcow2", readonly=1)
            check.launch()
            disk = check.list_devices()[0]
            check.mount_ro(disk + "5", "/")
            assert check.is_file("/gaslux-smoke.txt"), "root payload absent"
            assert check.filesize("/gaslux-smoke.txt") == 2 * 1024 * 1024
            assert [check.checksum_device("sha256", disk + str(i)) for i in range(1, 5)] == expected_hashes
            assert check.vfs_uuid(disk + "5") == uuid
        finally:
            try:
                check.shutdown()
            finally:
                check.close()
        # No guestfs appliance remains open. This is a COW-discard test, not a
        # recovery of in-place guest writes or an installed Windows VM.
        overlay_identity = overlay.lstat()
        assert stat.S_ISREG(overlay_identity.st_mode) and not overlay.is_symlink()
        assert overlay_identity.st_uid == os.getuid() and overlay_identity.st_nlink == 1
        assert overlay.parent.resolve() == directory.resolve()
        overlay.unlink()
        assert not overlay.exists() and not overlay.is_symlink()

        restored = guestfs.GuestFS(python_return_dict=True)
        try:
            restored.add_drive_opts(str(backing), format="raw", readonly=1)
            restored.launch()
            disks = restored.list_devices()
            assert len(disks) == 1 and restored.blockdev_getsize64(disks[0]) == VIRTUAL_BYTES
            disk = disks[0]
            assert restored.part_get_parttype(disk) == "gpt"
            assert restored.list_partitions() == [disk + str(i) for i in range(1, 6)]
            assert [restored.checksum_device("sha256", disk + str(i))
                    for i in range(1, 5)] == expected_hashes
            assert restored.vfs_type(disk + "5") != "ext4", (
                "discarded COW leaked the Linux filesystem into backing"
            )
            assert restored.pread_device(disk, WINDOW_BYTES, 0) == front
            assert restored.pread_device(
                disk, WINDOW_BYTES, VIRTUAL_BYTES - WINDOW_BYTES
            ) == back
        finally:
            try:
                restored.shutdown()
            finally:
                restored.close()

        after_identity = backing.stat()
        assert (after_identity.st_ino, after_identity.st_size,
                after_identity.st_mtime_ns, after_identity.st_ctime_ns) == (
                    backing_identity.st_ino, backing_identity.st_size,
                    backing_identity.st_mtime_ns, backing_identity.st_ctime_ns
                ), "backing file identity changed after COW discard"
        with backing.open("rb") as stream:
            assert hashlib.sha256(stream.read(4 * 1024 * 1024)).hexdigest() == original_backing_hash
            stream.seek(VIRTUAL_BYTES - 4 * 1024 * 1024)
            assert hashlib.sha256(stream.read(4 * 1024 * 1024)).hexdigest() == original_tail_hash
        print("PASS: synthetic COW root imported into fifth ext4 and discarded")
        print("PASS: original GPT, four Windows-shaped partitions and backing unchanged")
        print("NOT TESTED: real Windows boot, Mint boot, updates or in-place rollback")


if __name__ == "__main__":
    main()
