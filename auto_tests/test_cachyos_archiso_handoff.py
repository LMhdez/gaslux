"""Disk-free regression tests for the CachyOS Archiso GRUB loopback handoff."""
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "assets/live/cachyos-archiso-handoff.py"
spec = importlib.util.spec_from_file_location("gaslux_handoff", SOURCE)
assert spec and spec.loader
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)

ISO_BYTES = b"minimal synthetic ISO fixture, not a bootable release"
RUN_ID = "handoff-fixture-2026"
GOOD = {
    "schemaVersion": 1,
    "firmware": "uefi",
    "secureBootEnabled": False,
    "runId": RUN_ID,
    "isoStorageFilesystem": "ntfs",
    "isoStorageUuid": "A4F10E38BCD29475",
    "isoRelativePath": "/Gaslux/cachyos.iso",
    "isoSha256": hashlib.sha256(ISO_BYTES).hexdigest(),
    "isoSizeBytes": len(ISO_BYTES),
}


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.disk = root / "disk"
        self.iso = root / "iso"
        self.disk.mkdir()
        self.iso.mkdir()
        self.source = self.disk / "Gaslux/cachyos.iso"
        self.source.parent.mkdir()
        self.source.write_bytes(ISO_BYTES)
        for path in (
            "arch/x86_64/airootfs.sfs",
            "arch/boot/x86_64/vmlinuz-linux-cachyos",
            "arch/boot/x86_64/initramfs-linux-cachyos.img",
        ):
            target = self.iso / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"fixture")
        self.plan = dict(GOOD)
        self.inspect = patch.object(
            handoff._PREFLIGHT_MODULE,
            "inspect_cachyos_iso_root",
            return_value={"distribution": "cachyos", "libertix_installation_supported": False},
        )
        self.inspect.start()
        self.addCleanup(self.inspect.stop)

    def call(self, **changes):
        plan = {**self.plan, **changes}
        return handoff.prepare(plan, storage_root=self.disk, iso_root=self.iso)

    def test_generates_archiso_kernel_and_initrd_loopback(self):
        result = self.call()
        grub = result["grubEntry"]
        self.assertIn("search --no-floppy --fs-uuid --set=gaslux_iso_dev A4F10E38BCD29475", grub)
        self.assertIn("loopback gaslux_iso ($gaslux_iso_dev)$gaslux_iso_path", grub)
        self.assertIn("img_dev=UUID=A4F10E38BCD29475 img_loop=/Gaslux/cachyos.iso", grub)
        self.assertIn("linux (gaslux_iso)/arch/boot/x86_64/vmlinuz-linux-cachyos", grub)
        self.assertIn("initrd (gaslux_iso)/arch/boot/x86_64/initramfs-linux-cachyos.img", grub)
        self.assertFalse(result["productionInstallSupported"])
        self.assertFalse(result["isoMountedFromVerifiedSource"])
        self.assertFalse(result["windowsRecoveryVerified"])

    def test_no_writes(self):
        before = {
            str(p): hashlib.sha256(p.read_bytes()).digest()
            for root in (self.iso, self.disk) for p in root.rglob("*") if p.is_file()
        }
        self.call()
        after = {
            str(p): hashlib.sha256(p.read_bytes()).digest()
            for root in (self.iso, self.disk) for p in root.rglob("*") if p.is_file()
        }
        self.assertEqual(before, after)

    def test_iso_checksum_mismatch(self):
        with self.assertRaisesRegex(handoff.HandoffError, "SHA-256 mismatch"):
            self.call(isoSha256="0" * 64)

    def test_iso_size_mismatch(self):
        with self.assertRaisesRegex(handoff.HandoffError, "file size"):
            self.call(isoSizeBytes=len(ISO_BYTES) + 1)

    def test_missing_kernel(self):
        (self.iso / "arch/boot/x86_64/vmlinuz-linux-cachyos").unlink()
        with self.assertRaisesRegex(handoff.HandoffError, "file missing"):
            self.call()

    def test_missing_initrd(self):
        (self.iso / "arch/boot/x86_64/initramfs-linux-cachyos.img").unlink()
        with self.assertRaisesRegex(handoff.HandoffError, "file missing"):
            self.call()

    def test_missing_rootfs(self):
        (self.iso / "arch/x86_64/airootfs.sfs").unlink()
        with self.assertRaisesRegex(handoff.HandoffError, "file missing"):
            self.call()

    def test_unsafe_relative_iso_path(self):
        with self.assertRaisesRegex(handoff.HandoffError, "ISO path"):
            self.call(isoRelativePath="/Gaslux/../windows.iso")

    def test_iso_path_with_grub_injection(self):
        with self.assertRaisesRegex(handoff.HandoffError, "ISO path"):
            self.call(isoRelativePath="/Gaslux/x.iso';reboot;echo '")

    def test_symlink_to_iso_rejected(self):
        old = self.source.read_bytes()
        self.source.unlink()
        real = self.disk / "actual.iso"
        real.write_bytes(old)
        self.source.symlink_to(real)
        with self.assertRaisesRegex(handoff.HandoffError, "file missing/symlink"):
            self.call()

    def test_fat32_rejected_for_large_iso_reliability(self):
        with self.assertRaisesRegex(handoff.HandoffError, "unsupported ISO storage filesystem"):
            self.call(isoStorageFilesystem="vfat")

    def test_unsupported_bios(self):
        with self.assertRaisesRegex(handoff.HandoffError, "UEFI"):
            self.call(firmware="bios")

    def test_secure_boot_enabled(self):
        with self.assertRaisesRegex(handoff.HandoffError, "Secure Boot"):
            self.call(secureBootEnabled=True)

    def test_unknown_metadata_rejected(self):
        with self.assertRaisesRegex(handoff.HandoffError, "unexpected"):
            self.call(command="rm -rf /")

    def test_invalid_disk_uuid(self):
        with self.assertRaisesRegex(handoff.HandoffError, "UUID"):
            self.call(isoStorageUuid="../../etc/passwd")

    def test_exact_loop_mount_source_verification(self):
        mock_loop = "/dev/loop2"
        expected = {
            ("findmnt", "-rn", "-M", str(self.disk), "-o", "SOURCE,FSTYPE"): "/dev/vda3 ntfs3",
            ("blkid", "-s", "UUID", "-o", "value", "/dev/vda3"): GOOD["isoStorageUuid"],
            ("findmnt", "-rn", "-M", str(self.iso), "-o", "SOURCE,FSTYPE,OPTIONS"): "/dev/loop2 iso9660 ro,nosuid",
            ("losetup", "--noheadings", "--output", "BACK-FILE", mock_loop): str(self.source.resolve()),
        }
        def cmd(argv, **kwargs):
            value = expected.get(tuple(argv))
            return subprocess.CompletedProcess(argv, 0 if value else 1, (value or "") + "\n", "")
        result = handoff.prepare(
            self.plan, storage_root=self.disk, iso_root=self.iso,
            require_mounted_iso=True, mount_runner=cmd
        )
        self.assertTrue(result["isoMountedFromVerifiedSource"])

    def test_loop_mount_from_different_iso_is_rejected(self):
        def cmd(argv, **kwargs):
            if argv[0] == "findmnt" and str(self.disk) in argv:
                output = "/dev/vda3 ntfs3"
            elif argv[0] == "findmnt":
                output = "/dev/loop2 iso9660 ro"
            elif argv[0] == "blkid":
                output = GOOD["isoStorageUuid"]
            else:
                output = "/mnt/another.iso"
            return subprocess.CompletedProcess(argv, 0, output + "\n", "")
        with self.assertRaisesRegex(handoff.HandoffError, "different"):
            handoff.prepare(self.plan, storage_root=self.disk, iso_root=self.iso,
                            require_mounted_iso=True, mount_runner=cmd)

    def test_writable_iso_mount_is_rejected(self):
        def cmd(argv, **kwargs):
            if argv[0] == "findmnt" and str(self.disk) in argv:
                output = "/dev/vda3 ntfs3"
            elif argv[0] == "findmnt":
                output = "/dev/loop2 iso9660 rw,nosuid"
            else:
                output = GOOD["isoStorageUuid"]
            return subprocess.CompletedProcess(argv, 0, output + "\n", "")
        with self.assertRaisesRegex(handoff.HandoffError, "read-only"):
            handoff.prepare(self.plan, storage_root=self.disk, iso_root=self.iso,
                            require_mounted_iso=True, mount_runner=cmd)

    def test_mismatched_disk_uuid_rejected_before_loopback(self):
        def cmd(argv, **kwargs):
            output = "/dev/vda3 ntfs3" if argv[0] == "findmnt" else "FFFFFFFFFFFFFFFF"
            return subprocess.CompletedProcess(argv, 0, output + "\n", "")
        with self.assertRaisesRegex(handoff.HandoffError, "UUID mismatch"):
            handoff.prepare(self.plan, storage_root=self.disk, iso_root=self.iso,
                            require_mounted_iso=True, mount_runner=cmd)

    def test_ext4_iso_storage(self):
        result = self.call(
            isoStorageFilesystem="ext4",
            isoStorageUuid="01234567-89ab-cdef-0123-456789abcdef",
        )
        self.assertIn("insmod ext2", result["grubEntry"])
        self.assertNotIn("insmod ntfs", result["grubEntry"])


if __name__ == "__main__":
    unittest.main()
