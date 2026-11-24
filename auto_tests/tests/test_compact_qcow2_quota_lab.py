"""Adversarial deny-only checks for disposable ext4/QEMU quota fixture."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

LOCATION = Path(__file__).resolve().parents[1] / "tools/compact_qcow2_quota_lab.py"
SPEC = importlib.util.spec_from_file_location("gaslux_ext4_quota_fixture", LOCATION)
assert SPEC and SPEC.loader
quota = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quota)


class PhysicalQuotaFixtureTests(unittest.TestCase):
    def test_workspace_cannot_be_relative_root_device_or_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(quota.safe_parent(root), root)
            for unsafe in (Path("."), Path("/"), Path("/dev"), Path("/dev/loop0")):
                with self.assertRaises((ValueError, FileNotFoundError, PermissionError)):
                    quota.safe_parent(unsafe)
            fake = root / "alias"
            fake.symlink_to(root)
            with self.assertRaisesRegex(ValueError, "Symlinked"):
                quota.safe_parent(fake)
            nested = fake / "new"
            with self.assertRaisesRegex(ValueError, "Symlinked"):
                quota.safe_parent(nested)

    def test_qemu_writer_must_report_real_enospc(self):
        quota.assert_enospc(1, "", "write failed: No space left on device")
        quota.assert_enospc(5, "ENOSPC", "")
        for result in ((0, "", "No space left on device"),
                       (1, "", "Permission denied"),
                       (1, "", "Operation not permitted"),
                       (1, "", "qcow2: invalid refcount")):
            with self.assertRaises(ValueError):
                quota.assert_enospc(*result)

    def test_only_exact_loop_source_mounted_ext4_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "owned-volume.img"
            image.write_bytes(b"test")
            target = root / "owned-ext4"
            target.mkdir()
            loop = f"/dev/loop9: []: ({image})\n"
            valid_mount = f"/dev/loop9 ext4 {target}\n"
            with patch.object(quota, "run", side_effect=[
                    SimpleNamespace(stdout=loop, returncode=0),
                    SimpleNamespace(stdout=valid_mount, returncode=0)]):
                self.assertTrue(quota.loop_mount_verified(image, target))
            with patch.object(quota, "run", side_effect=[
                    SimpleNamespace(stdout=loop, returncode=0),
                    SimpleNamespace(stdout=f"/dev/sda ext4 {target}\n", returncode=0)]):
                self.assertFalse(quota.loop_mount_verified(image, target))
            with patch.object(quota, "run", side_effect=[
                    SimpleNamespace(stdout=loop, returncode=0),
                    SimpleNamespace(stdout=f"/dev/loop9 xfs {target}\n", returncode=0)]):
                self.assertFalse(quota.loop_mount_verified(image, target))
            with patch.object(quota, "run", side_effect=[
                    SimpleNamespace(stdout=f"/dev/loop9: []: ({root / 'foreign.img'})\n",
                                    returncode=0)]):
                self.assertFalse(quota.loop_mount_verified(image, target))
            image.unlink()
            image.symlink_to(root / "foreign.img")
            with patch.object(quota, "run") as runner:
                self.assertFalse(quota.loop_mount_verified(image, target))
                runner.assert_not_called()

    def test_no_production_or_installer_writes_are_ever_reported(self):
        source = LOCATION.read_text(encoding="utf-8")
        for gate in (
            '"real_60gib_quota_verified": False',
            '"windows_guest_booted": False',
            '"mint_guest_installed": False',
            '"dual_boot_verified": False',
            '"windows_recovery_verified": False',
            '"lab_writer_admitted": False',
            '"disk_writes_to_host_devices": 0',
        ):
            self.assertIn(gate, source)
        self.assertNotIn("qemu-system", source)
        self.assertNotIn("mount -o rw /dev", source)
        self.assertNotIn("sudo -S", source)

    def test_fail_without_private_dependencies_or_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            with patch.object(quota.shutil, "which", return_value=None), \
                 patch.object(quota.tempfile, "mkdtemp") as allocated:
                with self.assertRaisesRegex(RuntimeError, "Missing verified"):
                    quota.fixture(parent)
                allocated.assert_not_called()
            with patch.object(quota.shutil, "which", return_value="/bin/tool"), \
                 patch.object(quota.shutil, "disk_usage",
                              return_value=SimpleNamespace(free=256 * quota.MIB)), \
                 patch.object(quota.tempfile, "mkdtemp") as allocated:
                with self.assertRaisesRegex(RuntimeError, "Insufficient"):
                    quota.fixture(parent)
                allocated.assert_not_called()


if __name__ == "__main__":
    unittest.main()
