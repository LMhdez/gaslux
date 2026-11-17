"""Fail-closed contracts for the Mint/Windows disposable COW harness."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import windows_mint_overlay_root as mint


class FakeGuest:
    def __init__(self, devices=None, parts=None, root_size=24 * 1024**3,
                 fs="ext4", uuid="12345678-1234-4234-8234-123456789abc"):
        self.devices = devices or ["/dev/sda"]
        self.parts = parts or [f"/dev/sda{i}" for i in range(1, 6)]
        self.root_size = root_size
        self.fs = fs
        self.uuid = uuid
        self.closed = False

    def add_drive_opts(self, *args, **kwargs): pass
    def launch(self): pass
    def list_devices(self): return self.devices
    def blockdev_getsize64(self, path):
        return self.root_size if path == "/dev/sda5" else 128 * 1024**3
    def list_partitions(self): return self.parts
    def vfs_type(self, path): return self.fs
    def vfs_uuid(self, path): return self.uuid
    def checksum_device(self, algorithm, path):
        return ("a" if path.endswith("1") else "b") * 64
    def shutdown(self): pass
    def close(self): self.closed = True


class MintOverlayContracts(unittest.TestCase):
    def test_consent_is_required_before_touching_paths_or_guestfs(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                GuestFS=lambda **kwargs: self.fail("guestfs must not be opened"))}):
                with self.assertRaisesRegex(mint.MintOverlayError, "dedicated hosted-runner"):
                    mint.install_mint_root_and_boot(
                        overlay=Path("/not-opened/overlay.qcow2"),
                        base=Path("/not-opened/base.qcow2"),
                        nvram=Path("/not-opened/vars.fd"),
                        workspace=Path("/not-opened"),
                        ext4_proof={}, iso=Path("/not-opened/mint.iso"),
                        evidence=Path("/not-opened/evidence"))

    def test_exactly_one_disk_and_five_partitions_are_required(self):
        fake = FakeGuest(devices=["/dev/sda", "/dev/sdb"])
        with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                GuestFS=lambda **kwargs: fake)}):
            with self.assertRaisesRegex(mint.MintOverlayError, "ambiguous"):
                mint._guest_disk_audit(Path("/tmp/unused"))

    def test_guestmount_allows_runner_access_with_kernel_permissions(self):
        command = mint.guestmount_command(
            Path("/tmp/windows-cow.qcow2"), Path("/tmp/mint-target"))
        self.assertEqual(command[:2], ["sudo", "guestmount"])
        options = [command[index + 1] for index, value in enumerate(command[:-1])
                   if value == "-o"]
        self.assertEqual(options, ["allow_other", "default_permissions"])
        self.assertEqual(command[-1], "/tmp/mint-target")

    def test_guestmount_workflow_enables_fuse_allow_other(self):
        root = Path(mint.__file__).resolve().parents[2]
        workflow = root / ".github/workflows/windows-cachyos-post-ext4-fourth-boot.yml"
        content = workflow.read_text(encoding="utf-8")
        self.assertIn("sudo modprobe fuse", content)
        self.assertIn("user_allow_other", content)

    def test_wrong_root_extent_is_rejected(self):
        fake = FakeGuest(root_size=23 * 1024**3)
        with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                GuestFS=lambda **kwargs: fake)}):
            with self.assertRaisesRegex(mint.MintOverlayError, "24-GiB"):
                mint._guest_disk_audit(Path("/tmp/unused"))

    def test_root_must_be_ext4_and_expected_uuid(self):
        fake = FakeGuest(fs="xfs")
        with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                GuestFS=lambda **kwargs: fake)}):
            with self.assertRaisesRegex(mint.MintOverlayError, "not ext4"):
                mint._guest_disk_audit(Path("/tmp/unused"))

    def test_rejects_reordered_or_additional_partitions(self):
        fake = FakeGuest(parts=["/dev/sda1", "/dev/sda2", "/dev/sda3",
                                "/dev/sda5", "/dev/sda4"])
        with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                GuestFS=lambda **kwargs: fake)}):
            with self.assertRaisesRegex(mint.MintOverlayError, "exactly four Windows"):
                mint._guest_disk_audit(Path("/tmp/unused"))

    def test_native_grub_and_release_claims_are_never_enabled_by_harness(self):
        source = (Path(mint.__file__)).read_text(encoding="utf-8")
        self.assertIn('"mintSquashfsRootCopiedToWindowsCOWPartition5": True', source)
        self.assertNotIn('"mintInstalledIntoWindowsCOWPartition5": True', source)
        self.assertIn('"nativeGrubDualBootVerified": False', source)
        self.assertIn('"sameDiskDualBootVerified": False', source)
        self.assertIn('"updatesVerified": False', source)
        self.assertIn('"rollbackVerified": False', source)
        self.assertNotIn("losetup", source)
        self.assertNotIn("mkfs.ext4", source)
        self.assertNotIn("sgdisk", source)

    def test_installed_root_configuration_uses_real_newlines(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "etc").mkdir()
            with patch.object(mint.subprocess, "run") as run:
                mint.write_target_configuration(
                    target, "12345678-1234-4234-8234-123456789abc")
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args_list[0].kwargs["input"],
                             "UUID=12345678-1234-4234-8234-123456789abc / ext4 defaults 0 1\n")
            self.assertEqual(run.call_args_list[1].kwargs["input"], "GASLUXMINT\n")

    def test_installed_root_configuration_rejects_invalid_uuid(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "etc").mkdir()
            with patch.object(mint.subprocess, "run") as run:
                with self.assertRaisesRegex(mint.MintOverlayError, "invalid Mint root"):
                    mint.write_target_configuration(target, "not-a-uuid")
            run.assert_not_called()

    def test_success_returns_four_windows_partition_hashes(self):
        fake = FakeGuest()
        with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                GuestFS=lambda **kwargs: fake)}):
            root_uuid, hashes = mint._guest_disk_audit(Path("/tmp/unused"))
        self.assertEqual(root_uuid, fake.uuid)
        self.assertEqual(len(hashes), 4)
        self.assertTrue(all(len(value) == 64 for value in hashes))
        self.assertTrue(fake.closed)


if __name__ == "__main__":
    unittest.main()
