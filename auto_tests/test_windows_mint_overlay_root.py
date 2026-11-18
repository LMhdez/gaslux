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

    def test_guestfish_copy_in_uses_direct_libguestfs_transfer(self):
        command = mint.guestfish_copy_in_command(
            Path("/tmp/windows-cow.qcow2"), Path("/tmp/unpacked"))
        self.assertEqual(command, [
            "sudo", "guestfish", "--rw", "-a", "/tmp/windows-cow.qcow2",
            "-m", "/dev/sda5", "copy-in", "/tmp/unpacked/.", "/",
        ])

    def test_guestfish_download_uses_readonly_guest_access(self):
        command = mint.guestfish_download_command(
            Path("/tmp/windows-cow.qcow2"),
            "/boot/initrd.img-6.14.0-37-generic",
            Path("/tmp/initrd.img"))
        self.assertEqual(command, [
            "sudo", "guestfish", "--ro", "-a", "/tmp/windows-cow.qcow2",
            "-m", "/dev/sda5", "download",
            "/boot/initrd.img-6.14.0-37-generic", "/tmp/initrd.img",
        ])

    def test_initramfs_is_downloaded_after_fuse_unmount_before_host_inspection(self):
        source = Path(mint.__file__).read_text(encoding="utf-8")
        unmount = source.index('run(["sudo", "guestunmount", str(target)], timeout=120)')
        download = source.index("guestfish_download_command(overlay, f\"/boot/initrd.img-{version}\"")
        inspect = source.index('run(["lsinitramfs", str(initrd_copy)], timeout=600)')
        self.assertLess(unmount, download)
        self.assertLess(download, inspect)
        self.assertNotIn('"chroot", str(target), "lsinitramfs"', source)

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


    def _make_kernel_tree(self, root: Path, builtin: str = "kernel/fs/ext4.ko"):
        modules = root / "lib/modules/6.8.0-mint"
        modules.mkdir(parents=True)
        (modules / "modules.builtin").write_text(builtin + "\n", encoding="utf-8")
        (modules / "modules.dep").write_text(
            "kernel/drivers/block/virtio_blk.ko:\n"
            "kernel/drivers/virtio/virtio_pci.ko:\n",
            encoding="utf-8",
        )
        (root / "etc/initramfs-tools").mkdir(parents=True)
        (root / "etc/initramfs-tools/modules").write_text(
            "# keep existing settings\n", encoding="utf-8")
        return modules

    def test_prepare_initramfs_requests_loadable_storage_drivers(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_kernel_tree(root)
            def fake_run(args, **kwargs):
                Path(args[-1]).write_text(kwargs["input"], encoding="utf-8")
                return SimpleNamespace(returncode=0)
            with patch.object(mint.subprocess, "run", side_effect=fake_run) as run:
                builtins, loadable = mint.prepare_initramfs_modules(root, "6.8.0-mint")
            configured = (root / "etc/initramfs-tools/modules").read_text()
            self.assertEqual(builtins, {"ext4"})
            self.assertEqual(loadable, {"virtio_blk", "virtio_pci"})
            self.assertIn("virtio_blk\n", configured)
            self.assertIn("virtio_pci\n", configured)
            self.assertNotIn("ext4\n", configured)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][:2], ["sudo", "tee"])

    def test_prepare_initramfs_accepts_all_drivers_built_into_kernel(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            modules = self._make_kernel_tree(
                root,
                "kernel/fs/ext4.ko\n"
                "kernel/drivers/block/virtio_blk.ko\n"
                "kernel/drivers/virtio/virtio_pci.ko",
            )
            (modules / "modules.dep").write_text("", encoding="utf-8")
            with patch.object(mint.subprocess, "run") as run:
                builtins, loadable = mint.prepare_initramfs_modules(root, "6.8.0-mint")
            self.assertEqual(builtins, {"ext4", "virtio_blk", "virtio_pci"})
            self.assertEqual(loadable, set())
            run.assert_not_called()

    def test_prepare_initramfs_fails_closed_when_kernel_driver_is_missing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_kernel_tree(root, builtin="kernel/fs/ext4.ko")
            modules_dep = root / "lib/modules/6.8.0-mint/modules.dep"
            modules_dep.write_text("kernel/fs/ext4.ko:\n", encoding="utf-8")
            with patch.object(mint.subprocess, "run") as run:
                with self.assertRaisesRegex(mint.MintOverlayError, "virtio_blk"):
                    mint.prepare_initramfs_modules(root, "6.8.0-mint")
            run.assert_not_called()

    def test_prepare_initramfs_rejects_symlinked_modules_configuration(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_kernel_tree(root)
            config = root / "etc/initramfs-tools/modules"
            config.unlink()
            config.symlink_to(root / "outside")
            with patch.object(mint.subprocess, "run") as run:
                with self.assertRaisesRegex(mint.MintOverlayError, "not a regular file"):
                    mint.prepare_initramfs_modules(root, "6.8.0-mint")
            run.assert_not_called()

    def test_initramfs_validation_accepts_builtins_and_requires_loadable_modules(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            modules = self._make_kernel_tree(root, builtin="kernel/fs/ext4.ko")
            listing = (
                "usr/lib/modules/6.8.0-mint/kernel/drivers/block/virtio_blk.ko.zst\n"
                "usr/lib/modules/6.8.0-mint/kernel/drivers/virtio/virtio_pci.ko.xz\n"
            )
            mint.validate_initramfs_driver_support(root / "lib/modules", "6.8.0-mint", listing)
            with self.assertRaisesRegex(mint.MintOverlayError, "virtio_pci"):
                mint.validate_initramfs_driver_support(
                    root / "lib/modules", "6.8.0-mint",
                    "usr/lib/modules/6.8.0-mint/kernel/drivers/block/virtio_blk.ko.zst\n",
                )

    def test_initramfs_module_preparation_precedes_update_initramfs(self):
        source = Path(mint.__file__).read_text(encoding="utf-8")
        prepare = source.index("prepare_initramfs_modules(target, version)")
        update = source.index('"update-initramfs", "-u", "-k", version')
        self.assertLess(prepare, update)


    def test_bind_and_fuse_unmounts_are_checked_and_verified(self):
        source = Path(mint.__file__).read_text(encoding="utf-8")
        bind_cleanup = source.index("for bind_mount in (target /")
        fuse_unmount = source.index('run(["sudo", "guestunmount", str(target)]')
        fallback = source.index('["sudo", "fusermount3", "-u", str(target)]')
        verify = source.index('["sudo", "findmnt", "-rn", "--mountpoint", str(target)]')
        self.assertLess(bind_cleanup, fuse_unmount)
        self.assertLess(fuse_unmount, fallback)
        self.assertLess(fallback, verify)
        self.assertNotIn('str(bind_mount)], check=False', source)



if __name__ == "__main__":
    unittest.main()
