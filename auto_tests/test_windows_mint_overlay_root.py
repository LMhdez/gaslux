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


class FakeWritableGuest(FakeGuest):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.writes = []
        self.drive_opts = None

    def add_drive_opts(self, *args, **kwargs):
        self.drive_opts = kwargs

    def mount(self, partition, mountpoint):
        self.writes.append(("mount", partition, mountpoint))

    def tar_in(self, archive, mountpoint, **kwargs):
        self.writes.append(("tar_in", archive, mountpoint, kwargs))

    def sync(self):
        self.writes.append(("sync",))


class MintOverlayContracts(unittest.TestCase):
    def test_mint_tar_import_checks_windows_hashes_before_any_writable_mount(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "mint-root.tar.gz"
            archive.write_bytes(b"1" * (1024 * 1024 + 1))
            archive.chmod(0o600)
            guest = FakeWritableGuest()
            expected = ["a" * 64, "b" * 64, "b" * 64, "b" * 64]
            with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                    GuestFS=lambda **kwargs: guest)}):
                mint._import_tar_into_exact_owned_root(
                    Path(directory) / "windows-cow.qcow2",
                    archive, guest.uuid, expected)
            self.assertEqual(guest.drive_opts["readonly"], 0)
            self.assertEqual(guest.writes[0], ("mount", "/dev/sda5", "/"))
            self.assertEqual(guest.writes[1][0], "tar_in")
            self.assertEqual(guest.writes[1][2], "/")
            self.assertEqual(guest.writes[1][3],
                             {"compress": "gzip", "xattrs": True, "acls": True})
            self.assertEqual(guest.writes[-1], ("sync",))
            self.assertTrue(guest.closed)

    def test_mint_tar_import_refuses_changed_windows_without_writes(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "mint-root.tar.gz"
            archive.write_bytes(b"1" * (1024 * 1024 + 1))
            archive.chmod(0o600)
            guest = FakeWritableGuest()
            with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                    GuestFS=lambda **kwargs: guest)}):
                with self.assertRaisesRegex(mint.MintOverlayError, "Windows partition hashes"):
                    mint._import_tar_into_exact_owned_root(
                        Path(directory) / "windows-cow.qcow2",
                        archive, guest.uuid, ["f" * 64] * 4)
            self.assertEqual(guest.writes, [])
            self.assertTrue(guest.closed)

    def test_mint_tar_import_refuses_wrong_uuid_without_writes(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "mint-root.tar.gz"
            archive.write_bytes(b"1" * (1024 * 1024 + 1))
            archive.chmod(0o600)
            guest = FakeWritableGuest()
            expected = ["a" * 64, "b" * 64, "b" * 64, "b" * 64]
            with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                    GuestFS=lambda **kwargs: guest)}):
                with self.assertRaisesRegex(mint.MintOverlayError, "ownership or UUID"):
                    mint._import_tar_into_exact_owned_root(
                        Path(directory) / "windows-cow.qcow2",
                        archive, "00000000-0000-4000-8000-000000000000", expected)
            self.assertEqual(guest.writes, [])
            self.assertTrue(guest.closed)

    def test_mint_tar_import_rejects_symlink_archive_before_guestfs(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "root.tar.gz"
            archive.write_bytes(b"1" * (1024 * 1024 + 1))
            archive.chmod(0o600)
            link = Path(directory) / "mint-root.tar.gz"
            link.symlink_to(archive)
            with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                    GuestFS=lambda **kwargs: self.fail("guestfs must not open"))}):
                with self.assertRaisesRegex(mint.MintOverlayError, "archive missing or unsafe"):
                    mint._import_tar_into_exact_owned_root(
                        Path(directory) / "windows-cow.qcow2",
                        link, "12345678-1234-4234-8234-123456789abc",
                        ["a" * 64] * 4)

    def test_real_windows_job_requires_local_synthetic_import_before_any_guest(self):
        workflow = (Path(__file__).resolve().parents[1]
                    / ".github/workflows/windows-cachyos-post-ext4-fourth-boot.yml")
        source = workflow.read_text(encoding="utf-8")
        real = source.split("  genuine-client-two-stage-firstboot:", 1)[1]
        self.assertIn("needs: verify-host-and-proof-contracts", real)
        smoke = "python3 auto_tests/tools/windows_mint_synthetic_tar_guestfs.py"
        installer = "python3 auto_tests/tools/windows_x64_tcg_firstboot.py"
        self.assertIn("Mandatory real synthetic fifth-ext4 tar import", real)
        self.assertIn("GASLUX_SYNTHETIC_EXT4_CONSENT:", real)
        self.assertLess(real.index(smoke), real.index(installer))
        self.assertIn("set -Eeuo pipefail", real)
        self.assertNotIn("continue-on-error: true", real)

    def test_storage_initramfs_explicit_virtio_drivers_are_written_prewrite(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            modules = root / "lib/modules/6.14.0-37-generic"
            modules.mkdir(parents=True)
            (modules / "modules.builtin").write_text(
                "kernel/fs/ext4/ext4.ko\n"
            )
            for driver in ("virtio_pci", "virtio_blk"):
                (modules / f"{driver}.ko.zst").write_bytes(b"sample")
            tools = root / "etc/initramfs-tools"
            tools.mkdir(parents=True)
            (tools / "modules").write_text("# existing defaults\n")
            with patch.object(mint.subprocess, "run") as write:
                builtins = mint.prepare_mint_storage_initramfs_modules(
                    root, "6.14.0-37-generic")
            self.assertEqual(builtins, {"ext4"})
            write.assert_called_once()
            self.assertEqual(write.call_args.args[0][:2], ["sudo", "tee"])
            self.assertIn("virtio_blk\n", write.call_args.kwargs["input"])
            self.assertIn("virtio_pci\n", write.call_args.kwargs["input"])

    def test_storage_initramfs_refuses_missing_virtio_driver_before_write(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            modules = root / "lib/modules/6.14.0-37-generic"
            modules.mkdir(parents=True)
            (modules / "modules.builtin").write_text("kernel/fs/ext4/ext4.ko\n")
            (modules / "virtio_pci.ko.zst").write_bytes(b"sample")
            (root / "etc/initramfs-tools").mkdir(parents=True)
            with patch.object(mint.subprocess, "run") as write:
                with self.assertRaisesRegex(mint.MintOverlayError, "virtio_blk"):
                    mint.prepare_mint_storage_initramfs_modules(
                        root, "6.14.0-37-generic")
            write.assert_not_called()

    def test_storage_initramfs_rejects_dangling_symlink_before_write(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            modules = root / "lib/modules/6.14.0-37-generic"
            modules.mkdir(parents=True)
            (modules / "modules.builtin").write_text(
                "".join(f"kernel/builtin/{name}.ko\n"
                        for name in ("virtio_blk", "virtio_pci", "ext4"))
            )
            tools = root / "etc/initramfs-tools"
            tools.mkdir(parents=True)
            (tools / "modules").symlink_to(root / "nonexistent-foreign-modules")
            with patch.object(mint.subprocess, "run") as write:
                with self.assertRaisesRegex(mint.MintOverlayError, "unsafe Mint"):
                    mint.prepare_mint_storage_initramfs_modules(
                        root, "6.14.0-37-generic")
            write.assert_not_called()

    def test_storage_initramfs_accepts_verified_loadable_modules_and_builtin(self):
        listing = ("usr/lib/modules/6.14.0-37-generic/kernel/drivers/"
                   "block/virtio_blk.ko.zst\n"
                   "usr/lib/modules/6.14.0-37-generic/kernel/drivers/"
                   "virtio/virtio_pci.ko.zst\n")
        mint.verify_mint_storage_initramfs(listing, {"ext4"})
        with self.assertRaisesRegex(mint.MintOverlayError, "virtio_blk"):
            mint.verify_mint_storage_initramfs(
                listing.replace("virtio_blk.ko.zst", "irrelevant.ko.zst"),
                {"ext4"})

    def test_storage_initramfs_accepts_all_genuine_kernel_builtins(self):
        mint.verify_mint_storage_initramfs(
            "", {"ext4", "virtio_blk", "virtio_pci"})

    def test_mint_tar_stage_prepares_initramfs_before_guest_write(self):
        source = Path(mint.__file__).read_text(encoding="utf-8")
        self.assertLess(source.index('write_target_configuration(unpacked, root_uuid, hostname)'),
                        source.index('_import_tar_into_exact_owned_root(overlay, archive'))
        self.assertNotIn('run(["sudo", "cp", "-a", str(unpacked)', source)
        self.assertIn('refusing rootfs import with host chroot filesystem still mounted',
                      source)


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
        self.assertIn('f"{distribution}SquashfsRootCopiedToWindowsCOWPartition5": True', source)
        self.assertIn('distribution: str = "mint"', source)
        self.assertIn('require(distribution in ("mint", "zorin")', source)
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
