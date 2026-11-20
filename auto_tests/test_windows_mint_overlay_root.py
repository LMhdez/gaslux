"""Fail-closed contracts for the Mint/Windows disposable COW harness."""
from __future__ import annotations

import hashlib
import json
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
    def test_orderly_shutdown_witness_accepts_systemd_poweroff_unit(self):
        self.assertTrue(mint.has_orderly_shutdown_witness(
            b"[  OK  ] Finished systemd-poweroff.service - System Power Off.\n"))

    def test_orderly_shutdown_witness_accepts_kernel_power_down_line(self):
        self.assertTrue(mint.has_orderly_shutdown_witness(
            b"[   23.521817] reboot: Power down\n"))

    def test_orderly_shutdown_witness_accepts_crlf_serial_output(self):
        for witness in (
            b"systemd-shutdown[1]: Powering off.\r\n",
            b"[  OK  ] Finished systemd-poweroff.service - System Power Off.\r\n",
            b"[   23.521817] reboot: Power down\r\n",
        ):
            with self.subTest(witness=witness):
                self.assertTrue(mint.has_orderly_shutdown_witness(
                    b"Linux version 6.14\r\n" + witness))

    def test_orderly_shutdown_witness_rejects_embedded_carriage_return(self):
        self.assertFalse(mint.has_orderly_shutdown_witness(
            b"Linux version 6.14\nnoise\rsystemd-shutdown[1]: Powering off.\n"))

    def test_orderly_shutdown_witness_rejects_boot_or_login_only(self):
        self.assertFalse(mint.has_orderly_shutdown_witness(
            b"Linux version 6.14\nGASLUXMINT login:\n"))

    def test_orderly_shutdown_witness_rejects_unrelated_embedded_words(self):
        self.assertFalse(mint.has_orderly_shutdown_witness(
            b"kernel: previous command mentioned systemd-shutdown Powering off.\n"
        ))

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

    def test_post_windows_read_only_guestfs_checks_mint_files_and_hashes(self):
        import tempfile
        uuid = "12345678-1234-4234-8234-123456789abc"
        os_release = b"NAME=Linux Mint\\nID=linuxmint\\n"
        hashes = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
        class AfterWindowsGuest(FakeGuest):
            def __init__(self):
                super().__init__(uuid=uuid)
                self.mounts = []
            def mount_ro(self, part, directory):
                self.mounts.append((part, directory))
            def read_file(self, path):
                if path == "/etc/os-release":
                    return os_release
                if path == "/etc/fstab":
                    return f"UUID={uuid} / ext4 defaults 0 1\\n".encode()
                raise AssertionError("unexpected file")
            def checksum(self, algorithm, path):
                assert algorithm == "sha256"
                return ("2" if path.startswith("/boot/vmlinuz-") else "3") * 64
            def umount_all(self):
                self.mounts.append("unmounted")
        fake = AfterWindowsGuest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "windows.qcow2"
            base.write_bytes(b"private Windows COW test base")
            base.chmod(0o400)
            checkpoint = root / "windows-uefi-cow-checkpoint"
            checkpoint.mkdir(mode=0o700)
            overlay = checkpoint / "cachyos-unwritten-trial-overlay.qcow2"
            overlay.write_bytes(b"disposable")
            overlay.chmod(0o600)
            proof = {
                "mintRootUuid": uuid,
                "mintKernel": "vmlinuz-6.14.0-37-generic",
                "mintKernelSha256": "2" * 64,
                "mintInitramfsSha256": "3" * 64,
                "mintOsReleaseSha256": hashlib.sha256(os_release).hexdigest(),
                "windowsBackingQcow2Sha256": "e" * 64,
                "windowsPartitionSha256": hashes,
            }
            fourth = {
                "windowsBootAfterExt4Verified": True,
                "windowsBcdWinreEspAfterExt4Verified": True,
                "fifthExt4UuidSurvivedWindowsBoot": True,
                "fourthGuestCleanShutdownVerified": True,
                "windowsGptUnchangedAfterExt4Boot": True,
                "windowsBackingUnchangedAfterExt4Boot": True,
                "originalWindowsUefiUnchangedAfterExt4Boot": True,
                "sameDiskDualBootVerified": False,
                "rollbackProven": False,
                "fourthGuestSerialSha256": "f" * 64,
            }
            qemu_info = {"format": "qcow2", "virtual-size": 128 * 1024**3,
                         "backing-filename": str(base),
                         "backing-filename-format": "qcow2"}
            with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                    GuestFS=lambda **kwargs: fake)}), \\
                 patch("windows_cachyos_cow_checkpoint.owned_regular"), \\
                 patch("windows_cachyos_qcow2_gpt_readonly.qcow2_file_identity",
                       return_value="identity"), \\
                 patch("windows_cachyos_qcow2_gpt_readonly.require_unchanged_qcow2"), \\
                 patch.object(mint, "sha256", return_value="e" * 64), \\
                 patch.object(mint, "run", return_value=SimpleNamespace(
                     stdout=json.dumps(qemu_info))), \\
                 patch.object(mint, "_guest_disk_audit", return_value=(uuid, hashes)):
                persistence = mint.verify_mint_persistence_after_windows(
                    overlay=overlay, base=base, mint_proof=proof, fourth=fourth)
                self.assertTrue(persistence["mintRootFilesPersistAfterWindowsVerified"])
                self.assertEqual(persistence["fourthGuestSerialSha256"], "f" * 64)
                self.assertEqual(fake.mounts[0], ("/dev/sda5", "/"))
                self.assertTrue(fake.closed)
                # Fault injection: a changed Windows partition digest is a hard failure.
                with patch.object(mint, "_guest_disk_audit",
                                  return_value=(uuid, ["0" * 64] * 4)):
                    with self.assertRaisesRegex(mint.MintOverlayError,
                                                "partition hashes"):
                        mint.verify_mint_persistence_after_windows(
                            overlay=overlay, base=base, mint_proof=proof, fourth=fourth)
                # Fault injection: changed installed initramfs is not persistence.
                original = fake.checksum
                fake.checksum = lambda algorithm, path: (
                    "0" * 64 if path.startswith("/boot/initrd") else
                    original(algorithm, path))
                with self.assertRaisesRegex(mint.MintOverlayError,
                                            "kernel or installed initramfs"):
                    mint.verify_mint_persistence_after_windows(
                        overlay=overlay, base=base, mint_proof=proof, fourth=fourth)

    def test_post_windows_persistence_rejects_missing_fourth_boot_before_guestfs(self):
        with patch.dict(sys.modules, {"guestfs": SimpleNamespace(
                GuestFS=lambda **kwargs: self.fail("should not open guestfs"))}):
            with self.assertRaisesRegex(mint.MintOverlayError,
                                        "fourth Windows"):
                mint.verify_mint_persistence_after_windows(
                    overlay=Path("/no/overlay"), base=Path("/no/base"),
                    mint_proof={}, fourth={})

    def test_ephemeral_shutdown_service_is_explicit_and_one_boot_scoped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            system = target / "etc/systemd/system"
            system.mkdir(parents=True)
            def fake_run(args, **kwargs):
                if args[1] == "tee":
                    Path(args[2]).write_text(kwargs["input"], encoding="utf-8")
                elif args[1] == "ln":
                    Path(args[-1]).symlink_to(args[-2])
                elif args[1] == "install":
                    Path(args[-1]).mkdir(parents=True, exist_ok=True)
                return SimpleNamespace(returncode=0)
            with patch.object(mint.subprocess, "run", side_effect=fake_run):
                mint.configure_ephemeral_shutdown_service(target)
            unit = system / "gaslux-ci-shutdown.service"
            link = system / "multi-user.target.wants/gaslux-ci-shutdown.service"
            contents = unit.read_text()
            self.assertIn("ExecStartPre=/bin/sleep 15", contents)
            self.assertIn("ExecStart=/bin/systemctl poweroff", contents)
            self.assertIn("After=serial-getty@ttyS0.service", contents)
            self.assertNotIn("After=multi-user.target", contents)
            self.assertTrue(contents.endswith("\n"))
            self.assertEqual(link.readlink(), Path("../gaslux-ci-shutdown.service"))

    def test_ephemeral_shutdown_service_refuses_existing_unit_or_symlink(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            system = target / "etc/systemd/system"
            system.mkdir(parents=True)
            (system / "gaslux-ci-shutdown.service").symlink_to(target / "outside")
            with patch.object(mint.subprocess, "run") as run:
                with self.assertRaisesRegex(mint.MintOverlayError, "refusing to replace"):
                    mint.configure_ephemeral_shutdown_service(target)
            run.assert_not_called()

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
        recursive_cleanup = source.index("unmount_private_tree(bind_mount)")
        fuse_unmount = source.index('run(["sudo", "guestunmount", str(target)]')
        fallback = source.index('["sudo", "fusermount3", "-u", str(target)]')
        verify = source.index('["sudo", "findmnt", "-rn", "--mountpoint", str(target)]')
        self.assertLess(bind_cleanup, recursive_cleanup)
        self.assertLess(recursive_cleanup, fuse_unmount)
        self.assertLess(fuse_unmount, fallback)
        self.assertLess(fallback, verify)
        self.assertNotIn('str(bind_mount)], check=False', source)


    def test_unmount_private_tree_recursively_cleans_nested_mounts(self):
        calls = []
        def fake_run(args, **kwargs):
            calls.append(args)
            if args[1:3] == ["umount", "--recursive"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(mint.subprocess, "run", side_effect=fake_run):
            mint.unmount_private_tree(Path("/tmp/private/target/sys"))
        self.assertEqual(calls[0], [
            "sudo", "umount", "--recursive", "/tmp/private/target/sys",
        ])
        self.assertEqual(calls[1], ["sudo", "findmnt", "-rn", "-o", "TARGET"])

    def test_unmount_private_tree_fails_closed_when_nested_mount_remains(self):
        def fake_run(args, **kwargs):
            if args[1:3] == ["umount", "--recursive"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(
                returncode=0,
                stdout="/tmp/private/target/sys\n/tmp/private/target/sys/fs/cgroup\n",
                stderr="",
            )
        with patch.object(mint.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(mint.MintOverlayError, "remaining=.*cgroup"):
                mint.unmount_private_tree(Path("/tmp/private/target/sys"))

    def test_unmount_private_tree_rejects_symlinked_path_before_commands(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / "sys"
            link.symlink_to(root, target_is_directory=True)
            with patch.object(mint.subprocess, "run") as run:
                with self.assertRaisesRegex(mint.MintOverlayError, "unsafe chroot mount"):
                    mint.unmount_private_tree(link)
            run.assert_not_called()




if __name__ == "__main__":
    unittest.main()
