from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

import cachyos_windows_shared_root_pacstrap_host as host


class SharedRootPacstrapHostContracts(unittest.TestCase):
    def test_iso_private_loop_permission_fix_requires_exact_backing_identity(self):
        # Sparse 4 GiB private *file*, never a real block device/mount.
        with tempfile.TemporaryDirectory(prefix="gaslux-iso-test-") as td:
            workspace = Path(td)
            image = workspace / "cachyos-iso-source.raw"
            with image.open("xb") as file:
                file.truncate(4 * 1024**3)
            mountpoint = workspace / "cachyos-iso-storage"
            mountpoint.mkdir(mode=0o700)

            def run(argv, **kwargs):
                if argv[0] == "findmnt":
                    return subprocess.CompletedProcess(
                        argv, 0, "/dev/loop73 ext4 rw,relatime\n", "")
                if argv[0] == "losetup":
                    return subprocess.CompletedProcess(
                        argv, 0, str(image) + "\n", "")
                if argv[0] == "sudo":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                raise AssertionError("unexpected command " + str(argv))

            with mock.patch.object(host, "_run", side_effect=run) as commands:
                host._permit_owned_iso_staging_write(image, mountpoint)
                seen = [call.args[0] for call in commands.call_args_list]
                self.assertEqual(seen[0][0], "findmnt")
                self.assertEqual(seen[1],
                                 ["losetup", "--noheadings", "--output",
                                  "BACK-FILE", "/dev/loop73"])
                self.assertEqual(seen[2],
                                 ["sudo", "chown", "--",
                                  f"{os.getuid()}:{os.getgid()}", str(mountpoint)])
                self.assertEqual(seen[3],
                                 ["sudo", "chmod", "--", "0700", str(mountpoint)])

    def test_iso_private_loop_fails_before_chown_if_device_is_foreign(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-iso-deny-") as td:
            workspace = Path(td)
            image = workspace / "cachyos-iso-source.raw"
            with image.open("xb") as f:
                f.truncate(4 * 1024**3)
            mountpoint = workspace / "cachyos-iso-storage"
            mountpoint.mkdir(mode=0o700)
            for source, kind, options, actual_backing in (
                    ("/dev/sda", "ext4", "rw,relatime", str(image)),
                    ("/dev/loop4", "vfat", "rw,relatime", str(image)),
                    ("/dev/loop4", "ext4", "ro,relatime", str(image)),
                    ("/dev/loop4", "ext4", "rw,relatime", "/tmp/foreign.img")):
                def run(argv, **kwargs):
                    if argv[0] == "findmnt":
                        return subprocess.CompletedProcess(
                            argv, 0, f"{source} {kind} {options}\n", "")
                    if argv[0] == "losetup":
                        return subprocess.CompletedProcess(
                            argv, 0, actual_backing + "\n", "")
                    raise AssertionError("must refuse before any privileged write")
                with self.subTest(source=source, kind=kind, options=options,
                                  backing=actual_backing), \
                     mock.patch.object(host, "_run", side_effect=run) as commands, \
                     self.assertRaises(host.SharedRootPacstrapError):
                    host._permit_owned_iso_staging_write(image, mountpoint)
                self.assertFalse(any(x.args[0][0] == "sudo" for x in
                                     commands.call_args_list))

    def test_iso_private_mount_cannot_use_symlink_image(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-iso-linked-") as td:
            folder = Path(td)
            real = folder / "real-image.raw"
            real.touch()
            path = folder / "cachyos-iso-source.raw"
            path.symlink_to(real)
            mountpoint = folder / "cachyos-iso-storage"
            mountpoint.mkdir()
            with mock.patch.object(host, "_run") as commands, \
                 self.assertRaises(host.SharedRootPacstrapError):
                host._permit_owned_iso_staging_write(path, mountpoint)
            commands.assert_not_called()

    def test_genuine_vm_apt_stalls_fail_before_guest_launch(self):
        workflow = (TOOLS.parent.parent / ".github/workflows/"
                    "cachyos-windows10-shared-root-pacstrap.yml").read_text()
        self.assertIn("timeout --kill-after=10s 300s sudo apt-get", workflow)
        self.assertIn("timeout --kill-after=10s 600s sudo DEBIAN_FRONTEND=noninteractive apt-get", workflow)
        self.assertIn("Acquire::https::Timeout=60", workflow)
        # The firmware meta depends on hundreds of MB of unrelated GPU,
        # Wi-Fi, and device firmware. The guestfs Linux VM needs only the
        # authenticated kernel image and matching signed module packages.
        self.assertIn("apt-cache depends linux-image-generic", workflow)
        self.assertIn('extra_modules="linux-modules-extra-', workflow)
        self.assertIn('"$generic_kernel" "$extra_modules"', workflow)
        self.assertNotIn('libguestfs-tools linux-image-generic', workflow)
        self.assertIn("Kernel packaging unexpectedly requires firmware", workflow)
        self.assertIn("real-windows10-archiso-pacstrap-and-discard:", workflow)
        self.assertIn("if: github.event_name != 'pull_request'", workflow)

    def test_trial_firmware_uses_fresh_ovmf_template_not_windows_bootorder(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-ovmf-template-") as temp:
            root = Path(temp)
            template = root / "OVMF_VARS_4M.fd"
            destination = root / "trial-vars.fd"
            template.write_bytes(b"fresh-ovmf-template" * 8192)
            digest = host._copy_fresh_ovmf_vars(template, destination)
            self.assertEqual(destination.read_bytes(), template.read_bytes())
            self.assertEqual(len(digest), 64)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_trial_firmware_refuses_symlink_and_reused_destination(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-ovmf-reject-") as temp:
            root = Path(temp)
            template = root / "OVMF_VARS_4M.fd"
            template.write_bytes(b"fresh-ovmf-template" * 8192)
            destination = root / "trial-vars.fd"
            destination.write_bytes(b"existing")
            with self.assertRaises(host.SharedRootPacstrapError):
                host._copy_fresh_ovmf_vars(template, destination)
            destination.unlink()
            linked = root / "linked-template.fd"
            linked.symlink_to(template)
            with self.assertRaises(host.SharedRootPacstrapError):
                host._copy_fresh_ovmf_vars(linked, destination)

    def test_archiso_efi_loader_has_explicit_qemu_boot_priority(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        self.assertIn("from cachyos_windows_shared_archiso_handoff import", source)
        self.assertIn("from windows_x64_qemu_host_gate import OVMF_VARS", source)
        self.assertIn('"usb-storage,drive=liveefi,bootindex=1"', source)
        self.assertNotIn('"order=c"', source)
        self.assertIn("_copy_fresh_ovmf_vars(Path(OVMF_VARS), trial_vars)", source)
        self.assertNotIn("shutil.copyfile(nvram, trial_vars)", source)

    def test_host_keeps_checkpoint_and_readonly_media_integrity_guards(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        for token in (
            '(handoff / "host-checkpoint.json", "host-checkpoint.json")',
            '(handoff / "host-overlay-backing-proof.json", "host-overlay-backing-proof.json")',
            'post_info_doc.get("backing-filename")',
            "before_iso_image_sha",
            "before_control_sha",
            "before_boot_efi_sha",
            'require(created.returncode == 0, "could not create isolated UEFI fallback directory")',
        ):
            self.assertIn(token, source)

    def test_pacstrap_and_discard_evidence_are_valid_json_whitespace(self):
        source = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        self.assertNotIn('+ "' + chr(92) * 2 + 'n"', source)
        self.assertIn("json.dumps(pacstrap_proof, sort_keys=True, indent=2)", source)
        self.assertIn("json.dumps(discard_proof, sort_keys=True, indent=2)", source)
        self.assertIn('+ "' + chr(92) + 'n"', source)

    def test_guest_installer_remains_root_only_and_never_installs_efi(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap.py").read_text()
        self.assertIn('"pacstrap", "-K", "-C", str(strict_config), str(ROOT)', source)
        self.assertIn('verify_mounted_source(ROOT, root_partition, "ext4", readonly=False)', source)
        self.assertIn("GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED=1", source)
        for forbidden in ("sgdisk --clear", "grub-install", "efibootmgr -c", "mkfs.ext4"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
