from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

import cachyos_windows_shared_root_pacstrap_host as host


class SharedRootPacstrapHostContracts(unittest.TestCase):
    def test_owned_ext4_iso_copy_requires_exact_loop_backing_before_chown(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-ext4-iso-owner-") as temp:
            root = Path(temp)
            image = root / "cachyos-iso-source.raw"
            image.write_bytes(b"owned test image" * 4096)
            image.chmod(0o600)
            mount = root / "cachyos-iso-storage"
            mount.mkdir(mode=0o700)
            commands = []

            def fake_run(argv, **kwargs):
                commands.append(argv)
                if argv[0] == "findmnt":
                    return subprocess.CompletedProcess(argv, 0, "/dev/loop7 ext4\n", "")
                if argv[:3] == ["sudo", "losetup", "-j"]:
                    return subprocess.CompletedProcess(
                        argv, 0, "/dev/loop7: [0]:1 (" + str(image) + ")\n", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(host.os.path, "ismount", return_value=True), \
                 patch.object(host, "_run", side_effect=fake_run):
                host._prepare_owned_ext4_iso_copy(image, mount)
                self.assertEqual(
                    [argv[1] for argv in commands if argv[0] == "sudo"],
                    ["losetup", "chown", "chmod"])
                commands.clear()

                def wrong_loop(argv, **kwargs):
                    commands.append(argv)
                    if argv[0] == "findmnt":
                        return subprocess.CompletedProcess(argv, 0, "/dev/loop7 ext4\n", "")
                    if argv[:3] == ["sudo", "losetup", "-j"]:
                        return subprocess.CompletedProcess(argv, 0, "/dev/loop9: [0]:1 (foreign)\n", "")
                    raise AssertionError("privileged write after loop identity mismatch")

                with patch.object(host, "_run", side_effect=wrong_loop):
                    with self.assertRaisesRegex(host.SharedRootPacstrapError,
                                                "does not match the owned raw image"):
                        host._prepare_owned_ext4_iso_copy(image, mount)
                self.assertFalse(any("chown" in c for c in commands))

            with patch.object(host.os.path, "ismount", return_value=False), \
                 patch.object(host, "_run") as never:
                with self.assertRaisesRegex(host.SharedRootPacstrapError, "mountpoint"):
                    host._prepare_owned_ext4_iso_copy(image, mount)
                never.assert_not_called()

    def test_iso_copy_owner_check_is_inside_unmount_finally(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        start = source.index('storage_iso = storage_root / "cachyos.iso"')
        end = source.index('unmount_rw = _run(["sudo", "umount"', start)
        segment = source[start:end]
        self.assertLess(segment.index("_prepare_owned_ext4_iso_copy("),
                        segment.index('storage_iso.open("xb")'))
        self.assertIn("finally:", segment)

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
        # Check each report's serialization independently; the old test
        # required and forbade the exact same '+ "\\n"' source text.
        for proof in ("pacstrap_proof", "discard_proof"):
            marker = f"json.dumps({proof}, sort_keys=True, indent=2)"
            self.assertEqual(source.count(marker), 1)
            serialized = source.split(marker, 1)[1].split(').encode("utf-8")', 1)[0]
            self.assertIn(r'+ "\n"', serialized)

    def test_guest_installer_remains_root_only_and_never_installs_efi(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap.py").read_text()
        self.assertIn('"pacstrap", "-K", "-C", str(strict_config), str(ROOT)', source)
        self.assertIn('verify_mounted_source(ROOT, root_partition, "ext4", readonly=False)', source)
        self.assertIn("GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED=1", source)
        for forbidden in ("sgdisk --clear", "grub-install", "efibootmgr -c", "mkfs.ext4"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
