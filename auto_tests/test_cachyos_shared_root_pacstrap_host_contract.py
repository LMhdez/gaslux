from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

import cachyos_windows_shared_root_pacstrap_host as host


class SharedRootPacstrapHostContracts(unittest.TestCase):
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
        self.assertIn('"usb-storage,drive=liveefi,bootindex=1"', source)
        self.assertNotIn('"order=c"', source)
        self.assertIn("_copy_fresh_ovmf_vars(Path(OVMF_VARS), trial_vars)", source)
        self.assertNotIn("shutil.copyfile(nvram, trial_vars)", source)

    def test_pacstrap_and_discard_evidence_are_valid_json_whitespace(self):
        source = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        self.assertNotIn(r'+ "\\\\n"', source)
        self.assertIn("json.dumps(pacstrap_proof, sort_keys=True, indent=2)", source)
        self.assertIn("json.dumps(discard_proof, sort_keys=True, indent=2)", source)
        self.assertIn('+ "\\n"', source)

    def test_guest_installer_remains_root_only_and_never_installs_efi(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap.py").read_text()
        self.assertIn('"pacstrap", "-K", "-C", str(strict_config), str(ROOT)', source)
        self.assertIn("verify_mounted_source(ROOT, root_partition, \"ext4\", readonly=False)", source)
        self.assertIn("GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED=1", source)
        for forbidden in ("sgdisk --clear", "grub-install", "efibootmgr -c", "mkfs.ext4"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
