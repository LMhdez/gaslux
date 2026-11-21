"""Read-only, fail-closed Zorin ISO installer candidate inventory tests."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import zorin_official_iso_installer_inventory as inventory


class ZorinInstallerInventoryContracts(unittest.TestCase):
    def test_manifest_detects_installer_and_bootloader_candidates(self):
        installed, boot = inventory.parse_packages(
            "subiquity 1.0\ncurtin 2.0\nubiquity 3.0\n"
            "grub-efi-amd64-signed 1.0\nshim-signed 1.0\nlinux-image 6.17\n")
        self.assertEqual(installed, ["curtin", "subiquity", "ubiquity"])
        self.assertEqual(boot, ["grub-efi-amd64-signed", "shim-signed"])

    def test_unrelated_packages_do_not_imply_installer(self):
        self.assertEqual(inventory.parse_packages("python3 3.12\nlinux-image 6.17\n"),
                         ([], []))

    def test_launcher_inventory_never_executes_launcher(self):
        paths = inventory.parse_squashfs_paths(
            "squashfs-root/usr/share/applications/install-zorin-os.desktop\n"
            "squashfs-root/usr/share/applications/ordinary-app.desktop\n"
            "squashfs-root/usr/share/applications/../../etc/passwd.desktop\n")
        self.assertEqual(paths, ["usr/share/applications/install-zorin-os.desktop"])
        info = inventory.launcher_metadata(
            paths[0], b"[Desktop Entry]\nName=Install Zorin OS\nExec=zorin-os-installer\n")
        self.assertEqual(info["exec"], "zorin-os-installer")
        self.assertEqual(len(info["sha256"]), 64)

    def test_duplicate_exec_refuses_unique_invocation_claim(self):
        entry = inventory.launcher_metadata(
            "usr/share/applications/zorin-installer.desktop", b"Exec=a\nExec=b\n")
        self.assertNotIn("exec", entry)

    def test_foreign_launcher_path_is_rejected(self):
        with self.assertRaisesRegex(inventory.InventoryError, "launcher path"):
            inventory.launcher_metadata("../../etc/passwd.desktop", b"Exec=sh\n")

    def test_oversized_launcher_is_rejected(self):
        with self.assertRaisesRegex(inventory.InventoryError, "oversized"):
            inventory.launcher_metadata(
                "usr/share/applications/zorin-installer.desktop",
                b"X" * (inventory.MAX_LAUNCHER + 1),
            )

    def test_absent_hosted_runner_consent_refused_before_iso_read(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(inventory.InventoryError, "opted-in"):
                inventory.collect_inventory(Path("/no.iso"), Path("/not-mounted"))

    def test_no_native_install_or_disk_write_claims(self):
        text = Path(inventory.__file__).read_text(encoding="utf-8")
        for field in (
            "nativeInstallerInvoked", "installerWriteSetAuthenticated",
            "productionBootloaderVerified", "windowsEspSafeToWrite",
            "nativeInstallerIdentificationComplete", "stable",
        ):
            self.assertIn(f'"{field}": False', text)
        self.assertNotIn("mkfs.", text)
        self.assertNotIn("grub-install", text)
        self.assertNotIn("efibootmgr --create", text)


if __name__ == "__main__":
    unittest.main()
