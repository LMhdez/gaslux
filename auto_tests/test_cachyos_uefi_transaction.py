"""Filesystem fault-injection for CachyOS's VM-only EFI lab transaction.

All mounts, chroot calls and firmware checks are mocked; no disk/EFI mutations
occur on the test machine. This is NOT an end-to-end boot or Windows test.
"""
from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "assets/live/cachyos-uefi-lab.py"
spec = importlib.util.spec_from_file_location("cachyos_uefi_faults", SOURCE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
WIN_BYTES = b"MZ" + b"Windows Boot Manager fixture"
PLAN = {
    "version": 1, "firmware": "uefi", "secureBootEnabled": False,
    "runId": "cachyos-lab-fixture-1234",
    "rootUuid": "01234567-89ab-cdef-0123-456789abcdef",
    "espUuid": "AB12-CD34", "windowsBootUuid": "AB12-CD34",
    "windowsBootManagerSha256": hashlib.sha256(WIN_BYTES).hexdigest(),
    "linuxLabel": "CachyOS Linux", "grubResolution": "1920x1080",
}
GRUB_GOOD = (
    'menuentry "CachyOS" { linux /boot/vmlinuz-linux-cachyos }\n'
    'menuentry "Windows Boot Manager" --id gaslux-windows {}\n'
)


class UefiTransactionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.put("etc/os-release", "NAME=CachyOS\nID=cachyos\n")
        self.put("boot/vmlinuz-linux-cachyos", b"Linux kernel fixture")
        self.put("boot/initramfs-linux-cachyos.img", b"initramfs fixture")
        self.put("boot/efi/EFI/Microsoft/Boot/bootmgfw.efi", WIN_BYTES)
        (self.root / "etc/grub.d").mkdir(parents=True)
        (self.root / "etc/default/grub.d").mkdir(parents=True)
        self.commands = []
        self.fail_at = None
        self.bad_grub = False
        self.corrupt_windows = False
        self.foreign_grub = False

    def put(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return path

    def fake_run(self, *args):
        self.commands.append(args)
        self.assertEqual(args[0], "arch-chroot")
        self.assertEqual(args[1], str(self.root))
        command = args[2]
        if command == "grub-install":
            self.put("boot/efi/EFI/Gaslux-CachyOS/grubx64.efi", b"MZ" + b"grub fixture")
            if self.corrupt_windows:
                self.put("boot/efi/EFI/Microsoft/Boot/bootmgfw.efi", WIN_BYTES + b"modified")
        if command == "grub-mkconfig":
            self.put("boot/grub/grub.cfg.gaslux-candidate",
                     GRUB_GOOD if not self.bad_grub else 'menuentry "CachyOS" {}')
        if command == "grub-script-check" and self.foreign_grub:
            self.put("boot/grub/grub.cfg", "FOREIGN CONFIGURATION\n")
        if command == self.fail_at:
            raise module.LabError("fault injected: " + command)
        return ""

    def apply(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(module, "TARGET", self.root))
            stack.enter_context(patch.object(module, "check_host"))
            stack.enter_context(patch.object(module, "verify_mounts"))
            stack.enter_context(patch.object(module, "run", side_effect=self.fake_run))
            return module.apply_vm_lab(PLAN)

    def assert_cleanup(self):
        for rel in (
            "boot/grub/grub.cfg.gaslux-candidate",
            "etc/fstab",
            "etc/default/grub.d/99-gaslux.cfg",
            "etc/grub.d/45_gaslux_windows",
            "boot/efi/EFI/Gaslux-CachyOS",
        ):
            with self.subTest(path=rel):
                self.assertFalse((self.root / rel).exists())
        self.assertEqual((self.root / "boot/efi/EFI/Microsoft/Boot/bootmgfw.efi").read_bytes(), WIN_BYTES)

    def test_success_publishes_only_validated_grub_and_does_not_touch_windows(self):
        result = self.apply()
        self.assertEqual(result["status"], "vm-lab-efi-files-installed")
        self.assertEqual(result["bootsVerified"], "false")
        self.assertTrue((self.root / "boot/grub/grub.cfg").is_file())
        self.assertEqual((self.root / "boot/grub/grub.cfg").read_text(), GRUB_GOOD)
        self.assertFalse((self.root / "boot/grub/grub.cfg.gaslux-candidate").exists())
        self.assertIn(("--no-nvram"), self.commands[0])
        self.assertEqual((self.root / "boot/efi/EFI/Microsoft/Boot/bootmgfw.efi").read_bytes(), WIN_BYTES)

    def test_grub_install_failure_rolls_back_new_files(self):
        self.fail_at = "grub-install"
        with self.assertRaisesRegex(module.LabError, "grub-install"):
            self.apply()
        self.assert_cleanup()

    def test_partial_grub_generation_never_published(self):
        self.fail_at = "grub-mkconfig"
        with self.assertRaisesRegex(module.LabError, "grub-mkconfig"):
            self.apply()
        self.assert_cleanup()
        self.assertFalse((self.root / "boot/grub/grub.cfg").exists())

    def test_grub_script_check_failure_cleans_candidate(self):
        self.fail_at = "grub-script-check"
        with self.assertRaisesRegex(module.LabError, "grub-script-check"):
            self.apply()
        self.assert_cleanup()

    def test_missing_windows_menu_rejected_before_publish(self):
        self.bad_grub = True
        with self.assertRaisesRegex(module.LabError, "lacks required"):
            self.apply()
        self.assert_cleanup()

    def test_foreign_grub_cfg_is_not_overwritten_or_deleted(self):
        self.foreign_grub = True
        with self.assertRaises(FileExistsError):
            self.apply()
        self.assertEqual((self.root / "boot/grub/grub.cfg").read_text(),
                         "FOREIGN CONFIGURATION\n")
        self.assert_cleanup()

    def test_detects_windows_loader_mutation_after_grub_install(self):
        self.corrupt_windows = True
        with self.assertRaisesRegex(module.LabError, "Windows Boot Manager changed"):
            self.apply()
        self.assertFalse((self.root / "boot/grub/grub.cfg").exists())
        self.assertFalse((self.root / "boot/efi/EFI/Gaslux-CachyOS").exists())
        self.assertNotEqual((self.root / "boot/efi/EFI/Microsoft/Boot/bootmgfw.efi").read_bytes(),
                            WIN_BYTES)


if __name__ == "__main__":
    unittest.main()
