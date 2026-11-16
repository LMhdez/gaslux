"""Tests for the pure CachyOS UEFI configuration renderer."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

MOD = Path(__file__).resolve().parents[1] / "assets/live/cachyos-uefi-config.py"
spec = importlib.util.spec_from_file_location("cachyos_uefi_config", MOD)
assert spec is not None and spec.loader is not None
uefi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uefi)

GOOD = {
    "version": 1,
    "firmware": "uefi",
    "secureBootEnabled": False,
    "runId": "laboratory_run_2026",
    "rootUuid": "01234567-89ab-cdef-0123-456789abcdef",
    "espUuid": "AB12-CD34",
    "windowsBootUuid": "AB12-CD34",
    "linuxLabel": "CachyOS Linux",
    "grubResolution": "1920x1080",
}


class UefiConfigTests(unittest.TestCase):
    def render(self, **changes):
        values = deepcopy(GOOD)
        values.update(changes)
        return uefi.render(values)

    def test_configuration_contains_exact_verified_identifiers(self):
        result = self.render()
        self.assertIn("UUID=" + GOOD["rootUuid"] + " / ext4", result["fstab"])
        self.assertIn("UUID=" + GOOD["espUuid"] + " /boot/efi vfat", result["fstab"])
        self.assertIn("search --no-floppy --fs-uuid --set=root AB12-CD34",
                      result["windowsGrubEntry"])
        self.assertIn("chainloader /EFI/Microsoft/Boot/bootmgfw.efi",
                      result["windowsGrubEntry"])
        self.assertEqual(result["releaseSafe"], "false")

    def test_deterministic(self):
        self.assertEqual(self.render(), self.render())

    def test_refuse_secure_boot(self):
        with self.assertRaises(uefi.PlanError):
            self.render(secureBootEnabled=True)

    def test_refuse_legacy_boot(self):
        with self.assertRaises(uefi.PlanError):
            self.render(firmware="bios")

    def test_refuse_cross_disk_windows_loader(self):
        with self.assertRaisesRegex(uefi.PlanError, "share"):
            self.render(windowsBootUuid="EF56-7890")

    def test_refuse_non_string_uuid(self):
        with self.assertRaises(uefi.PlanError):
            self.render(rootUuid=123)

    def test_refuse_ambiguous_guid_case(self):
        with self.assertRaises(uefi.PlanError):
            self.render(rootUuid="01234567-89AB-CDEF-0123-456789ABCDEF")

    def test_refuse_shell_injection(self):
        with self.assertRaises(uefi.PlanError):
            self.render(linuxLabel="CachyOS $(reboot)")

    def test_refuse_grub_injection(self):
        with self.assertRaises(uefi.PlanError):
            self.render(linuxLabel='CachyOS"\nchainloader /evil')

    def test_refuse_unknown_fields(self):
        with self.assertRaises(uefi.PlanError):
            self.render(adminMode=True)

    def test_refuse_boolean_version(self):
        with self.assertRaises(uefi.PlanError):
            self.render(version=True)

    def test_cli_stdout_is_non_destructive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(GOOD), encoding="utf-8")
            from subprocess import run
            result = run(["python3", str(MOD), str(path)], check=False,
                         text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["bootloaderId"], "Gaslux-CachyOS")
            self.assertEqual(list(Path(directory).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
