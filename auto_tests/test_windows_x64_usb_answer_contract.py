"""Microsoft-documented removable-USB Windows answer-file experiment.

No guest or host disks are created by these no-write contract tests.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest
import xml.etree.ElementTree as ET

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "windows_usb_answer", TOOLS / "windows_x64_tcg_firstboot.py")
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)

NS = {"u": "urn:schemas-microsoft-com:unattend"}


class WindowsUsbAnswerContracts(unittest.TestCase):
    def test_firstlogon_discovers_unique_usb_letter_not_assuming_a(self):
        for profile, build in (
            ("win10_22h2_en_us_x64", "19045"),
            ("win11_26h2_en_us_x64", "26300"),
        ):
            with self.subTest(profile=profile):
                xml = ET.fromstring(vm.generate_unattend(profile, build))
                value = xml.find(
                    ".//u:FirstLogonCommands/u:SynchronousCommand/u:CommandLine", NS
                ).text
                self.assertIn("Get-Volume -FileSystemLabel GASLUXCI", value)
                self.assertIn("$v.Count -ne 1", value)
                self.assertIn("exit 20", value)
                self.assertIn("GASLUX.PS1", value)
                self.assertNotIn("-File A:", value)
                self.assertLess(len(value), 240)

    def test_fat32_usb_does_not_replace_windows_disk_or_bootloader(self):
        source = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        for phrase in (
            'only-disposable-answer-usb.img',
            '["truncate", "-s", "64M", str(usb)]',
            '["mkfs.vfat", "-F", "32", "-n", "GASLUXCI", str(usb)]',
            '"::/Autounattend.xml"',
            '"::/GASLUX.PS1"',
            'if=none,id=lab_unattend,format=raw,readonly=on,file={usb}',
            'usb-storage,drive=lab_unattend,bus=lab_usb.0',
            'only-disposable-windows-target.qcow2',
            'if=none,id=only_windows,format=qcow2,file={disk}',
        ):
            self.assertIn(phrase, source)
        for banned in (
            "if=floppy", "file=/dev/sda", "file=/dev/nvme",
            "bcdedit /delete", "reagentc /enable",
        ):
            self.assertNotIn(banned, source)

    def test_windows_boot_acceptance_remains_independent_of_usb(self):
        source = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        for marker in (
            '"windowsClientBootVerified": False',
            '"winReAndBcdRecovered": False',
            '"dualBootVerified": False',
            '"stable": False',
            'GASLUX_WINDOWS_X64_WINRE_ENABLED=1',
            'GASLUX_WINDOWS_X64_BCD_ENUMERATED=1',
            'QEMU exited before installed Windows first-logon witness',
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
