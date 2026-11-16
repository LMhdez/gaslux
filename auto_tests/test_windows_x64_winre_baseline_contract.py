"""Windows 10/11 virtual UEFI/GPT WinRE baseline, no real disks touched."""
from __future__ import annotations

import importlib.util
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "auto_tests/tools/windows_x64_tcg_firstboot.py"
sys.path.insert(0, str(FILE.parent))
spec = importlib.util.spec_from_file_location("gaslux_winre_tcg", FILE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NS = {"u": "urn:schemas-microsoft-com:unattend"}


class WindowsClientGPTWinREContracts(unittest.TestCase):
    def test_microsoft_esp_msr_windows_winre_partition_sequence(self):
        for key, build in (
            ("win10_22h2_en_us_x64", "19045"),
            ("win11_26h2_en_us_x64", "26300"),
        ):
            with self.subTest(key=key):
                xml = module.generate_unattend(key, build)
                root = ET.fromstring(xml)
                parts = root.findall(".//u:CreatePartition", NS)
                self.assertEqual(len(parts), 4)
                types = [p.find("u:Type", NS).text for p in parts]
                self.assertEqual(types, ["EFI", "MSR", "Primary", "Primary"])
                sizes = [int(p.find("u:Size", NS).text) for p in parts]
                self.assertEqual(sizes, [260, 16, 73728, 1536])
                self.assertTrue(all(p.find("u:Extend", NS) is None for p in parts))
                modifications = root.findall(".//u:ModifyPartition", NS)
                self.assertEqual(len(modifications), 3)
                self.assertEqual(
                    [p.find("u:PartitionID", NS).text for p in modifications],
                    ["1", "3", "4"])
                self.assertEqual(
                    [p.find("u:Format", NS).text for p in modifications],
                    ["FAT32", "NTFS", "NTFS"])
                self.assertIsNone(modifications[0].find("u:TypeID", NS))
                self.assertIsNone(modifications[1].find("u:TypeID", NS))
                self.assertEqual(
                    modifications[2].find("u:TypeID", NS).text,
                    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC")
                self.assertIsNone(
                    modifications[2].find("u:Letter", NS),
                    "recovery partition must have no user drive letter")
                self.assertEqual(
                    [p.text for p in root.findall(".//u:InstallTo/u:PartitionID", NS)],
                    ["3"])
                self.assertEqual(
                    [p.text for p in root.findall(".//u:Disk/u:WillWipeDisk", NS)],
                    ["true"])
                self.assertEqual(
                    [p.text for p in root.findall(".//u:Disk/u:DiskID", NS)],
                    ["0"])

    def test_running_windows_proves_enabled_recovery_not_just_command_exit(self):
        for key, build in (
            ("win10_22h2_en_us_x64", "19045"),
            ("win11_26h2_en_us_x64", "26300"),
        ):
            with self.subTest(key=key):
                witness = module.witness_powershell(key, build)
                self.assertIn("Get-Partition -DiskNumber 0", witness)
                self.assertIn("{de94bba4-06d1-4d40-a16a-bfd50179d6ac}",
                              witness)
                self.assertIn("reagentc /info", witness)
                self.assertIn("Windows RE status:", witness)
                self.assertIn("WinRE is missing, disabled or unverifiable", witness)
                self.assertIn("GASLUX_WINDOWS_X64_WINRE_ENABLED=1", witness)
                self.assertIn("GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1", witness)
                self.assertIn("bcdedit /enum '{bootmgr}'", witness)
                self.assertIn("Get-CimInstance -ClassName Win32_OperatingSystem",
                              witness)
                self.assertNotIn("reagentc /enable", witness)
                self.assertNotIn("diskpart", witness.lower())

    def test_linux_reserved_unallocated_space_not_claimed_stable(self):
        self.assertEqual(module.VM_SIZE, "128G")
        used_mb = 260 + 16 + module.WINDOWS_PRIMARY_MB + module.WINRE_PARTITION_MB
        unused_mb = 128 * 1024 - used_mb
        self.assertGreater(unused_mb, 45 * 1024)
        source = FILE.read_text()
        self.assertIn("windowsClientBootVerified", source)
        self.assertIn("winReAndBcdRecovered", source)
        self.assertIn('"winReAndBcdRecovered": False', source)
        self.assertIn('"dualBootVerified": False', source)
        self.assertIn('"stable": False', source)
        for forbidden in (
            "/dev/sda", "/dev/nvme", "reagentc /enable",
            "bcdedit /set", "bcdedit /delete", "shrink-volume",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
