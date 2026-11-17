"""Fail-closed tests for a real but VM-only Windows evaluation TCG installer.

Tests only XML and contracts: never download Windows or boot a guest.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "auto_tests/tools/windows_x64_tcg_firstboot.py"
HOST = ROOT / "auto_tests/tools/windows_x64_qemu_host_gate.py"

spec = importlib.util.spec_from_file_location("gaslux_windows_tcg", SRC)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
sys.path.insert(0, str(SRC.parent))
spec.loader.exec_module(module)
NS = {"u": "urn:schemas-microsoft-com:unattend"}


class WindowsX64RealTcgContracts(unittest.TestCase):
    def test_unattended_xml_valid_for_two_real_client_profiles(self):
        for key, prefix in (("win10_22h2_en_us_x64", "19045"),
                            ("win11_26h2_en_us_x64", "26300")):
            with self.subTest(profile=key):
                xml = module.generate_unattend(key, prefix)
                root = ET.fromstring(xml)
                self.assertEqual(root.tag,
                                 "{urn:schemas-microsoft-com:unattend}unattend")
                self.assertEqual(
                    len(root.findall(".//u:DiskConfiguration/u:Disk", NS)), 1)
                self.assertEqual(
                    [i.text for i in root.findall(".//u:Disk/u:DiskID", NS)], ["0"])
                self.assertEqual(
                    [i.text for i in root.findall(".//u:Disk/u:WillWipeDisk", NS)],
                    ["true"])
                self.assertEqual(
                    [p.text for p in root.findall(".//u:CreatePartition/u:Type", NS)],
                    ["EFI", "MSR", "Primary", "Primary"])
                self.assertEqual(
                    [i.text for i in root.findall(".//u:InstallTo/u:PartitionID", NS)],
                    ["3"])
                command = root.find(".//u:FirstLogonCommands/u:SynchronousCommand/u:CommandLine",
                                    NS)
                self.assertIsNotNone(command)
                self.assertIn("powershell.exe", command.text)
                self.assertIn("-File A:\\GASLUX.PS1", command.text)
                self.assertNotIn("-EncodedCommand", command.text)
                self.assertLess(len(command.text), 240,
                                "first logon command must not hit setup length limit")
                self.assertIn("GASLUX", module.witness_powershell(key, prefix))
                self.assertIn(module.MARKER, module.witness_powershell(key, prefix))
                self.assertIn("ProductType -ne 1", module.witness_powershell(key, prefix))
                self.assertIn("Get-Partition", module.witness_powershell(key, prefix))
                self.assertIn("reagentc /info", module.witness_powershell(key, prefix))
                self.assertIn("Windows RE status:", module.witness_powershell(key, prefix))
                self.assertIn("GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
                              module.witness_powershell(key, prefix))
                self.assertIn("bcdedit /enum", module.witness_powershell(key, prefix))
                self.assertNotIn("bcdedit /set", module.witness_powershell(key, prefix))

    def test_oobe_international_defaults_present_for_real_win10_and_win11(self):
        for profile, build in (("win10_22h2_en_us_x64", "19045"),
                               ("win11_26h2_en_us_x64", "26300")):
            with self.subTest(profile=profile):
                xml = module.generate_unattend(profile, build)
                module.validate_oobe_answer_pass(xml)
                root = ET.fromstring(xml)
                passes = [x for x in root.findall("u:settings", NS)
                          if x.attrib.get("pass") == "oobeSystem"]
                self.assertEqual(len(passes), 1)
                international = [c for c in passes[0].findall("u:component", NS)
                                 if c.attrib.get("name") ==
                                 "Microsoft-Windows-International-Core"]
                self.assertEqual(len(international), 1)
                for name in ("InputLocale", "SystemLocale", "UILanguage",
                             "UserLocale"):
                    self.assertEqual(
                        international[0].find("u:" + name, NS).text, "en-US")
                self.assertNotIn(b"SkipMachineOOBE", xml)
                self.assertNotIn(b"SkipUserOOBE", xml)

    def test_incomplete_oobe_locale_refused_before_vm_start(self):
        xml = module.generate_unattend("win10_22h2_en_us_x64", "19045")
        root = ET.fromstring(xml)
        oobe = next(x for x in root.findall("u:settings", NS)
                    if x.attrib.get("pass") == "oobeSystem")
        international = next(c for c in oobe.findall("u:component", NS)
                             if c.attrib.get("name") ==
                             "Microsoft-Windows-International-Core")
        for name in ("InputLocale", "SystemLocale", "UILanguage",
                     "UserLocale"):
            with self.subTest(removed=name):
                child = international.find("u:" + name, NS)
                international.remove(child)
                with self.assertRaisesRegex(module.LabError,
                                            "Windows OOBE " + name):
                    module.validate_oobe_answer_pass(ET.tostring(root))
                international.append(child)

    def test_repeated_or_skipped_oobe_pass_refused(self):
        xml = module.generate_unattend("win11_26h2_en_us_x64", "26300")
        root = ET.fromstring(xml)
        oobe = next(x for x in root.findall("u:settings", NS)
                    if x.attrib.get("pass") == "oobeSystem")
        repeated = ET.fromstring(ET.tostring(oobe))
        root.append(repeated)
        with self.assertRaisesRegex(module.LabError, "ambiguous"):
            module.validate_oobe_answer_pass(ET.tostring(root))
        root.remove(repeated)
        ET.SubElement(oobe, "{urn:schemas-microsoft-com:unattend}SkipMachineOOBE"
                      ).text = "true"
        with self.assertRaisesRegex(module.LabError, "skip directives"):
            module.validate_oobe_answer_pass(ET.tostring(root))

    def test_fixture_only_never_downloads_or_boots(self):
        for profile in module.EXPECTED:
            proc = subprocess.run(
                [sys.executable, str(SRC), "--profile", profile, "--fixture-only"],
                capture_output=True, text=True, timeout=8,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('"windowsClientBootVerified": false', proc.stdout)

    def test_firstlogon_script_is_owned_usb_and_has_valid_serial_constructor(self):
        src = SRC.read_text()
        media = (SRC.parent / "windows_x64_partitioned_answer_usb.py").read_text()
        self.assertIn('guest_ps1 = workspace / "GASLUX.PS1"', src)
        self.assertIn('build_partitioned_answer(answer, xmlfile, guest_ps1)', src)
        self.assertIn('"::/GASLUX.PS1"', media)
        self.assertIn('"::/Autounattend.xml"', media)
        self.assertIn("firstLogonScriptSha256", src)
        self.assertIn("[System.IO.Ports.SerialPort]::new(", 
                      module.witness_powershell("win10_22h2_en_us_x64", "19045"))
        self.assertNotIn("New-Object System.IO.Ports.SerialPort(",
                         module.witness_powershell("win10_22h2_en_us_x64", "19045"))
        self.assertNotIn('bcdedit /set', module.witness_powershell(
            "win11_26h2_en_us_x64", "26300"))

    def test_boot_is_tcg_nonphysical_only(self):
        code = SRC.read_text()
        for value in ("q35,accel=tcg,smm=on", "only-disposable-windows-target.qcow2",
                      "fif=none", "if=none,id=only_windows", "if=pflash",
                      "GASLUX_WINDOWS_TCG_CONSENT", "GASLUX_WINDOWS_EVIDENCE",
                      "GITHUB_REPOSITORY", "if=none,id=lab_unattend", "swtpm",
                      "MicrosoftOnlyRedirect", "digest.hexdigest() == expected",
                      "Get-CimInstance", "Win32_OperatingSystem"):
            if value == "fif=none":
                continue
            self.assertIn(value, code)
        # The controlled A/B mode deliberately switches FAT12 floppy to
        # one file-backed, read-only FAT32 USB. Preserve host-disk bans.
        self.assertIn("usb-storage,drive=lab_unattend,bus=lab_usb.0,removable=on", code)
        self.assertIn("readonly=on,file={answer}", code)
        self.assertNotIn("if=floppy,format=raw", code)
        for banned in ("if=ide,file=/dev/", "if=none,file=/dev/",
                       "file=/dev/sda", "file=/dev/nvme",
                       "--skippgpcheck", "bcdedit /delete",
                       "SigLevel = Never", "-accel kvm", "dev/shm/"):
            self.assertNotIn(banned, code)

    def test_unexpected_microsoft_redirects_fail_closed(self):
        class Request:
            pass
        redirect = module.MicrosoftOnlyRedirect()
        for url in ("http://software-static.download.prss.microsoft.com/file.iso",
                    "https://login.evil.org/windows.iso",
                    "https://software-static.download.prss.microsoft.com.evil.org/file.iso"):
            with self.subTest(url=url):
                with self.assertRaises(module.LabError):
                    redirect.redirect_request(Request(), None, 302, "redirect", {}, url)

    def test_without_explicit_hosted_consent_no_setup(self):
        env = {key: value for key, value in os.environ.items()
               if key not in ("GASLUX_WINDOWS_TCG_CONSENT", "GITHUB_ACTIONS",
                              "RUNNER_OS", "GITHUB_REPOSITORY")}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(module.LabError):
                    module.validate_environment(Path(tmp))

    def test_setup_command_limits_windows_disk_number_zero(self):
        xml = module.generate_unattend("win10_22h2_en_us_x64", "19045")
        self.assertNotIn(b"<DiskID>1</DiskID>", xml)
        self.assertNotIn(b"<DiskID>2</DiskID>", xml)
        self.assertNotIn(b"<WillWipeDisk>false</WillWipeDisk>", xml)
        self.assertNotIn(b"<DiskID>0</DiskID><DiskID>0</DiskID>", xml)
        self.assertNotIn(b"Linux", xml)

    def test_iso_download_is_pinned_independently(self):
        source = SRC.read_text()
        self.assertIn("load_catalog()", source)
        self.assertIn("MIN_ISO_SIZE", source)
        self.assertIn("MAX_ISO_SIZE", source)
        self.assertIn("digest.hexdigest() == expected", source)
        self.assertIn("refusing to overwrite ISO", source)
        self.assertNotIn("verify=False", source)
        self.assertNotIn("ssl._create_unverified_context", source)

    def test_firstboot_marker_not_accepted_from_qemu_exit(self):
        source = SRC.read_text()
        self.assertIn("QEMU exited before installed Windows first-logon witness", source)
        self.assertIn("GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1", source)
        self.assertIn("GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1", source)
        self.assertIn("GASLUX_WINDOWS_X64_BCD_ENUMERATED=1", source)
        self.assertIn("GASLUX_WINDOWS_X64_WINRE_ENABLED=1", source)
        self.assertIn("GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1", source)
        self.assertIn("proc.kill()", source)


if __name__ == "__main__":
    unittest.main()
