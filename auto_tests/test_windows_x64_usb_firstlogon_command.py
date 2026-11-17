"""FAT32 USB first-logon path and pinned witness SHA contracts.

No Windows ISO download, QEMU guest, mounted filesystem or host disk writes.
The historical proven FAT12 floppy FirstLogon path must remain untouched.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_tcg_firstboot.py"
SPEC = importlib.util.spec_from_file_location("windows_usb_firstlogon", SOURCE)
assert SPEC and SPEC.loader
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)

NAMESPACE = {"u": "urn:schemas-microsoft-com:unattend"}
PROFILES = (("win10_22h2_en_us_x64", "19045"),
            ("win11_26h2_en_us_x64", "26300"))


def first_logon_command(xml: bytes) -> str:
    root = ET.fromstring(xml)
    commands = root.findall(
        ".//u:FirstLogonCommands/u:SynchronousCommand/u:CommandLine",
        NAMESPACE
    )
    assert len(commands) == 1
    assert commands[0].text is not None
    return commands[0].text


class USBFirstLogonCommandContracts(unittest.TestCase):
    def test_windows_profiles_resolve_label_and_pin_exact_script_digest(self):
        for profile, build in PROFILES:
            with self.subTest(profile=profile):
                command = VM.usb_firstlogon_command(profile, build)
                generated = first_logon_command(
                    VM.generate_unattend(profile, build, usb_answer=True)
                )
                expected_script = (
                    VM.witness_powershell(profile, build) + "\n"
                ).encode("utf-8")
                sha256 = hashlib.sha256(expected_script).hexdigest()
                self.assertEqual(command, generated)
                self.assertIn(sha256, command)
                self.assertLess(len(command), 240)
                self.assertIn("Get-Volume -FileSystemL GASLUXCI", command)
                self.assertIn("if(@($v).Count-ne 1){throw}", command)
                self.assertIn("Get-FileHash $p", command)
                self.assertIn(";&$p\"", command)
                self.assertIn("-NoP -EP Bypass -C", command)
                self.assertNotIn("A:\\GASLUX.PS1", command)
                self.assertNotIn("C:\\", command)
                VM.validate_oobe_answer_pass(
                    VM.generate_unattend(profile, build, usb_answer=True)
                )

    def test_original_fat12_firstlogon_command_is_byte_identical(self):
        for profile, build in PROFILES:
            with self.subTest(profile=profile):
                original = VM.generate_unattend(profile, build)
                explicit_floppy = VM.generate_unattend(
                    profile, build, usb_answer=False
                )
                self.assertEqual(original, explicit_floppy)
                self.assertEqual(
                    first_logon_command(original),
                    "powershell.exe -NoProfile -NonInteractive "
                    "-ExecutionPolicy Bypass -File A:\\GASLUX.PS1",
                )

    def test_modified_witness_payload_changes_pinned_sha(self):
        for profile, build in PROFILES:
            with self.subTest(profile=profile):
                original = VM.usb_firstlogon_command(profile, build)
                with patch.object(
                    VM, "witness_powershell",
                    return_value="a different deliberately untrusted script",
                ):
                    altered = VM.usb_firstlogon_command(profile, build)
                self.assertNotEqual(original, altered)
                self.assertIn(hashlib.sha256(
                    b"a different deliberately untrusted script\n"
                ).hexdigest(), altered)

    def test_usb_answer_mode_passed_before_media_write_and_boot(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('usb_answer=args.two_stage_install_only', source)
        self.assertLess(
            source.index('usb_answer=args.two_stage_install_only'),
            source.index('xmlfile = workspace / "Autounattend.xml"'),
        )
        self.assertLess(
            source.index('usb_answer=args.two_stage_install_only'),
            source.index('disk = workspace / "only-disposable-windows-target.qcow2"'),
        )
        self.assertIn('f"if=none,id=lab_unattend,format=raw,readonly=on,file={answer}"',
                      source)

    def test_reject_duplicate_ambiguous_missing_volume_or_hash(self):
        for profile, build in PROFILES:
            cmd = VM.usb_firstlogon_command(profile, build)
            self.assertIn("if(@($v).Count-ne 1){throw}", cmd)
            self.assertIn("if((Get-FileHash $p).Hash-ne '", cmd)
            self.assertIn("'){throw};&$p\"", cmd)
            self.assertEqual(cmd.count("GASLUXCI"), 1)
            self.assertEqual(cmd.count("Get-FileHash"), 1)

    def test_host_and_release_acceptance_gates_not_weakened(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('report["windowsClientBootVerified"] = ok', source)
        self.assertIn('"dualBootVerified": False', source)
        self.assertIn('"winReAndBcdRecovered": False', source)
        self.assertIn('if not ok:', source)
        self.assertIn('raise LabError(diagnostic)', source)
        self.assertNotIn('report["windowsClientBootVerified"] = True', source)


if __name__ == "__main__":
    unittest.main()
