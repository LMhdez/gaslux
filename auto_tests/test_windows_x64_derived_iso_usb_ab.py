"""Controlled derived-ISO FAT12-vs-FAT32 answer-media A/B safety contracts.

No Microsoft ISO, QEMU guest, host block device, or disk mutation.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SRC = TOOLS / "windows_x64_tcg_firstboot.py"
spec = importlib.util.spec_from_file_location("windows_usb_ab", SRC)
assert spec and spec.loader
VM = importlib.util.module_from_spec(spec)
spec.loader.exec_module(VM)


class DerivedIsoUsbABTest(unittest.TestCase):
    def test_only_readonly_file_backed_answer_usb_in_source(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn('answer = workspace / "only-disposable-answer-usb.img"', source)
        self.assertIn('build_partitioned_answer(answer, xmlfile, guest_ps1)', source)
        self.assertIn('from windows_x64_partitioned_answer_usb import', source)
        self.assertIn('f"if=none,id=lab_unattend,format=raw,readonly=on,file={answer}"',
                      source)
        self.assertIn('"usb-storage,drive=lab_unattend,bus=lab_usb.0,removable=on"', source)
        self.assertNotIn('if=floppy,format=raw,file=', source)
        self.assertIn('boot_iso = derived', source)
        self.assertIn('GASLUX_MICROSOFT_VERIFIED_SOURCE_TO_LAB_NOPROMPT_DERIVATIVE=1',
                      source)

    def test_unattend_and_guest_script_remain_on_the_same_owned_image(self):
        source = SRC.read_text(encoding="utf-8")
        image_helper = (TOOLS / "windows_x64_partitioned_answer_usb.py").read_text()
        self.assertIn('"@@1M"', image_helper)
        self.assertIn('["mcopy", "-i", str(image) + "@@1M", str(xml)', image_helper)
        self.assertIn('["mcopy", "-i", str(image) + "@@1M", str(powershell)', image_helper)
        self.assertIn('and not image.exists() and not image.is_symlink()', image_helper)
        self.assertIn('guest_ps1.write_text(', source)
        self.assertIn('if (@($serialProof).Count -ne 7)', source)

    def test_second_guest_detaches_only_dvd_and_keeps_readonly_answer_usb(self):
        original = [
            "qemu-system-x86_64", "-boot", "order=dc",
            "-monitor", "none", "-serial", "file:/tmp/second-serial.log",
            "-drive",
            "if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file=/tmp/derived.iso",
            "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
            "-drive", "if=none,id=only_windows,format=qcow2,file=/tmp/new-disk.qcow2",
            "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
            "-drive",
            "if=none,id=lab_unattend,format=raw,readonly=on,file=/tmp/owned-usb.img",
            "-device", "usb-storage,drive=lab_unattend,bus=lab_usb.0,removable=on",
        ]
        first, second = VM.build_two_stage_qemu_args(
            original, Path("/tmp/initial-serial.log"))
        self.assertIn("order=d", first)
        self.assertIn("order=c", second)
        self.assertIn("-no-reboot", first)
        self.assertNotIn("-no-reboot", second)
        self.assertTrue(any("id=verified_iso" in x for x in first))
        self.assertFalse(any("verified_iso" in x for x in second))
        for stage in (first, second):
            self.assertEqual(sum("id=lab_unattend" in a for a in stage), 1)
            self.assertIn("usb-storage,drive=lab_unattend,bus=lab_usb.0,removable=on", stage)
            self.assertFalse(any("if=floppy" in a for a in stage))
            self.assertEqual(sum("readonly=on,file=/tmp/owned-usb.img" in a
                                 for a in stage), 1)

    def test_explicit_removable_flag_only_on_owned_readonly_usb(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertEqual(
            source.count(
                '"usb-storage,drive=lab_unattend,bus=lab_usb.0,removable=on"'
            ), 1)
        self.assertIn("readonly=on,file={answer}", source)
        self.assertIn("build_partitioned_answer(answer, xmlfile, guest_ps1)",
                      source)
        self.assertIn("boot_iso = derived", source)
        self.assertNotIn("removable=off", source)

    def test_source_has_no_relaxed_windows_firstboot_gate(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn('report["windowsClientBootVerified"] = ok', source)
        self.assertIn('if not ok:', source)
        self.assertIn('raise LabError(diagnostic)', source)
        self.assertIn('"dualBootVerified": False', source)
        self.assertIn('"winReAndBcdRecovered": False', source)
        self.assertNotIn('report["windowsClientBootVerified"] = True', source)


if __name__ == "__main__":
    unittest.main()
