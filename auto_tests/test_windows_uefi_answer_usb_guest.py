"""Offline negative/positive UEFI GRUB FAT32 USB visibility witness contracts.

No host disk, QEMU guest, Microsoft media, local account, or mutation.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
SCRIPT = TOOLS / "windows_uefi_answer_usb_guest.py"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("guest_usb_probe", SCRIPT)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

READY = probe.READY + b"\n"
LABEL = probe.STAGES["LABEL"] + b"1\n"
XML = probe.STAGES["XML"] + b"1\n"
SCRIPT_OK = probe.STAGES["SCRIPT"] + b"1\n"
SUCCESS = probe.SUCCESS + b"\n"
VALID = READY + LABEL + XML + SCRIPT_OK + SUCCESS


class GuestUSBVisibilityTests(unittest.TestCase):
    def test_complete_ordered_uefi_witness_accepted_as_lab_only(self):
        self.assertTrue(probe.validate_witness(VALID))

    def test_positive_before_evidence_is_rejected(self):
        with self.assertRaisesRegex(probe.GuestUSBError, "after success"):
            probe.validate_witness(READY + SUCCESS + LABEL + XML + SCRIPT_OK)

    def test_positive_without_scan_is_rejected(self):
        with self.assertRaisesRegex(probe.GuestUSBError, "before guest scan"):
            probe.validate_witness(LABEL + XML + SCRIPT_OK + SUCCESS)

    def test_missing_label_xml_or_script_rejected(self):
        for stage in ("LABEL", "XML", "SCRIPT"):
            with self.subTest(stage=stage):
                data = VALID.replace(probe.STAGES[stage] + b"1",
                                     probe.STAGES[stage] + b"0")
                with self.assertRaisesRegex(probe.GuestUSBError,
                                            "lacks independently observed files"):
                    probe.validate_witness(data)

    def test_missing_file_witness_dominates_positive(self):
        with self.assertRaisesRegex(probe.GuestUSBError, "could not see"):
            probe.validate_witness(VALID + probe.FAILURE + b"\n")

    def test_duplicate_success_or_stage_rejected(self):
        for data in (VALID + SUCCESS, VALID + LABEL, VALID + READY):
            with self.subTest(data=data[-90:]):
                with self.assertRaisesRegex(probe.GuestUSBError,
                                            "ambiguous|duplicate"):
                    probe.validate_witness(data)

    def test_conflicting_zero_and_one_rejected(self):
        with self.assertRaisesRegex(probe.GuestUSBError, "ambiguous"):
            probe.validate_witness(VALID + probe.STAGES["XML"] + b"0\n")

    def test_prefixed_marker_is_not_a_guest_witness(self):
        data = READY + LABEL + XML + SCRIPT_OK + b"fake> " + probe.SUCCESS + b"\n"
        with self.assertRaisesRegex(probe.GuestUSBError, "unrecognized"):
            probe.validate_witness(data)

    def test_unknown_or_nonboolean_fields_fail_closed(self):
        for extra in (
            b"GASLUX_EFI_ANSWER_USB_EXTRA=1\n",
            b"GASLUX_EFI_ANSWER_USB_SCRIPT_FOUND=2\n",
            b"GASLUX_EFI_ANSWER_USB_LABEL_FOUND=11\n",
        ):
            with self.subTest(extra=extra):
                with self.assertRaises(probe.GuestUSBError):
                    probe.validate_witness(VALID + extra)

    def test_partial_output_remains_unproven(self):
        self.assertFalse(probe.validate_witness(READY + LABEL + XML + SCRIPT_OK))


if __name__ == "__main__":
    unittest.main()
