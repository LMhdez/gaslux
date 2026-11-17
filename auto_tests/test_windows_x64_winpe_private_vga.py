"""Diskless VGA telemetry: numeric parsing, private ownership, no screenshot leak."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location(
    "winpe_vga_numeric", TOOLS / "windows_x64_winpe_private_vga.py")
assert SPEC and SPEC.loader
VGA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VGA)


def ppm(w=3, h=2, pixels=b"\0\0\0" * 6):
    return f"P6\n{w} {h}\n255\n".encode("ascii") + pixels


class WinpeVGASafety(unittest.TestCase):
    def test_black_frame_is_numeric_only(self):
        data = VGA.numeric_ppm(ppm())
        self.assertEqual(data["width"], 3)
        self.assertEqual(data["height"], 2)
        self.assertEqual(data["uniqueRgbSampleCount"], 1)
        self.assertEqual(data["nonBlackPercent"], 0)
        self.assertEqual(data["dominantRgbPercent"], 100)

    def test_frame_color_change_detectable_without_pixel_output(self):
        mixed = VGA.numeric_ppm(
            ppm(pixels=(b"\0\0\0" * 3 + b"\xff\xff\xff" * 3)))
        self.assertEqual(mixed["uniqueRgbSampleCount"], 2)
        self.assertEqual(mixed["nonBlackPercent"], 50)
        self.assertEqual(mixed["sampleCount"], 6)

    def test_incomplete_oversized_and_wrong_format_rejected(self):
        samples = (b"", b"P3\n3 2\n255\n" + b"0" * 18,
                   ppm(pixels=b"\0" * 17), b"Q" * (VGA.MAX_SCREEN_BYTES + 1),
                   ppm(0, 2, b""))
        for example in samples:
            with self.subTest(size=len(example)):
                with self.assertRaises(VGA.LabError):
                    VGA.numeric_ppm(example)

    def test_unowned_workspaces_rejected_before_hmp(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch) / "fat12_floppy"
            work.mkdir()
            with self.assertRaisesRegex(VGA.LabError, "unowned WinPE"):
                VGA.verify_owned_paths(
                    work, work / "winpe-hmp.sock",
                    work / "winpe-vga-early.ppm")

    def test_unapproved_screenshot_basename_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch) / "fat32_usb"
            work.mkdir()
            with self.assertRaisesRegex(VGA.LabError, "unowned WinPE"):
                VGA.verify_owned_paths(
                    work, work / "winpe-hmp.sock",
                    work / "user-data.ppm")

    def test_capture_has_bounded_hmp_and_finally_delete(self):
        code = (TOOLS / "windows_x64_winpe_private_vga.py").read_text()
        self.assertIn('while len(response) < 131072', code)
        self.assertIn('conn.settimeout(5)', code)
        self.assertIn('stat.S_IMODE(root.stat().st_mode) == 0o700', code)
        self.assertIn('stat.S_IMODE(work.stat().st_mode) == 0o700', code)
        self.assertIn('screenshot.unlink()', code)
        self.assertIn('finally:', code)
        self.assertIn('screenshot.stat().st_nlink == 1', code)
        self.assertNotIn('upload-artifact', code)


if __name__ == "__main__":
    unittest.main()
