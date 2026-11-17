"""No-guest safety tests for two private numeric-only WinPE VGA snapshots.

No ISO, QEMU, physical disk, image upload, storage mutation or OCR.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_winpe_vga_diagnostic.py"
spec = importlib.util.spec_from_file_location("winpe_numeric_vga", SOURCE)
assert spec and spec.loader
VGA = importlib.util.module_from_spec(spec)
spec.loader.exec_module(VGA)


def ppm(w: int, h: int, rgb: bytes) -> bytes:
    return f"P6\n{w} {h}\n255\n".encode("ascii") + rgb


class OwnedWinPENumericVga(unittest.TestCase):
    def test_synthetic_black_frame_only_reports_numeric_stats(self):
        summary = VGA.numeric_ppm_stats(ppm(4, 4, bytes(48)))
        self.assertEqual(summary["nonBlackPercent"], 0)
        self.assertEqual(summary["uniqueRgbSampleCount"], 1)
        self.assertEqual(summary["dominantRgbPercent"], 100)
        self.assertEqual(set(summary), {
            "width", "height", "sampleCount", "uniqueRgbSampleCount",
            "nonBlackPercent", "dominantRgbPercent",
        })

    def test_synthetic_white_frame_only_reports_numeric_stats(self):
        summary = VGA.numeric_ppm_stats(ppm(4, 4, bytes([255] * 48)))
        self.assertEqual(summary["width"], 4)
        self.assertEqual(summary["height"], 4)
        self.assertEqual(summary["nonBlackPercent"], 100)
        self.assertEqual(summary["uniqueRgbSampleCount"], 1)

    def test_synthetic_two_colour_samples(self):
        frame = ppm(2, 2, bytes([0, 0, 0, 255, 0, 0,
                                  0, 0, 0, 255, 0, 0]))
        summary = VGA.numeric_ppm_stats(frame)
        self.assertEqual(summary["uniqueRgbSampleCount"], 2)
        self.assertEqual(summary["nonBlackPercent"], 50)

    def test_incomplete_or_oversized_ppm_is_rejected(self):
        candidates = (
            b"", b"P3\n2 2\n255\n" + bytes(12),
            ppm(2, 2, bytes(11)), ppm(2, 2, bytes(13)),
            b"P6\n0 2\n255\n",
            b"P6\n4097 1\n255\n",
            b"P6\n1 1\n250\n" + bytes(3),
        )
        for frame in candidates:
            with self.subTest(bytes=len(frame)):
                with self.assertRaises(VGA.LabError):
                    VGA.numeric_ppm_stats(frame)

    def test_foreign_hmp_socket_refused_before_capture(self):
        with self.assertRaisesRegex(VGA.LabError, "unowned diskless"):
            VGA.capture_owned_qemu_vga(
                Path("/tmp/foreign/initial-installer-hmp.sock"),
                Path("/tmp/foreign/winpe-vga-early.ppm"),
            )

    def test_private_two_level_runner_ownership_contract(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('workspace.name in ("fat12_floppy", "fat32_usb")', source)
        self.assertIn('parent.parent == Path("/home/runner/work/_temp")', source)
        self.assertIn('stat.S_IMODE(parent.stat().st_mode) == 0o700', source)
        self.assertIn('stat.S_IMODE(workspace.stat().st_mode) == 0o700', source)
        self.assertIn('monitor_path.name == "initial-installer-hmp.sock"', source)
        self.assertIn('monitor_path.is_socket() and not monitor_path.is_symlink()', source)

    def test_only_two_bounded_fresh_screenshot_names_and_immediate_unlink(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('"winpe-vga-early.ppm"', source)
        self.assertIn('"winpe-vga-late.ppm"', source)
        self.assertIn('not out.exists() and not out.is_symlink()', source)
        self.assertIn('out.unlink()', source)
        self.assertIn('MAX_SCREEN_BYTES = 16 * 1024 * 1024', source)
        self.assertIn("QEMU VGA HMP response exceeded allowed size", source)

    def test_diagnostic_cannot_be_misread_as_firstboot_or_release(self):
        source = (TOOLS / "windows_x64_winpe_answer_probe.py").read_text()
        self.assertIn('windowsClientBootVerified": False', source)
        self.assertIn('storageWritesAuthorized": False', source)
        self.assertIn('dualBootVerified": False', source)
        self.assertIn('require(result["fat12_floppy"]', source)
        self.assertIn('require(result["fat32_usb"]', source)
        self.assertNotIn("windowsClientBootVerified=true", source)


if __name__ == "__main__":
    unittest.main()
