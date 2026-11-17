"""Read-only QEMU VGA telemetry tests: no Windows guest, disk or screenshot upload."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_vga_diagnostic.py"
SPEC = importlib.util.spec_from_file_location("win_vga_numeric", SOURCE)
assert SPEC and SPEC.loader
VGA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VGA)


def ppm(width: int, height: int, rgb: bytes) -> bytes:
    return f"P6\n{width} {height}\n255\n".encode("ascii") + rgb


class WindowsPrivateVgaTelemetryTests(unittest.TestCase):
    def test_black_display_numeric_only(self):
        result = VGA.numeric_ppm_stats(ppm(4, 4, b"\x00" * 48))
        self.assertEqual(result["width"], 4)
        self.assertEqual(result["height"], 4)
        self.assertEqual(result["nonBlackPercent"], 0)
        self.assertEqual(result["uniqueRgbSampleCount"], 1)
        self.assertEqual(result["dominantRgbPercent"], 100)
        self.assertEqual(set(result), {
            "width", "height", "sampleCount", "uniqueRgbSampleCount",
            "nonBlackPercent", "dominantRgbPercent"
        })

    def test_blue_display_numeric_only(self):
        result = VGA.numeric_ppm_stats(ppm(4, 4, bytes([0, 0, 190]) * 16))
        self.assertEqual(result["nonBlackPercent"], 100)
        self.assertEqual(result["uniqueRgbSampleCount"], 1)
        self.assertEqual(result["dominantRgbPercent"], 100)

    def test_mixed_display_fraction(self):
        result = VGA.numeric_ppm_stats(
            ppm(2, 2, bytes([0, 0, 0, 250, 250, 250,
                             0, 0, 0, 0, 0, 100]))
        )
        self.assertEqual(result["nonBlackPercent"], 50)
        self.assertEqual(result["uniqueRgbSampleCount"], 3)

    def test_unsupported_or_incomplete_format_rejected(self):
        for frame in (
            b"", b"P3\n2 2\n255\n" + b"0" * 50,
            ppm(2, 2, b"\x00" * 11), ppm(2, 2, b"\x00" * 13),
            b"P6\n0 4\n255\n", b"P6\n4097 1\n255\n",
            b"P6\n1 1\n250\n" + b"\x00" * 3,
            b"P6\n1 1\n255\n" + b"\x00" * (VGA.MAX_SCREEN_BYTES + 1),
        ):
            with self.subTest(frameSize=len(frame)):
                with self.assertRaises(VGA.LabError):
                    VGA.numeric_ppm_stats(frame)

    def test_unowned_hmp_socket_refused_before_snapshot(self):
        with self.assertRaisesRegex(VGA.LabError, "unowned QEMU monitor"):
            VGA.capture_owned_qemu_vga(
                Path("/tmp/not-our-hmp.sock"), Path("/tmp/diskless-vga-test.ppm")
            )

    def test_diskless_probe_reports_numeric_frames_only(self):
        source = (TOOLS / "windows_x64_original_dvd_com1_probe.py").read_text()
        self.assertIn("capture_owned_qemu_vga(", source)
        self.assertIn("first-stage-vga-early.ppm", source)
        self.assertIn("first-stage-vga-timeout.ppm", source)
        self.assertIn("GASLUX_ORIGINAL_WIN10_DVD_VGA_STATS_CHANGED_", source)
        self.assertIn("NOT TESTED: WinPE Setup, Windows installation", source)
        self.assertIn("out.unlink()", SOURCE.read_text())
        self.assertNotIn("WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=1", source)
        self.assertNotIn("boot_vm(", source)

    def test_vga_screendump_requires_private_owned_directory(self):
        source = SOURCE.read_text()
        self.assertIn('stat.S_IMODE(workspace.stat().st_mode) == 0o700', source)
        self.assertIn('workspace.stat().st_uid == os.getuid()', source)
        self.assertIn('monitor_path.name == "initial-installer-hmp.sock"', source)
        self.assertIn('out.name in ("first-stage-vga-early.ppm"', source)
        self.assertIn("if (out.is_file() and not out.is_symlink()", source)


if __name__ == "__main__":
    unittest.main()
