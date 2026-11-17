"""No-write regressions for diagnostic VGA capture during Windows VM first boot.

Simulates QEMU timing and HMP display responses; never boots Windows or touches
any real disk. An image can never establish a Windows/WinRE boot witness.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_tcg_firstboot.py"
spec = importlib.util.spec_from_file_location("windows_firstboot_vga", SOURCE)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
import windows_x64_uefi_visual_probe as visual  # noqa: E402


class FakeQemu:
    killed = False

    def poll(self):
        return -9 if self.killed else None

    def kill(self):
        self.killed = True

    def wait(self, timeout):
        return -9


class FirstbootVGATests(unittest.TestCase):
    def run_probe(self, fail_frames=False):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            serial = directory / "guest-serial.log"
            serial.write_bytes(vm.BOOT_FROM_CD_PROMPT + b"\n")
            frames = []
            monitor = directory / "initial-installer-hmp.sock"
            fake = FakeQemu()

            def screenshot(monitor_path, evidence, profile, label):
                self.assertEqual(monitor_path, monitor)
                self.assertEqual(evidence, directory)
                self.assertEqual(profile, "win10_22h2_en_us_x64")
                if fail_frames:
                    raise visual.ProbeError("test-only invalid VGA frame")
                return {"file": label + ".ppm", "sha256": "a" * 64, "bytes": 42}

            ticks = iter(range(0, 12000, 180))
            with (
                patch.object(vm.subprocess, "Popen", return_value=fake),
                patch.object(vm.time, "monotonic", side_effect=lambda: next(ticks)),
                patch.object(vm.time, "sleep", return_value=None),
                patch.object(vm, "send_first_iso_boot_key") as sendkey,
                patch.object(visual, "snapshot", side_effect=screenshot) as capture,
            ):
                accepted, detail = vm.boot_vm(
                    ["qemu-system-x86_64"], serial, 2200, "win10_22h2_en_us_x64",
                    monitor_socket=monitor, progress_evidence=directory,
                    progress_frames=frames,
                )
            self.assertFalse(accepted)
            self.assertIn("timed out", detail)
            self.assertTrue(fake.killed)
            sendkey.assert_called_once_with(monitor)
            self.assertEqual(
                [call.args[3] for call in capture.call_args_list],
                ["03-firstboot-early", "04-firstboot-middle",
                 "05-firstboot-late"],
            )
            return frames

    def test_three_hashed_diagnostic_frames_never_mark_windows_boot(self):
        frames = self.run_probe()
        self.assertEqual(len(frames), 3)
        self.assertTrue(all(len(image["sha256"]) == 64 for image in frames))

    def test_unavailable_display_does_not_create_boot_evidence(self):
        self.assertEqual(self.run_probe(fail_frames=True), [])

    def test_screenshot_allowlist_excludes_arbitrary_file_names(self):
        for label in ("../../host", "06-extra", "EFI/Microsoft", "sendkey"):
            self.assertNotIn(label, visual.LABELS)

    def test_only_safe_finite_frame_labels_are_allowed(self):
        self.assertEqual(
            visual.LABELS[3:],
            ("03-firstboot-early", "04-firstboot-middle",
             "05-firstboot-late"),
        )


if __name__ == "__main__":
    unittest.main()
