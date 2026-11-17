"""Fail-closed timeout diagnostics for disposable Windows Setup, no guest/disk."""
from __future__ import annotations

import importlib.util
import io
import pathlib
import sys
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SRC = TOOLS / "windows_x64_tcg_firstboot.py"
SPEC = importlib.util.spec_from_file_location("windows_stage1_timeout", SRC)
assert SPEC and SPEC.loader
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)


class FakeDisk:
    name = "only-disposable-windows-target.qcow2"
    parent = pathlib.Path("/home/runner/work/_temp/gaslux-win-x64-mock")

    def __init__(self, *, blocks=600000):
        self.blocks = blocks

    def is_file(self):
        return True

    def is_symlink(self):
        return False

    def stat(self):
        return SimpleNamespace(st_blocks=self.blocks)


class WindowsStalledPantherTests(unittest.TestCase):
    def setUp(self):
        self.disk = FakeDisk()
        self.process = SimpleNamespace(poll=lambda: -9)

    def test_inspector_called_only_on_stopped_guest(self):
        seen = []
        output = io.StringIO()
        with redirect_stdout(output):
            value = VM.diagnose_stalled_windows_stage(
                self.disk, self.process, 0, lambda disk: seen.append(disk))
        self.assertIsNone(value)
        self.assertEqual(seen, [self.disk])
        self.assertIn("GASLUX_WINDOWS_STAGE1_STALLED_QCOW2_GROWTH_HEURISTIC=1",
                      output.getvalue())
        self.assertNotIn("FIRSTBOOT_PASS", output.getvalue())

    def test_running_guest_refuses_inspection(self):
        seen = []
        running = SimpleNamespace(poll=lambda: None)
        with self.assertRaisesRegex(VM.LabError, "must be stopped"):
            VM.diagnose_stalled_windows_stage(
                self.disk, running, 0, lambda disk: seen.append(disk))
        self.assertEqual(seen, [])

    def test_unowned_disk_refused_before_callback(self):
        seen = []
        self.disk.name = "windows-host-device.qcow2"
        with self.assertRaisesRegex(VM.LabError, "unowned"):
            VM.diagnose_stalled_windows_stage(
                self.disk, self.process, 0, lambda disk: seen.append(disk))
        self.assertEqual(seen, [])

    def test_diagnostic_failure_does_not_claim_windows_boot(self):
        def refused(_):
            raise RuntimeError("private guest XML must not be emitted")
        output = io.StringIO()
        with redirect_stdout(output):
            value = VM.diagnose_stalled_windows_stage(
                self.disk, self.process, 0, refused)
        self.assertIsNone(value)
        self.assertIn("GASLUX_WINDOWS_STAGE1_PANTHER_INSPECTION_UNAVAILABLE=1",
                      output.getvalue())
        self.assertNotIn("private guest", output.getvalue())
        self.assertNotIn("FIRSTBOOT_PASS", output.getvalue())

    def test_no_growth_does_not_claim_windows_boot(self):
        output = io.StringIO()
        with redirect_stdout(output):
            value = VM.diagnose_stalled_windows_stage(
                FakeDisk(blocks=0), self.process, 0, None)
        self.assertIsNone(value)
        self.assertIn("GASLUX_WINDOWS_STAGE1_STALLED_QCOW2_GROWTH_HEURISTIC=0",
                      output.getvalue())

    def test_timeout_path_runs_only_after_qemu_wait(self):
        text = SRC.read_text()
        segment = text[text.index("    first_stage_stalled = False"):]
        self.assertIn("if first_stage_stalled:", segment)
        self.assertLess(segment.index("proc.wait(timeout=30)"),
                        segment.index("diagnose_stalled_windows_stage("))
        self.assertIn('return False, "Windows Setup did not reboot its first owned VM"',
                      segment)


if __name__ == "__main__":
    unittest.main()
