"""Fail-closed tests for Windows QCOW2 overlay fault-injection lab.

All tests use temporary regular files; never run qemu-img, qemu-io, mount,
or touch a real Windows installation.
"""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import windows_cachyos_qcow2_overlay_discard as lab


class OverlayIsolationGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gaslux-overlay-guards-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.disk = self.root / "only-disposable-windows-target.qcow2"
        self.disk.write_bytes(b"synthetic-not-a-windows-disk")
        self.consent = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "LMhdez/gaslux",
            "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
                "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
            "GASLUX_WINDOWS_OVERLAY_TEST": "I_ACCEPT_NEW_QCOW2_OVERLAY_ONLY",
        }

    def test_refuses_disk_outside_private_runner_directory(self):
        with patch.dict(os.environ, self.consent):
            with self.assertRaises(lab.GeometryError):
                lab.owned_base(self.disk)

    def test_refuses_missing_explicit_overlay_consent(self):
        env = dict(self.consent)
        env.pop("GASLUX_WINDOWS_OVERLAY_TEST")
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(lab.GeometryError):
                lab.overlay_trial(self.disk)

    def test_refuses_symlink_target(self):
        link = self.root / "disk-link.qcow2"
        link.symlink_to(self.disk)
        with patch.dict(os.environ, self.consent):
            with self.assertRaises(lab.GeometryError):
                lab.owned_base(link)

    def test_refuses_hardlinked_disk(self):
        link = self.root / "second-name.qcow2"
        os.link(self.disk, link)
        with patch.dict(os.environ, self.consent):
            with self.assertRaises(lab.GeometryError):
                lab.owned_base(self.disk)

    def test_no_qemu_commands_when_preflight_rejects_target(self):
        with patch.dict(os.environ, self.consent), patch.object(
            lab.subprocess, "run", side_effect=AssertionError("unexpected disk I/O")
        ):
            with self.assertRaises(lab.GeometryError):
                lab.overlay_trial(self.disk)

    def test_read_windows_rejects_truncated_gpt_window(self):
        with patch.object(lab, "bounded_qcow2_dd_command", return_value=["fake"]), \
             patch.object(lab.subprocess, "run", return_value=None):
            with self.assertRaises(lab.GeometryError):
                lab.read_windows(self.disk, self.root)


if __name__ == "__main__":
    unittest.main()
