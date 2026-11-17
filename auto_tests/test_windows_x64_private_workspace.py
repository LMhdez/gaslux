"""Fail-closed cleanup tests for the disposable Windows VM workspace."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import windows_x64_tcg_firstboot as lab


class PrivateWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runner_temp = Path(self.temp.name) / "runner-temp"
        self.runner_temp.mkdir()
        self.workspace = self.runner_temp / "gaslux-win-x64-test"
        self.workspace.mkdir(mode=0o700)
        (self.workspace / "root-owned-fixture").write_text("disposable", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_detects_mountpoint_and_nested_mounts_only(self):
        self.assertTrue(lab.workspace_has_active_mount(
            self.workspace, ["/", str(self.workspace / "target/dev")]))
        self.assertTrue(lab.workspace_has_active_mount(
            self.workspace, [str(self.workspace)]))
        self.assertFalse(lab.workspace_has_active_mount(
            self.workspace, [str(self.runner_temp), str(self.runner_temp / "other")]))

    def test_preserves_workspace_when_mount_is_active(self):
        result = subprocess.CompletedProcess(
            ["findmnt"], 0, stdout=f"{self.workspace}/target\n", stderr="")
        with patch.object(lab.subprocess, "run", return_value=result) as mocked:
            self.assertFalse(lab.cleanup_private_workspace(self.workspace, self.runner_temp))
        self.assertTrue(self.workspace.is_dir())
        mocked.assert_called_once()

    def test_refuses_workspace_outside_runner_temp_without_running_commands(self):
        outside = Path(self.temp.name) / "outside" / "gaslux-win-x64-foreign"
        outside.parent.mkdir()
        outside.mkdir(mode=0o700)
        with patch.object(lab.subprocess, "run") as mocked:
            self.assertFalse(lab.cleanup_private_workspace(outside, self.runner_temp))
        mocked.assert_not_called()
        self.assertTrue(outside.is_dir())

    def test_refuses_workspace_with_unsafe_permissions(self):
        self.workspace.chmod(0o755)
        with patch.object(lab.subprocess, "run") as mocked:
            self.assertFalse(lab.cleanup_private_workspace(self.workspace, self.runner_temp))
        mocked.assert_not_called()
        self.assertTrue(self.workspace.is_dir())

    def test_uses_sudo_one_filesystem_cleanup_only_after_no_mounts(self):
        def fake_run(args, **kwargs):
            if args[0] == "findmnt":
                return subprocess.CompletedProcess(args, 0, stdout="/\n", stderr="")
            if args[:3] == ["sudo", "rm", "-rf"]:
                shutil.rmtree(args[-1])
                return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
            raise AssertionError(f"unexpected cleanup command: {args}")

        with patch.object(lab.subprocess, "run", side_effect=fake_run) as mocked:
            self.assertTrue(lab.cleanup_private_workspace(self.workspace, self.runner_temp))
        self.assertFalse(self.workspace.exists())
        self.assertEqual(mocked.call_count, 2)


if __name__ == "__main__":
    unittest.main()
