"""Negative contracts for the post-Windows disposable QCOW2 COW checkpoint."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import sys

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
MODULE_PATH = TOOLS / "windows_cachyos_cow_checkpoint.py"
spec = importlib.util.spec_from_file_location("gaslux_cow_checkpoint", MODULE_PATH)
assert spec and spec.loader
cow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cow)


def candidate():
    return {
        "candidateWindowsGptPrimaryAndBackupConsistent": True,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


class WindowsCowCheckpointContractTests(unittest.TestCase):
    def test_geometry_candidate_must_have_three_exact_failclosed_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / cow.BASE_NAME
            vars = Path(tmp) / cow.VARS_NAME
            for field, value in (
                ("candidateWindowsGptPrimaryAndBackupConsistent", False),
                ("candidateWindowsGptPrimaryAndBackupConsistent", 1),
                ("storageWritesAuthorized", True),
                ("releaseEligible", True),
            ):
                with self.subTest(field=field, value=value):
                    report = candidate()
                    report[field] = value
                    with self.assertRaisesRegex(cow.CheckpointError, "GPT geometry"):
                        cow.prepare_postboot_cow(disk, vars, report)
            with self.assertRaisesRegex(cow.CheckpointError, "GPT geometry"):
                cow.prepare_postboot_cow(disk, vars, {})
            with self.assertRaisesRegex(cow.CheckpointError, "GPT geometry"):
                cow.prepare_postboot_cow(disk, vars, [])

    def test_absent_additional_hosted_only_consent_is_rejected(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(cow.CheckpointError, "additional hosted"):
                cow.validate_workspace(Path("/tmp/not-gaslux.qcow2"),
                                       Path("/tmp/ovmf-variables.fd"))

    def make_local_workspace(self, root):
        folder = Path(root) / "gaslux-win-x64-test123"
        folder.mkdir(mode=0o700)
        folder.chmod(0o700)
        disk = folder / cow.BASE_NAME
        disk.write_bytes(b"q" * 65537)
        vars = folder / cow.VARS_NAME
        vars.write_bytes(b"v" * 999999)
        env = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "LMhdez/gaslux",
            "RUNNER_TEMP": str(root),
            "GASLUX_WINDOWS_COW_CHECKPOINT_CONSENT": cow.EXPECTED_CONSENT,
            "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
                "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
        }
        return folder, disk, vars, env

    def test_nonprivate_workspace_rejected_before_any_qemu(self):
        with tempfile.TemporaryDirectory() as root:
            folder, disk, vars, env = self.make_local_workspace(root)
            folder.chmod(0o755)
            with patch.object(cow, "ROOT", Path(root)), patch.dict(
                os.environ, env, clear=True,
            ), patch.object(cow, "run_qemu") as command:
                with self.assertRaisesRegex(cow.CheckpointError, "private owned"):
                    cow.validate_workspace(disk, vars)
                command.assert_not_called()

    def test_symlink_disk_rejected_before_any_qemu(self):
        with tempfile.TemporaryDirectory() as root:
            folder, disk, vars, env = self.make_local_workspace(root)
            disk.unlink()
            other = folder / "foreign-disk"
            other.write_bytes(b"q" * 65537)
            disk.symlink_to(other)
            with patch.object(cow, "ROOT", Path(root)), patch.dict(
                os.environ, env, clear=True,
            ), patch.object(cow, "run_qemu") as command:
                with self.assertRaisesRegex(cow.CheckpointError, "redirected"):
                    cow.validate_workspace(disk, vars)
                command.assert_not_called()

    def test_hardlinked_disk_rejected_before_any_qemu(self):
        with tempfile.TemporaryDirectory() as root:
            folder, disk, vars, env = self.make_local_workspace(root)
            os.link(disk, folder/"unexpected-link")
            with patch.object(cow, "ROOT", Path(root)), patch.dict(
                os.environ, env, clear=True,
            ), patch.object(cow, "run_qemu") as command:
                with self.assertRaisesRegex(cow.CheckpointError, "exclusive owned"):
                    cow.validate_workspace(disk, vars)
                command.assert_not_called()

    def test_unexpected_existing_checkpoint_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            folder, disk, vars, env = self.make_local_workspace(root)
            (folder / cow.CHECKPOINT_DIR).mkdir()
            with patch.object(cow, "ROOT", Path(root)), patch.dict(
                os.environ, env, clear=True,
            ), patch.object(cow, "validate_workspace"), patch.object(
                cow, "run_qemu",
            ) as command:
                with self.assertRaisesRegex(cow.CheckpointError, "existing checkpoint"):
                    cow.prepare_postboot_cow(disk, vars, candidate())
                command.assert_not_called()

    def test_existing_source_with_backing_chain_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            folder, disk, vars, env = self.make_local_workspace(root)
            def fake_qemu(args, timeout=40):
                return subprocess.CompletedProcess(args, 0, json.dumps({
                    "format": "qcow2", "virtual-size": cow.VIRTUAL_BYTES,
                    "backing-filename": "/some/foreign.img",
                }), "")
            with patch.object(cow, "ROOT", Path(root)), patch.dict(
                os.environ, env, clear=True,
            ), patch.object(cow, "run_qemu", side_effect=fake_qemu):
                with self.assertRaisesRegex(cow.CheckpointError, "incorrect QCOW2"):
                    cow.validate_workspace(disk, vars)

    def test_source_prohibits_unsafe_storage_commands(self):
        code = MODULE_PATH.read_text()
        for unsafe in ("sgdisk", "wipefs", "mkfs", "parted",
                       "mount ", "qemu-io", "os.system("):
            with self.subTest(command=unsafe):
                self.assertNotIn(unsafe, code)
        self.assertIn('"qemu-img", "compare"', code)
        self.assertIn('"qemu-img", "create"', code)
        self.assertIn('"backing-filename"', code)


if __name__ == "__main__":
    unittest.main()
