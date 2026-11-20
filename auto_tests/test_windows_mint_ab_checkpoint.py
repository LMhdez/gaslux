"""Fail-closed Mint A/B forensic checkpoint contracts (no guests, no Windows)."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import subprocess

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows_mint_ab_checkpoint as ab


class MintAbCheckpointContracts(unittest.TestCase):
    def test_absent_explicit_checkpoint_consent_rejects_before_any_disk(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ab.AbCheckpointError, "separate Mint A/B"):
                ab.prepare_checkpoint(
                    base=Path("/dev/sda"), nvram=Path("/dev/nvram"),
                    overlay=Path("/dev/sdb"), ovmf_code=Path("/dev/ovmf"),
                    mint_root_uuid="00000000-0000-4000-8000-000000000001")

    def test_symlink_and_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "src"
            src.write_bytes(b"qcow2")
            for dst in (root / "linked", root / "symlink"):
                if dst.name == "linked":
                    os.link(src, dst)
                else:
                    dst.symlink_to(src)
                with self.subTest(dst=dst):
                    with self.assertRaisesRegex(ab.AbCheckpointError,
                                                "symlinked|hardlink"):
                        ab.file_guard(dst, root)

    def test_wrong_mode_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            target = folder / "arm-a.qcow2"
            target.write_bytes(b"test")
            target.chmod(0o644)
            with self.assertRaisesRegex(ab.AbCheckpointError, "permissions"):
                ab.file_guard(target, folder, 0o600)

    def test_foreign_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            target = folder / "arm-a.qcow2"
            target.write_bytes(b"test")
            with self.assertRaisesRegex(ab.AbCheckpointError, "foreign"):
                ab.file_guard(target, folder / "elsewhere")

    def test_duplicate_destination_rejected_before_convert(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            image = folder / "arm-a.qcow2"
            image.write_bytes(b"existing")
            with patch.object(ab, "command") as command:
                with self.assertRaisesRegex(ab.AbCheckpointError, "reused"):
                    ab.standalone(folder / "reference.qcow2", image, folder)
                command.assert_not_called()

    def test_independent_image_must_have_no_backing_or_encryption(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sample.qcow2"
            for extra in ({"backing-filename": "/tmp/shared.qcow2"},
                          {"full-backing-filename": "/tmp/shared.qcow2"},
                          {"encrypted": True},
                          {"virtual-size": ab.VIRTUAL_BYTES - 512}):
                import json
                payload = {"format": "qcow2",
                           "virtual-size": ab.VIRTUAL_BYTES} | extra
                with self.subTest(extra=extra):
                    with patch.object(ab, "command",
                            return_value=subprocess.CompletedProcess(
                                [], 0, json.dumps(payload), "")):
                        with self.assertRaisesRegex(ab.AbCheckpointError,
                                                    "not independent"):
                            ab.image_info(path)

    def test_ovmf_independent_clones_match_bytewise(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "trial-vars.fd"
            src.write_bytes(b"var" * 1000)
            dst_a = root / "arm-a-vars.fd"
            dst_b = root / "arm-b-vars.fd"
            sha = ab.clone_vars(src, dst_a, root)
            self.assertEqual(sha, ab.clone_vars(src, dst_b, root))
            self.assertEqual(len({src.stat().st_ino, dst_a.stat().st_ino,
                                  dst_b.stat().st_ino}), 3)
            self.assertEqual(dst_a.stat().st_mode & 0o777, 0o600)

    def test_missing_tpm_is_explicitly_not_applicable(self):
        with tempfile.TemporaryDirectory() as d:
            info = ab.clone_tpm_state(None, Path(d))
            self.assertIs(info["applicable"], False)

    def test_tpm_rejects_links_and_unexpected_socket(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "swtpm-state"
            src.mkdir()
            data = src / "state.bin"
            data.write_bytes(b"state")
            directory = root / "mint-ab-independent-checkpoint"
            directory.mkdir()
            os.link(data, src / "bad-hardlink")
            with self.assertRaisesRegex(ab.AbCheckpointError, "unsafe TPM"):
                ab.clone_tpm_state(src, directory)

    def test_recovery_must_detect_corruption_before_restoring(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            reference, arm = root / "reference.qcow2", root / "arm-a.qcow2"
            reference.write_bytes(b"reference")
            arm.write_bytes(b"arm")
            arm.chmod(0o600)
            responses = [
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", ""),
            ]
            with patch.object(ab, "command", side_effect=responses):
                with self.assertRaisesRegex(ab.AbCheckpointError, "not independently detected"):
                    ab.reproduce_restore(reference, arm, root)
            self.assertTrue(arm.exists(), "must not destroy arm on unproved recovery")

    def test_source_never_uses_production_disk_utilities_or_merge_semantics(self):
        code = (Path(__file__).parent / "tools" /
                "windows_mint_ab_checkpoint.py").read_text()
        for unsafe in ("sgdisk", "wipefs", "mkfs", "parted", "mount -o rw",
                       "os.system(", "ACCEPT_NO_WRITER", "qemu-img rebase"):
            with self.subTest(command=unsafe):
                self.assertNotIn(unsafe, code)
        self.assertIn('"qemu-img", "compare"', code)
        self.assertIn('"qemu-img", "convert"', code)
        self.assertIn("controlRecoveredAfterFaultInjection", code)


if __name__ == "__main__":
    unittest.main()
