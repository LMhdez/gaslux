"""Fixed synthetic GPT identity and atomic restore contract tests."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))

import windows_mint_ab_synthetic as synthetic
from windows_mint_ab_checkpoint import AbCheckpointError


class SyntheticProfileTests(unittest.TestCase):
    def test_fixed_profile_geometry_cannot_be_weakened(self) -> None:
        synthetic.validate_profile(synthetic.PROFILE)
        for delta in (
            {"virtual_bytes": 32 * synthetic.MiB},
            {"fifth_last_lba": 80000},
            {"scratch_bytes": 0},
            {"name": "production-windows"},
        ):
            with self.subTest(delta=delta):
                with self.assertRaisesRegex(
                    AbCheckpointError, "unsupported or forged"
                ):
                    synthetic.validate_profile(replace(synthetic.PROFILE, **delta))

    def test_scratch_is_gpt_derived_and_outside_fifth_partition(self) -> None:
        offset = synthetic.validate_scratch(
            synthetic.PROFILE.fifth_last_lba, synthetic.PROFILE
        )
        self.assertGreater(
            offset, synthetic.PROFILE.fifth_last_lba * synthetic.SECTOR
        )
        self.assertLess(
            offset + synthetic.PROFILE.scratch_bytes,
            synthetic.PROFILE.virtual_bytes - 34 * synthetic.SECTOR,
        )

    def test_wrong_partition_geometry_rejected(self) -> None:
        for end in (0, 77824, 999999, -1):
            with self.subTest(end=end):
                with self.assertRaisesRegex(
                    AbCheckpointError, "fifth partition end changed"
                ):
                    synthetic.validate_scratch(end, synthetic.PROFILE)

    def test_guest_boot_and_arbitrary_workspace_not_authorized(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(synthetic, "generate_private_gpt") as disk:
                with self.assertRaisesRegex(
                    AbCheckpointError, "consent"
                ):
                    synthetic.run_fixed_synthetic()
                disk.assert_not_called()

    def test_reject_existing_raw_fixture_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            raw = folder / "synthetic-gpt.raw"
            raw.write_bytes(b"foreign")
            with patch.object(synthetic, "_run") as process:
                with self.assertRaisesRegex(
                    AbCheckpointError, "foreign synthetic"
                ):
                    synthetic.generate_private_gpt(raw, folder)
                process.assert_not_called()
            self.assertEqual(raw.read_bytes(), b"foreign")

    def test_other_arm_and_immutable_reference_must_remain_identical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            ref = folder / "reference.qcow2"
            a = folder / "arm-a.qcow2"
            b = folder / "arm-b.qcow2"
            ref.write_bytes(b"reference")
            a.write_bytes(b"arm-a")
            b.write_bytes(b"arm-b")
            with patch.object(synthetic, "command") as cmd:
                cmd.return_value.returncode = 1
                with patch.object(synthetic, "atomic_restore_owned_arm") as restore:
                    synthetic.arm_fault_and_restore(
                        ref, a, b, folder,
                        offset=40 * synthetic.MiB,
                        full_bound=64 * synthetic.MiB,
                    )
                    restore.assert_called_once()
                    self.assertEqual(ref.read_bytes(), b"reference")
                    self.assertEqual(b.read_bytes(), b"arm-b")

    def test_failed_restore_must_not_generate_success_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            ref = folder / "reference.qcow2"
            a = folder / "arm-a.qcow2"
            b = folder / "arm-b.qcow2"
            ref.write_bytes(b"reference")
            a.write_bytes(b"arm-a")
            b.write_bytes(b"arm-b")
            with patch.object(synthetic, "command") as cmd:
                cmd.return_value.returncode = 1
                with patch.object(
                    synthetic, "atomic_restore_owned_arm",
                    side_effect=OSError(28, "ENOSPC"),
                ):
                    with self.assertRaises(OSError):
                        synthetic.arm_fault_and_restore(
                            ref, a, b, folder,
                            offset=40 * synthetic.MiB,
                            full_bound=64 * synthetic.MiB,
                        )
                    self.assertFalse((folder / "checkpoint.json").exists())


if __name__ == "__main__":
    unittest.main()
