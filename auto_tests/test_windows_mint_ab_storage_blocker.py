"""Conservative Mint A/B QCOW2 storage: real tiny images, never guest boots.

Storage headroom and quotas cannot be inferred from sparse or compressed images.
Do not change the 128-GiB real Windows/Mint A/B admission bound based on these.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows_mint_ab_capacity as cap
import windows_mint_ab_checkpoint as cp

MIB = 1024**2
GIB = 1024**3
SMALL_VIRTUAL_BYTES = 64 * MIB
HISTORICAL_AVAILABLE_BYTES = 94_807_687_168
HISTORICAL_FULL_BOUND = 137_460_187_136


def runner(*argv: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, check=check, text=True, capture_output=True, timeout=60,
    )


def free_fs(available_bytes: int) -> SimpleNamespace:
    return SimpleNamespace(
        f_frsize=4096,
        f_blocks=300_000_000,
        f_bavail=available_bytes // 4096,
        f_bfree=available_bytes // 4096,
    )


class AConservativeAandBBudget(unittest.TestCase):
    def test_historical_shortfall_reproduced_exactly_without_sparse_discount(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(
                cap.os, "statvfs", return_value=free_fs(HISTORICAL_AVAILABLE_BYTES),
            ):
                proof = cap.measure_capacity(
                    directory=Path(root), phase="early",
                    full_allocated_bytes=HISTORICAL_FULL_BOUND,
                )
        self.assertEqual(proof["minimumFreeBytesRequired"], 867_710_795_776)
        self.assertEqual(proof["capacityShortfallBytes"], 772_903_108_608)
        self.assertEqual(proof["result"], "BLOCKED_CAPACITY")
        self.assertEqual(proof["worstCaseRemainingStandaloneImagesAndRestores"], 6)
        self.assertEqual(proof["nonImageReserveBytes"], 40 * GIB)
        self.assertFalse(proof["compressionAssumedForCapacity"])
        self.assertFalse(proof["windowsGuestBootsAuthorized"])
        self.assertFalse(proof["checkpointReadyForReview"])

    def test_late_budget_is_four_full_images_plus_eight_gib_only(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            base = work / "windows-backing.qcow2"
            base.write_bytes(b"private mock")
            child = work / "windows-uefi-cow-checkpoint"
            child.mkdir()
            overlay = child / "mint-staged.qcow2"
            overlay.write_bytes(b"private mock")
            need = 4 * HISTORICAL_FULL_BOUND + 8 * GIB
            with patch.object(cap.os, "statvfs", return_value=free_fs(need - 4096)):
                result = cap.measure_capacity(
                    directory=work, phase="late",
                    full_allocated_bytes=HISTORICAL_FULL_BOUND,
                    base=base, overlay=overlay,
                )
            self.assertEqual(result["minimumFreeBytesRequired"], 558_430_683_136)
            self.assertEqual(result["capacityShortfallBytes"], 4096)
            self.assertEqual(result["result"], "BLOCKED_CAPACITY")
            self.assertEqual(result["worstCaseRemainingStandaloneImagesAndRestores"], 4)
            self.assertEqual(result["nonImageReserveBytes"], 8 * GIB)
            self.assertFalse(result["windowsGuestBootsAuthorized"])

    def test_unknown_quota_must_be_recorded_as_unobserved_not_claimed_measured(self):
        with tempfile.TemporaryDirectory() as root:
            required = cap.EARLY_IMAGES * HISTORICAL_FULL_BOUND + cap.EARLY_RESERVE
            with patch.object(cap.os, "statvfs", return_value=free_fs(required + 4096)):
                result = cap.measure_capacity(
                    directory=Path(root), phase="early",
                    full_allocated_bytes=HISTORICAL_FULL_BOUND,
                    quota_remaining_bytes=None,
                )
        # Current contract does NOT prove that a separate filesystem quota
        # does not exist; this test records the residual safety uncertainty.
        self.assertEqual(result["quotaStatus"], "not-observable")
        self.assertIsNone(result["quotaRemainingBytes"])
        self.assertFalse(result["checkpointReadyForReview"])
        self.assertFalse(result["windowsGuestBootsAuthorized"])

    def test_measured_quota_below_threshold_blocks_even_with_plenty_of_fs_space(self):
        with tempfile.TemporaryDirectory() as root:
            need = cap.EARLY_IMAGES * HISTORICAL_FULL_BOUND + cap.EARLY_RESERVE
            with patch.object(cap.os, "statvfs", return_value=free_fs(need + 4096)):
                result = cap.measure_capacity(
                    directory=Path(root), phase="early",
                    full_allocated_bytes=HISTORICAL_FULL_BOUND,
                    quota_remaining_bytes=need - 1,
                )
        self.assertEqual(result["effectiveAvailableBytes"], need - 1)
        self.assertEqual(result["result"], "BLOCKED_CAPACITY")


class BRealSmallQcow2Restore(unittest.TestCase):
    """QEMU disk utilities only: never invoke qemu-system or a guest."""

    def setUp(self):
        self.assertIsNotNone(shutil.which("qemu-img"), "qemu-utils is required")
        self.assertIsNotNone(shutil.which("qemu-io"), "qemu-utils is required")
        self.assertIsNotNone(shutil.which("fuser"), "process detachment must be checked")
        self.tmp = tempfile.TemporaryDirectory(prefix="gaslux-mint-storage-tiny-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ref = self.root / "reference.qcow2"
        self.arm = self.root / "arm-a.qcow2"
        runner("qemu-img", "create", "-f", "qcow2", str(self.ref), str(SMALL_VIRTUAL_BYTES))
        runner(
            "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", "-c",
            str(self.ref), str(self.arm),
        )
        self.ref.chmod(0o400)
        self.arm.chmod(0o600)
        measurement = json.loads(runner(
            "qemu-img", "measure", "--output=json", "-O", "qcow2",
            "--size", str(SMALL_VIRTUAL_BYTES),
        ).stdout)
        self.bound = measurement["fully-allocated"]
        self.assertGreaterEqual(self.bound, SMALL_VIRTUAL_BYTES)
        self.assertNotEqual(self.ref.stat().st_ino, self.arm.stat().st_ino)
        cp.image_info(self.ref, SMALL_VIRTUAL_BYTES)
        cp.image_info(self.arm, SMALL_VIRTUAL_BYTES)

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def inject_arm_fault(self):
        runner(
            "qemu-io", "-f", "qcow2", "-c", "write -P 0x77 1048576 4096",
            str(self.arm),
        )

    def restore(self):
        cp.atomic_restore_owned_arm(
            self.ref, self.arm, self.root,
            expected_virtual_bytes=SMALL_VIRTUAL_BYTES,
            fully_allocated_bound=self.bound,
        )

    def test_sparse_physical_allocation_is_observed_not_admission_discount(self):
        actual_allocated = self.ref.stat().st_blocks * 512
        self.assertGreater(actual_allocated, 0)
        self.assertLessEqual(actual_allocated, self.bound)
        self.assertGreater(self.bound, 0)
        # Deliberately NEVER substitute actual_allocated into cap.measure_capacity.

    def test_shared_backing_chain_is_not_an_independent_arm(self):
        backed = self.root / "shared-backed.qcow2"
        runner(
            "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
            str(self.ref), str(backed),
        )
        with self.assertRaisesRegex(cp.AbCheckpointError, "not independent"):
            cp.image_info(backed, SMALL_VIRTUAL_BYTES)
        self.assertEqual(self.ref.stat().st_nlink, 1)

    def test_successful_atomic_restore_replaces_only_arm_no_leftover_temporary(self):
        self.inject_arm_fault()
        original_ref = self.digest(self.ref)
        previous_inode = self.arm.stat().st_ino
        self.assertEqual(
            runner("qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
                   str(self.ref), str(self.arm), check=False).returncode, 1,
        )
        self.restore()
        cp.equivalent(self.ref, self.arm)
        self.assertEqual(self.digest(self.ref), original_ref)
        self.assertNotEqual(self.arm.stat().st_ino, previous_inode)
        self.assertFalse((self.root / "arm-a.qcow2.restore.tmp.qcow2").exists())
        self.assertFalse(cp.image_info(self.arm, SMALL_VIRTUAL_BYTES).get("backing-filename"))

    def test_enospc_during_temporary_convert_leaves_both_original_images_intact(self):
        self.inject_arm_fault()
        old_ref, old_arm = self.digest(self.ref), self.digest(self.arm)
        temp = self.root / "arm-a.qcow2.restore.tmp.qcow2"

        def fail_with_partial(source, destination, directory, expected_virtual):
            self.assertEqual(source, self.ref)
            self.assertEqual(destination, temp)
            self.assertEqual(directory, self.root)
            self.assertEqual(expected_virtual, SMALL_VIRTUAL_BYTES)
            destination.write_bytes(b"owned-incomplete-restore-temp")
            raise OSError(errno.ENOSPC, "injected synthetic ENOSPC")

        with patch.object(cp, "standalone", side_effect=fail_with_partial):
            with self.assertRaises(OSError) as raised:
                self.restore()
        self.assertEqual(raised.exception.errno, errno.ENOSPC)
        self.assertEqual((self.digest(self.ref), self.digest(self.arm)), (old_ref, old_arm))
        self.assertEqual(temp.read_bytes(), b"owned-incomplete-restore-temp")
        self.assertFalse((self.root / "checkpoint.json").exists())
        with patch.object(cp, "standalone") as command:
            with self.assertRaisesRegex(cp.AbCheckpointError, "reused"):
                self.restore()
            command.assert_not_called()

    def test_interrupted_temporary_clone_never_replaces_original_arm(self):
        self.inject_arm_fault()
        old_ref, old_arm = self.digest(self.ref), self.digest(self.arm)
        temp = self.root / "arm-a.qcow2.restore.tmp.qcow2"

        def interrupt_convert(*args, **kwargs):
            temp.write_bytes(b"owned-aborted-conversion")
            raise KeyboardInterrupt("injected interruption")

        with patch.object(cp, "standalone", side_effect=interrupt_convert):
            with self.assertRaises(KeyboardInterrupt):
                self.restore()
        self.assertEqual((self.digest(self.ref), self.digest(self.arm)), (old_ref, old_arm))
        self.assertTrue(temp.exists())
        self.assertFalse((self.root / "checkpoint.json").exists())

    def test_corrupt_temporary_does_not_replace_arm_on_compare_failure(self):
        self.inject_arm_fault()
        old_ref, old_arm = self.digest(self.ref), self.digest(self.arm)
        temp = self.root / "arm-a.qcow2.restore.tmp.qcow2"

        def wrong_convert(source, destination, directory, expected_virtual):
            runner(
                "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
                str(self.arm), str(destination),
            )
            destination.chmod(0o600)
            return self.digest(destination)

        with patch.object(cp, "standalone", side_effect=wrong_convert):
            with self.assertRaises(subprocess.CalledProcessError):
                self.restore()
        self.assertTrue(temp.exists())
        self.assertEqual((self.digest(self.ref), self.digest(self.arm)), (old_ref, old_arm))
        self.assertFalse((self.root / "checkpoint.json").exists())

    def test_foreign_preexisting_restore_temp_is_preserved_and_blocks_retry(self):
        temp = self.root / "arm-a.qcow2.restore.tmp.qcow2"
        source = self.root / "foreign-user-artifact"
        source.write_bytes(b"foreign-untouched")
        temp.symlink_to(source)
        initial = self.digest(self.arm)
        with patch.object(cp, "standalone") as convert:
            with self.assertRaisesRegex(cp.AbCheckpointError, "reused"):
                self.restore()
            convert.assert_not_called()
        self.assertEqual(source.read_bytes(), b"foreign-untouched")
        self.assertEqual(self.digest(self.arm), initial)

    def test_insufficient_free_space_refuses_before_creating_restore_temp(self):
        temp = self.root / "arm-a.qcow2.restore.tmp.qcow2"
        with (
            patch.object(cp.os, "statvfs", return_value=free_fs(self.bound + 2 * GIB)),
            patch.object(cp, "standalone") as convert,
        ):
            with self.assertRaisesRegex(cp.AbCheckpointError, "insufficient"):
                self.restore()
            convert.assert_not_called()
        self.assertFalse(temp.exists())


if __name__ == "__main__":
    unittest.main()
