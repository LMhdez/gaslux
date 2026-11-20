"""No physical disk: fault-injection tests for disposable QCOW2 checkpoints."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


checkpoint = load("synthetic_checkpoint", ROOT / "tools/cachyos_synthetic_recovery_checkpoint.py")
transaction = load("synthetic_proposal_fixture", ROOT / "test_cachyos_partition_transaction_simulation.py")


class SyntheticCheckpointTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("qemu-img"):
            self.skipTest("qemu-img required for genuine disposable QCOW2 fixture")
        self.tmp = tempfile.TemporaryDirectory(
            prefix=checkpoint.PREFIX, dir=os.environ["RUNNER_TEMP"])
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.source = self.folder / checkpoint.SOURCE_NAME
        subprocess.run(["qemu-img", "create", "-f", "qcow2",
                        str(self.source), "16M"], check=True, capture_output=True)
        report, plan = transaction.fixture()
        self.proposal = transaction.sim.propose(report, plan)
        self.snapshot = self.folder / ("checkpoint-" + "a" * 32)

    def seal(self):
        return checkpoint.create_synthetic_checkpoint(
            self.folder, self.source, self.proposal)

    def verify(self, saved):
        return checkpoint.verify_synthetic_checkpoint(
            self.folder, self.proposal, saved["checkpointManifestSha256"])

    def test_real_qcow2_copied_fsynced_and_verified_without_write_authority(self):
        baseline = self.source.read_bytes()
        saved = self.seal()
        observed = self.verify(saved)
        self.assertEqual((self.snapshot / "baseline.qcow2").read_bytes(), baseline)
        self.assertEqual(self.source.read_bytes(), baseline)
        self.assertTrue(observed["syntheticSnapshotHashVerified"])
        for flag in ("windowsRecoveryVerified", "storageWritesAuthorized",
                     "releaseEligible"):
            self.assertIs(observed[flag], False)
            self.assertIs(saved[flag], False)

    def test_unsealed_checkpoint_after_injected_power_cut_rejected(self):
        with self.assertRaisesRegex(
                checkpoint.CheckpointRejected, "injected interruption"):
            checkpoint.create_synthetic_checkpoint(
                self.folder, self.source, self.proposal,
                interrupt_after_copy=True)
        self.assertFalse((self.snapshot / "manifest.json").exists())
        with self.assertRaises(FileNotFoundError):
            checkpoint.verify_synthetic_checkpoint(
                self.folder, self.proposal, "0" * 64)

    def test_snapshot_corruption_rejected_even_with_unchanged_manifest(self):
        saved = self.seal()
        with (self.snapshot / "baseline.qcow2").open("r+b") as f:
            f.seek(-1, os.SEEK_END)
            previous = f.read(1)
            f.seek(-1, os.SEEK_END)
            f.write(bytes([previous[0] ^ 1]))
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "corrupted"):
            self.verify(saved)

    def test_manifest_replay_or_tampering_rejected(self):
        saved = self.seal()
        with (self.snapshot / "manifest.json").open("ab") as f:
            f.write(b"\n")
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "digest mismatch"):
            self.verify(saved)

    def test_wrong_manifest_digest_rejected(self):
        saved = self.seal()
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "digest mismatch"):
            checkpoint.verify_synthetic_checkpoint(
                self.folder, self.proposal, "f" * 64)

    def test_checkpoint_cannot_overwrite_an_existing_transaction(self):
        self.seal()
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "already exists"):
            self.seal()

    def test_hardlinked_source_and_non_private_checkpoint_root_rejected(self):
        os.link(self.source, self.folder / "foreign-hardlink")
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "exclusive owned"):
            self.seal()
        (self.folder / "foreign-hardlink").unlink()
        os.chmod(self.folder, 0o755)
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "not private"):
            self.seal()

    def test_symlink_source_and_wrong_source_name_rejected(self):
        source_other = self.folder / "foreign.qcow2"
        self.source.rename(source_other)
        self.source.symlink_to(source_other)
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "symlink"):
            self.seal()
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "unexpected synthetic"):
            checkpoint.create_synthetic_checkpoint(
                self.folder, source_other, self.proposal)

    def test_foreign_transaction_or_forged_authority_rejected(self):
        bogus = dict(self.proposal)
        bogus["storageWritesAuthorized"] = True
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "forbidden authority"):
            checkpoint.create_synthetic_checkpoint(
                self.folder, self.source, bogus)
        bogus = dict(self.proposal)
        bogus["identity"] = dict(self.proposal["identity"])
        bogus["identity"]["transactionId"] = "b" * 32
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "modified proposal"):
            checkpoint.create_synthetic_checkpoint(
                self.folder, self.source, bogus)

    def test_original_source_mutation_does_not_modify_checkpoint(self):
        saved = self.seal()
        snapshot_before = (self.snapshot / "baseline.qcow2").read_bytes()
        with self.source.open("ab") as f:
            f.write(b"only-mutated-disposable-source")
        observed = self.verify(saved)
        self.assertTrue(observed["syntheticSnapshotHashVerified"])
        self.assertEqual((self.snapshot / "baseline.qcow2").read_bytes(),
                         snapshot_before)
        self.assertNotEqual(self.source.read_bytes(), snapshot_before)


if __name__ == "__main__":
    unittest.main()
