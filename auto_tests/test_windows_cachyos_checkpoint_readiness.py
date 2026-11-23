"""Synthetic negative contracts for historical Windows 10 checkpoint readiness.

These fixtures contain NO Windows image, BCD/ESP data, QEMU or installer.
Structural compatibility must NEVER be promoted to recovery authority.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import windows_cachyos_checkpoint_readiness as readiness
from windows_cachyos_bcd_ab_control import (
    TPM_CONTROL, TPM_TREATMENT, WINDOWS_CONTROL_OVERLAY,
    WINDOWS_CONTROL_VARS,
)
from windows_cachyos_cow_checkpoint import CHECKPOINT_DIR, OVERLAY_NAME


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CheckpointReadinessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="gaslux-checkpoint-readiness-synthetic-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.chmod(0o700)
        self.folder = self.root / CHECKPOINT_DIR
        self.folder.mkdir(mode=0o700)
        self.disk = self.folder / OVERLAY_NAME
        self.control = self.folder / WINDOWS_CONTROL_OVERLAY
        self.vars_b = self.folder / "trial-ovmf-variables.fd"
        self.vars_a = self.folder / WINDOWS_CONTROL_VARS
        self.base = self.root / "only-disposable-windows-target.qcow2"
        self.original_vars = self.root / "ovmf-variables.fd"
        contents = (
            (self.disk, b"QFI\xfb" + b"synthetic owned checkpoint" * 10),
            (self.control, b"QFI\xfb" + b"synthetic owned checkpoint" * 10),
            (self.vars_b, b"synthetic UEFI baseline bytes"),
            (self.vars_a, b"synthetic UEFI baseline bytes"),
            (self.base, b"QFI\xfb" + b"synthetic immutable Windows backing"),
            (self.original_vars, b"synthetic original UEFI baseline bytes"),
        )
        for path, raw in contents:
            path.write_bytes(raw)
            path.chmod(0o400 if path == self.base else 0o600)
        for name in (TPM_CONTROL, TPM_TREATMENT):
            state = self.root / name
            state.mkdir(mode=0o700)
            (state / "state.bin").write_bytes(b"synthetic TPM not boot evidence")
        self.manifest = {
            "transactionId": "test-only-transaction-001",
            "artifactTransactionId": "test-only-transaction-001",
            "sourceOverlaySha256": digest(self.disk),
            "controlOverlaySha256": digest(self.control),
            "sourceVarsSha256": digest(self.vars_b),
            "controlVarsSha256": digest(self.vars_a),
            "immutableBackingSha256": digest(self.base),
            "originalOvmfVarsSha256": digest(self.original_vars),
            "initialBcdSha256": "a" * 64,
            "controlBcdSha256": "a" * 64,
            "treatmentBcdSha256": "a" * 64,
        }
        self.quota = 70 * 1024**3
        self.volume = SimpleNamespace(
            f_frsize=4096, f_bavail=16 * 1024**3 // 1024,
            f_bfree=16 * 1024**3 // 1024,
            f_blocks=16 * 1024**3 // 1024 + 1,
        )
        # 16m 4KiB blocks = 64GiB: independent from QCOW2 virtual size.

    def check(self, quota=None, manifest=None, recovery=None):
        # We mock only statvfs: files are real temporary regular files.
        with mock.patch.object(
            readiness.os, "statvfs", return_value=self.volume
        ):
            return readiness.inspect_readonly_ab_checkpoint(
                self.root, transaction_id="test-only-transaction-001",
                manifest=self.manifest if manifest is None else manifest,
                external_quota_bytes=self.quota if quota is None else quota,
                restore_witness=recovery,
            )

    def refused(self, code: str, **kwargs):
        with self.assertRaises(readiness.CheckpointReadinessRefusal) as caught:
            self.check(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_A_checkpoint_not_found(self):
        self.disk.unlink()
        self.refused("CHECKPOINT_NOT_FOUND")

    def test_B_source_hash_mismatch(self):
        self.manifest["sourceOverlaySha256"] = "0" * 64
        self.refused("SOURCE_HASH_MISMATCH")

    def test_C_source_still_in_use_by_current_process(self):
        fd = os.open(self.disk, os.O_RDONLY | os.O_CLOEXEC)
        try:
            self.refused("SOURCE_STILL_IN_USE")
        finally:
            os.close(fd)

    def test_D_insufficient_capacity_includes_growth_and_forensic_reserve(self):
        self.volume.f_bavail = self.volume.f_bfree = 1
        self.refused("INSUFFICIENT_CAPACITY")

    def test_E_unknown_quota_refused(self):
        self.refused("UNKNOWN_QUOTA", quota=-1)

    def test_unknown_quota_none_is_denied_even_with_valid_files(self):
        with mock.patch.object(
            readiness.os, "statvfs", return_value=self.volume
        ), self.assertRaises(readiness.CheckpointReadinessRefusal) as caught:
            readiness.inspect_readonly_ab_checkpoint(
                self.root, transaction_id="test-only-transaction-001",
                manifest=self.manifest, external_quota_bytes=None,
            )
        self.assertEqual(caught.exception.code, "UNKNOWN_QUOTA")

    def test_F_shared_ovmf_vars_refused(self):
        self.vars_a.unlink()
        os.link(self.vars_b, self.vars_a)
        self.refused("SHARED_OVMF_VARS")

    def test_G_shared_tpm_state_refused(self):
        path = self.root / TPM_TREATMENT / "state.bin"
        path.unlink()
        os.link(self.root / TPM_CONTROL / "state.bin", path)
        self.refused("SHARED_TPM_STATE")

    def test_H_foreign_transaction_refused(self):
        self.manifest["artifactTransactionId"] = "other-transaction"
        self.refused("FOREIGN_TRANSACTION")

    def test_I_backing_identity_mismatch_refused(self):
        self.manifest["immutableBackingSha256"] = "b" * 64
        self.refused("BACKING_IDENTITY_MISMATCH")

    def test_J_restore_not_proven_even_with_self_reported_witness(self):
        with self.assertRaises(readiness.CheckpointReadinessRefusal) as caught:
            self.check(recovery={
                "windowsBootVerified": True, "restoreVerified": True,
                "claim": "not independently authenticated",
            })
        self.assertEqual(caught.exception.code, "RESTORE_NOT_PROVEN")
        measured = caught.exception.diagnostics
        paths = (self.disk, self.control, self.vars_a, self.vars_b,
                 self.base, self.original_vars)
        self.assertEqual(
            measured["localApparentArtifactBytes"],
            sum(p.stat().st_size for p in paths),
        )
        self.assertEqual(
            measured["localAllocatedArtifactBytes"],
            sum(p.stat().st_blocks * 512 for p in paths),
        )
        for flag in (
            "quotaIndependentlyVerified",
            "sourceProvenanceAuthenticated",
            "externalQemuProcessQuiescenceProven",
            "checkpointInPlaceRecoveryProven",
            "operationalWritesAuthorized",
        ):
            self.assertFalse(measured[flag], flag)
        self.assertGreater(
            measured["physicalRequiredFreeBytesBeforeRun"],
            18 * 1024**3,
        )

    def test_initial_bcd_claim_mismatch_refused(self):
        self.manifest["treatmentBcdSha256"] = "c" * 64
        self.refused("INITIAL_BCD_MISMATCH")

    def test_shared_mutable_overlay_refused(self):
        self.control.unlink()
        os.link(self.disk, self.control)
        self.refused("SHARED_MUTABLE_OVERLAY")

    def test_missing_origin_ovmf_file_refused(self):
        self.original_vars.unlink()
        self.refused("CHECKPOINT_NOT_FOUND")

    def test_fake_quota_never_grants_operational_authority(self):
        # Even a fully fabricated but syntactically well-shaped plan cannot
        # claim restore, guest boot, writer or release eligibility.
        self.refused("RESTORE_NOT_PROVEN")

    def test_module_has_no_guest_writer_or_qemu_execution(self):
        source = (TOOLS / "windows_cachyos_checkpoint_readiness.py").read_text()
        for forbidden in (
            "subprocess.run(", "subprocess.Popen(", "qemu-system-x86_64",
            "guestfs.GuestFS", "grub-install", "efibootmgr -c", "mkfs.",
            "chmod(", "unlink(", "write_bytes(", "open(\"wb\"",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
