"""No-media, no-guest regressions for the rebased Windows GPT-only COW lab.

PR #159 originally guarded an earlier overlay/thirdboot implementation. This
suite targets the replacement in PR #192 without reintroducing parallel disk
writers or granting production installation authority.
"""
from __future__ import annotations

import inspect
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import windows_cachyos_real_windows_gpt_cow_transaction as txn


class WindowsGptCowRebasedContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gaslux-gpt-cow-guards-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = self.root / "only-disposable-windows-target.qcow2"
        self.overlay_dir = self.root / "gaslux-windows-linux-gpt-test"
        self.overlay_dir.mkdir(mode=0o700)
        self.overlay = self.overlay_dir / "fresh-transaction-only.qcow2"

    def test_missing_consent_stops_before_disk_inspection(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(txn, "owned_base", return_value=None), \
             patch.object(txn, "qcow2_file_identity",
                          side_effect=AssertionError("unexpected disk inspection")):
            with self.assertRaisesRegex(txn.GeometryError, "consent"):
                txn.trial(self.base)

    def test_reused_overlay_stops_before_qemu(self):
        self.overlay.write_bytes(b"synthetic-not-a-qcow2-file")
        with patch.object(txn, "command",
                          side_effect=AssertionError("unexpected qemu-img")):
            with self.assertRaisesRegex(txn.GeometryError, "reused"):
                txn.allocate_overlay(self.base, self.overlay)

    def test_symlink_overlay_stops_before_qemu(self):
        target = self.root / "foreign.qcow2"
        target.write_bytes(b"synthetic-not-a-windows-disk")
        self.overlay.symlink_to(target)
        with patch.object(txn, "command",
                          side_effect=AssertionError("unexpected qemu-img")):
            with self.assertRaisesRegex(txn.GeometryError, "reused"):
                txn.allocate_overlay(self.base, self.overlay)

    def test_foreign_overlay_rejected_without_disk_command(self):
        foreign = self.root / "foreign-directory"
        foreign.mkdir()
        overlay = foreign / "fresh-transaction-only.qcow2"
        overlay.write_bytes(b"synthetic-only")
        with patch.object(txn, "command",
                          side_effect=AssertionError("unexpected qemu-img")):
            with self.assertRaisesRegex(txn.GeometryError, "unowned"):
                txn.verify_overlay(self.base, overlay)

    def test_transaction_confined_to_cow_and_verifies_windows_hashes(self):
        source = inspect.getsource(txn.trial)
        self.assertIn("inspect_owned_disk(base)", source)
        self.assertIn("require_unchanged_qcow2(base, identity)", source)
        self.assertIn("overlay.unlink()", source)
        self.assertIn('"storageWritesAuthorized": False', source)
        self.assertIn('"sameDiskDualBootVerified": False', source)
        self.assertIn('"inPlaceWindowsRollbackVerified": False', source)
        self.assertIn('"linuxSystemInstalled": False', source)
        self.assertNotIn("sgdisk --clear", source)
        self.assertNotIn("mkfs", source)

    def test_exact_fifth_gpt_and_first_four_windows_entries_guarded(self):
        source = inspect.getsource(txn.verify_fifth_entry)
        self.assertIn("actual[:512] == original[:512]", source)
        self.assertIn("not any(actual[5*128:])", source)
        self.assertIn("LINUX_TYPE", source)
        self.assertIn("LINUX_GUID", source)
        self.assertIn("first % 2048 == 0", source)
        self.assertIn("not any(fifth) and actual == original", source)


if __name__ == "__main__":
    unittest.main()
