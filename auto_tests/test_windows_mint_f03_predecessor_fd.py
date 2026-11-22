"""M-278-01: actual Mint F-03 predecessor FD identity/read-boundary regressions.

Includes intentional RED cases against the 7b8954a1 predecessor pathname-reopen
implementation. No guest boots, physical disks, real Windows or system ESP.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows_mint_ab_forensic as mint


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MintF03FixedPredecessorTests(unittest.TestCase):
    def setUp(self):
        self.owned = tempfile.TemporaryDirectory(prefix="mint-f03-fd-")
        self.addCleanup(self.owned.cleanup)
        self.evidence = Path(self.owned.name) / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.transaction = "mint-f03-test-transaction"
        self.env = patch.dict(
            os.environ, {"GITHUB_RUN_ID": "9001", "GITHUB_SHA": "a" * 40}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.valid = {
            "transactionId": self.transaction, "result": "PASS",
            "authorizedForProduction": False,
        }
        for phase, names in mint.F03_PREDECESSOR_FILES.items():
            for key, filename in names.items():
                path = self.evidence / filename
                if not path.exists():
                    if key == "earlyCapacity":
                        record = {
                            "schema": "gaslux-mint-ab-capacity-v1",
                            "phase": "early", "result": "PASS",
                            "githubRunId": "9001", "sourceCommit": "a" * 40,
                        }
                    else:
                        record = self.valid
                    path.write_text(json.dumps(record, sort_keys=True))
        self.checkpoint = self.evidence / "mint-ab-checkpoint.json"

    def expected(self, phase: str) -> dict:
        return {
            key: digest((self.evidence / file).read_bytes())
            for key, file in mint.F03_PREDECESSOR_FILES[phase].items()
        }

    def inspect(self, phase: str = "before_windows_a", expected=None):
        return mint.authenticated_predecessor_status(
            phase=phase,
            evidence=self.evidence,
            transaction_id=self.transaction,
            supplied_sha256=self.expected(phase) if expected is None else expected,
        )

    def test_four_f03_phases_accept_their_exact_valid_predecessor_bytes(self):
        for phase in mint.F03_EVIDENCE_PHASES:
            with self.subTest(phase=phase):
                status, problems = self.inspect(phase)
                self.assertEqual(problems, [])
                self.assertEqual(set(status), set(mint.F03_PREDECESSOR_FILES[phase]))
                self.assertTrue(all(item["sha256Matched"] for item in status.values()))

    def test_real_module_never_reopens_path_for_hash_or_json(self):
        expected = self.expected("before_windows_a")
        with (
            patch.object(mint, "sha256_file",
                         side_effect=AssertionError("pathname sha256_file forbidden")),
            patch.object(Path, "read_bytes",
                         side_effect=AssertionError("pathname read_bytes forbidden")),
        ):
            status, problems = self.inspect(expected=expected)
        self.assertEqual(problems, [])
        self.assertTrue(all(v["sha256Matched"] for v in status.values()))

    def _intercept_first_file_read(self, callback):
        original = os.read
        original_fstat = os.fstat
        inode = self.checkpoint.stat().st_ino
        fired = []

        def intercept(fd, n):
            record = original_fstat(fd)
            if not fired and record.st_ino == inode and stat.S_ISREG(record.st_mode):
                fired.append(True)
                callback()
            return original(fd, n)

        return patch.object(os, "read", side_effect=intercept), fired

    def test_rename_replacement_after_fd_open_is_refused(self):
        original = self.expected("before_windows_a")

        def mutation():
            self.checkpoint.rename(self.evidence / "old-checkpoint-private.json")
            self.checkpoint.write_text(json.dumps({
                "transactionId": self.transaction, "result": "PASS",
                "forged": "new pathname contents",
            }))

        hook, fired = self._intercept_first_file_read(mutation)
        with hook:
            status, issues = self.inspect(expected=original)
        self.assertTrue(fired, "test did not inject a rename after FD open")
        self.assertTrue(any(x["predecessor"] == "checkpoint" for x in issues))
        self.assertFalse(status["checkpoint"]["sha256Matched"])

    def test_late_symlink_after_fd_open_is_refused(self):
        original = self.expected("before_windows_a")

        def mutation():
            old = self.evidence / "renamed-authentic-checkpoint.json"
            self.checkpoint.rename(old)
            self.checkpoint.symlink_to(old)

        hook, fired = self._intercept_first_file_read(mutation)
        with hook:
            status, issues = self.inspect(expected=original)
        self.assertTrue(fired, "symlink injection was not exercised")
        self.assertTrue(any(x["predecessor"] == "checkpoint" for x in issues))
        self.assertFalse(status["checkpoint"]["sha256Matched"])

    def test_in_place_mutation_during_fd_read_is_refused(self):
        original = self.expected("before_windows_a")

        def mutation():
            # Same inode and same length: ctime/mtime MUST still be rechecked.
            data = self.checkpoint.read_bytes().replace(b"PASS", b"FAIL")
            self.checkpoint.write_bytes(data)

        hook, fired = self._intercept_first_file_read(mutation)
        with hook:
            status, issues = self.inspect(expected=original)
        self.assertTrue(fired, "in-place mutation injection was not exercised")
        self.assertTrue(any(x["predecessor"] == "checkpoint" for x in issues))
        self.assertFalse(status["checkpoint"]["sha256Matched"])

    def test_in_place_mutation_after_read_before_final_stat_is_refused(self):
        original = self.expected("before_windows_a")
        raw_read = os.read
        inode = self.checkpoint.stat().st_ino
        fired = []

        def read_and_mutate(fd, n):
            data = raw_read(fd, n)
            if not fired and os.fstat(fd).st_ino == inode:
                fired.append(True)
                self.checkpoint.write_bytes(self.checkpoint.read_bytes().replace(
                    b"PASS", b"FAIL"))
            return data

        with patch.object(os, "read", side_effect=read_and_mutate):
            status, issues = self.inspect(expected=original)
        self.assertTrue(fired)
        self.assertFalse(status["checkpoint"]["sha256Matched"])
        self.assertTrue(issues)

    def test_invalid_expected_sha_and_modified_payload_are_denied(self):
        expected = self.expected("before_windows_a")
        expected["checkpoint"] = "0" * 64
        self.assertTrue(self.inspect(expected=expected)[1])
        self.checkpoint.write_text('{"transactionId":"mint-f03-test-transaction"}')
        self.assertFalse(self.inspect(expected={
            **expected, "checkpoint": digest(b"not-the-file"),
        })[0]["checkpoint"]["sha256Matched"])

    def test_invalid_json_matching_digest_and_foreign_transaction_are_denied(self):
        for record, expected_issue in (
            (b'{"transactionId":', "invalid_predecessor_json"),
            (json.dumps({"transactionId": "different", "result": "PASS"}).encode(),
             "foreign_predecessor_transaction"),
        ):
            with self.subTest(reason=expected_issue):
                self.checkpoint.write_bytes(record)
                expected = self.expected("before_windows_a")
                status, issues = self.inspect(expected=expected)
                self.assertFalse(status["checkpoint"]["sha256Matched"])
                self.assertIn(expected_issue, [x["issue"] for x in issues])

    def test_hardlink_uid_inode_identity_mismatch_are_denied(self):
        expected = self.expected("before_windows_a")
        copy = self.evidence / "hardlink-to-checkpoint"
        os.link(self.checkpoint, copy)
        self.assertTrue(self.inspect(expected=expected)[1])
        copy.unlink()
        real_fstat = os.fstat
        real_inode = self.checkpoint.stat().st_ino
        for attr, change in (
            ("st_uid", os.getuid() + 1),
            ("st_ino", real_inode + 1),
            ("st_nlink", 2),
        ):
            with self.subTest(attr=attr):
                def forged(fd, attr=attr, change=change):
                    st = real_fstat(fd)
                    if st.st_ino != real_inode:
                        return st
                    fields = (
                        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                        "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
                    )
                    attrs = {k: getattr(st, k) for k in fields}
                    attrs[attr] = change
                    return types.SimpleNamespace(**attrs)

                with patch.object(os, "fstat", side_effect=forged):
                    status, issues = self.inspect(expected=expected)
                self.assertTrue(issues, attr)
                self.assertFalse(status["checkpoint"]["sha256Matched"], attr)

    def test_short_read_eof_and_read_error_are_denied(self):
        initial = self.expected("before_windows_a")
        inode = self.checkpoint.stat().st_ino
        raw_read = os.read
        raw_fstat = os.fstat
        for fault in ("short", "read_error"):
            with self.subTest(fault=fault):
                fired = []

                def broken(fd, n, fault=fault):
                    if raw_fstat(fd).st_ino == inode:
                        fired.append(True)
                        if fault == "short":
                            return b""
                        raise OSError(5, "synthetic EIO during fixed FD read")
                    return raw_read(fd, n)

                with patch.object(os, "read", side_effect=broken):
                    status, issues = self.inspect(expected=initial)
                self.assertTrue(fired)
                self.assertTrue(issues)
                self.assertFalse(status["checkpoint"]["sha256Matched"])

    def test_predecessor_above_2mb_is_denied_before_reading(self):
        self.checkpoint.write_bytes(b"x" * 2_000_001)
        status, issues = self.inspect()
        self.assertFalse(status["checkpoint"]["sha256Matched"])
        self.assertIn("oversized_predecessor", [x["issue"] for x in issues])

    def test_missing_and_late_symlink_predecessors_are_denied(self):
        expected = self.expected("before_windows_a")
        moved = self.evidence / "checkpoint-moved-for-test"
        self.checkpoint.rename(moved)
        self.assertTrue(self.inspect(expected=expected)[1])
        self.checkpoint.symlink_to(moved)
        status, issues = self.inspect(expected=expected)
        self.assertTrue(issues)
        self.assertFalse(status["checkpoint"]["sha256Matched"])

    def test_early_capacity_run_commit_and_normal_transaction_are_enforced(self):
        cap = self.evidence / "mint-ab-capacity-early.json"
        original = json.loads(cap.read_text())
        original["githubRunId"] = "other-run"
        cap.write_text(json.dumps(original))
        expected = self.expected("before_windows_a")
        self.assertIn("foreign_preflight_run", [
            x["issue"] for x in self.inspect(expected=expected)[1]
        ])
        cap.write_text(json.dumps({
            "schema": "gaslux-mint-ab-capacity-v1", "result": "PASS",
            "githubRunId": "9001", "sourceCommit": "a" * 40,
        }))
        expected = self.expected("before_windows_a")
        self.assertEqual(self.inspect(expected=expected)[1], [])

    def test_f03_gate_publishes_blocked_evidence_without_boot_authority(self):
        self.checkpoint.write_text('{"transactionId":"foreign","result":"PASS"}')
        expected = self.expected("before_windows_a")
        complete = {
            "fileInventories": {
                resource: {"available": True, "fileSha256": {"/fixed": "a" * 64}}
                for resource in ("esp", "recovery")
            }
        }
        with self.assertRaisesRegex(mint.ForensicError, "F-03"):
            mint.require_complete_forensic_inventories(
                phase="before_windows_a",
                sources={"arm_a_preboot": complete, "arm_b_preboot": complete},
                transaction_id=self.transaction,
                evidence=self.evidence,
                preceding_sha256=expected,
            )
        gate = json.loads(
            (self.evidence / mint.F03_EVIDENCE_PHASES["before_windows_a"][0]).read_text()
        )
        self.assertEqual(gate["result"], "BLOCKED_EVIDENCE")
        self.assertFalse(gate["nextGuestBootAuthorizedByThisGate"])
        self.assertIn("windows_a", gate["subsequentBootsBlocked"])


if __name__ == "__main__":
    unittest.main()
