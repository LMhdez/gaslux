"""M-278-01: exercise REAL Mint module against pathname/descriptor races.

All files are owned private synthetic evidence. No QEMU guest or Windows disk.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows_mint_ab_forensic as forensic


class MintF03PinnedPredecessorTests(unittest.TestCase):
    TRANSACTION = "m27801-synthetic-transaction"
    RUN = "778899"
    COMMIT = "a" * 40

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mint-m27801-")
        self.addCleanup(self.tmp.cleanup)
        self.evidence = Path(self.tmp.name) / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.env = patch.dict(
            os.environ,
            {"GITHUB_RUN_ID": self.RUN, "GITHUB_SHA": self.COMMIT},
        )
        self.env.start()
        self.addCleanup(self.env.stop)

    @staticmethod
    def _digest(data):
        return hashlib.sha256(data).hexdigest()

    def _make_phase(self, phase="before_windows_a"):
        hashes = {}
        paths = {}
        for key, filename in forensic.F03_PREDECESSOR_FILES[phase].items():
            record = (
                {
                    "schema": "gaslux-mint-ab-capacity-v1",
                    "result": "PASS",
                    "githubRunId": self.RUN,
                    "sourceCommit": self.COMMIT,
                }
                if key == "earlyCapacity"
                else {"transactionId": self.TRANSACTION, "result": "PASS", "sentinel": "A"}
            )
            content = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
            target = self.evidence / filename
            target.write_bytes(content)
            target.chmod(0o600)
            hashes[key] = self._digest(content)
            paths[key] = target
        return hashes, paths

    def _check(self, phase, hashes):
        return forensic.authenticated_predecessor_status(
            phase=phase,
            evidence=self.evidence,
            transaction_id=self.TRANSACTION,
            supplied_sha256=hashes,
        )

    def _assert_denied(self, phase, hashes, key):
        status, issues = self._check(phase, hashes)
        self.assertFalse(status[key]["sha256Matched"])
        self.assertTrue(any(x["predecessor"] == key for x in issues))
        return issues

    def test_a_valid_predecessors_in_all_four_f03_phases(self):
        for phase in forensic.F03_EVIDENCE_PHASES:
            with self.subTest(phase=phase):
                hashes, _ = self._make_phase(phase)
                status, issues = self._check(phase, hashes)
                self.assertEqual(issues, [])
                self.assertEqual(set(status), set(hashes))
                self.assertTrue(all(x["sha256Matched"] for x in status.values()))
                for p in forensic.F03_PREDECESSOR_FILES[phase].values():
                    (self.evidence / p).unlink()

    def test_b_rename_symlink_and_same_inode_mutation_cannot_mix_hash_and_json(self):
        """RED against actual legacy sha256_file(path)->read_bytes(path).

        When the fixed implementation uses os.read on a pinned FD, inject the
        same change after a read, before identity/content revalidation.
        """
        for attack in ("rename", "symlink", "inplace"):
            with self.subTest(attack=attack):
                hashes, paths = self._make_phase()
                target = paths["checkpoint"]
                inode = target.stat().st_ino
                modified = False
                original_hash = forensic.sha256_file
                original_read = os.read

                def alter(*, attack=attack, target=target):
                    nonlocal modified
                    if modified:
                        return
                    modified = True
                    if attack == "inplace":
                        original = target.read_bytes()
                        changed = original.replace(b'"sentinel": "A"', b'"sentinel": "B"')
                        self.assertNotEqual(original, changed)
                        self.assertEqual(len(original), len(changed))
                        with target.open("r+b") as handle:
                            handle.write(changed)
                            handle.flush()
                            os.fsync(handle.fileno())
                    else:
                        target.rename(target.with_suffix(".moved"))
                        foreign = self.evidence / "foreign-payload.json"
                        foreign.write_bytes(
                            json.dumps(
                                {
                                    "transactionId": self.TRANSACTION,
                                    "result": "PASS",
                                    "sentinel": "B",
                                }
                            ).encode()
                        )
                        if attack == "symlink":
                            target.symlink_to(foreign)
                        else:
                            target.write_bytes(foreign.read_bytes())

                def legacy_hash(path, original_hash=original_hash, target=target):
                    digest = original_hash(path)
                    if path == target:
                        alter()
                    return digest

                def pinned_read(fd, size, original_read=original_read, inode=inode):
                    data = original_read(fd, size)
                    if os.fstat(fd).st_ino == inode and data:
                        alter()
                    return data

                with (
                    patch.object(forensic, "sha256_file", side_effect=legacy_hash),
                    patch.object(forensic.os, "read", side_effect=pinned_read),
                ):
                    self._assert_denied("before_windows_a", hashes, "checkpoint")
                self.assertTrue(modified, "the adversarial mutation must execute")
                for item in self.evidence.iterdir():
                    item.unlink()

    def test_c_symlink_before_open_rejected(self):
        hashes, paths = self._make_phase()
        target = paths["checkpoint"]
        payload = self.evidence / "other.json"
        payload.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(payload)
        self._assert_denied("before_windows_a", hashes, "checkpoint")

    def test_d_rename_between_open_and_read_is_denied(self):
        hashes, paths = self._make_phase()
        target = paths["checkpoint"]
        original_open = os.open
        changed = False

        def attack_open(name, flags, *args, **kwargs):
            nonlocal changed
            fd = original_open(name, flags, *args, **kwargs)
            if name == target.name and not changed:
                changed = True
                target.rename(target.with_suffix(".moved"))
                target.write_bytes(
                    b'{"transactionId":"' + self.TRANSACTION.encode() + b'","result":"PASS"}'
                )
            return fd

        with patch.object(forensic.os, "open", side_effect=attack_open):
            self._assert_denied("before_windows_a", hashes, "checkpoint")
        self.assertTrue(changed)

    def test_e_wrong_hash_and_invalid_json_refused(self):
        hashes, paths = self._make_phase()
        hashes["checkpoint"] = "f" * 64
        self._assert_denied("before_windows_a", hashes, "checkpoint")
        paths["checkpoint"].write_bytes(b"{malformed")
        hashes["checkpoint"] = self._digest(b"{malformed")
        self._assert_denied("before_windows_a", hashes, "checkpoint")

    def test_f_foreign_transaction_and_failed_prior_gate_refused(self):
        for forged in (
            {"transactionId": "other-transaction", "result": "PASS"},
            {"transactionId": self.TRANSACTION, "result": "BLOCKED_EVIDENCE"},
        ):
            hashes, paths = self._make_phase()
            payload = json.dumps(forged).encode()
            paths["checkpoint"].write_bytes(payload)
            hashes["checkpoint"] = self._digest(payload)
            self._assert_denied("before_windows_a", hashes, "checkpoint")
            for p in paths.values():
                p.unlink()

    def test_g_early_capacity_foreign_run_and_commit_refused(self):
        for field, wrong in (("githubRunId", "another-run"), ("sourceCommit", "b" * 40)):
            hashes, paths = self._make_phase()
            source = paths["earlyCapacity"]
            data = json.loads(source.read_bytes())
            data[field] = wrong
            blob = json.dumps(data).encode()
            source.write_bytes(blob)
            hashes["earlyCapacity"] = self._digest(blob)
            self._assert_denied("before_windows_a", hashes, "earlyCapacity")
            for p in paths.values():
                p.unlink()

    def test_h_ownership_link_count_and_inode_invalid(self):
        for fault in ("hardlink", "uid", "inode"):
            with self.subTest(fault=fault):
                hashes, paths = self._make_phase()
                target = paths["checkpoint"]
                original_fstat = os.fstat
                original_stat = os.stat
                if fault == "hardlink":
                    os.link(target, self.evidence / "another-hardlink")
                elif fault == "uid":
                    inode = target.stat().st_ino

                    def wrong_uid(fd, original_fstat=original_fstat, inode=inode):
                        info = original_fstat(fd)
                        if info.st_ino != inode:
                            return info
                        return types.SimpleNamespace(
                            **{
                                key: getattr(info, key) + (1 if key == "st_uid" else 0)
                                for key in (
                                    "st_mode",
                                    "st_uid",
                                    "st_dev",
                                    "st_ino",
                                    "st_nlink",
                                    "st_size",
                                    "st_mtime_ns",
                                    "st_ctime_ns",
                                )
                            }
                        )
                else:

                    def wrong_inode(
                        name, *args, original_stat=original_stat, target=target, **kwargs
                    ):
                        info = original_stat(name, *args, **kwargs)
                        if name != target.name or kwargs.get("dir_fd") is None:
                            return info
                        return types.SimpleNamespace(
                            **{
                                key: getattr(info, key) + (1 if key == "st_ino" else 0)
                                for key in (
                                    "st_mode",
                                    "st_uid",
                                    "st_dev",
                                    "st_ino",
                                    "st_nlink",
                                    "st_size",
                                    "st_mtime_ns",
                                    "st_ctime_ns",
                                )
                            }
                        )

                with (
                    patch.object(forensic.os, "fstat", side_effect=wrong_uid)
                    if fault == "uid"
                    else patch.object(forensic, "re", wraps=forensic.re),
                    patch.object(forensic.os, "stat", side_effect=wrong_inode)
                    if fault == "inode"
                    else patch.object(forensic, "re", wraps=forensic.re),
                ):
                    self._assert_denied("before_windows_a", hashes, "checkpoint")
                for item in self.evidence.iterdir():
                    item.unlink()

    def test_i_eof_short_read_and_eio_fail_closed(self):
        for fault in ("eof", "eio"):
            with self.subTest(fault=fault):
                hashes, paths = self._make_phase()
                inode = paths["checkpoint"].stat().st_ino
                real_read = os.read

                def read(fd, count, inode=inode, fault=fault, real_read=real_read):
                    if os.fstat(fd).st_ino == inode:
                        if fault == "eio":
                            raise OSError(errno.EIO, "synthetic EIO")
                        return b""
                    return real_read(fd, count)

                with patch.object(forensic.os, "read", side_effect=read):
                    self._assert_denied("before_windows_a", hashes, "checkpoint")
                for p in paths.values():
                    p.unlink()

    def test_j_oversized_predecessor_and_untrusted_evidence_dir(self):
        hashes, paths = self._make_phase()
        data = b"a" * 2_000_001
        paths["checkpoint"].write_bytes(data)
        hashes["checkpoint"] = self._digest(data)
        self._assert_denied("before_windows_a", hashes, "checkpoint")
        self.evidence.chmod(0o777)
        try:
            with self.assertRaises(forensic.ForensicError):
                self._check("before_windows_a", hashes)
        finally:
            self.evidence.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
