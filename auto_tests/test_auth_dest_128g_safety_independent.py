"""Independent 128-GiB sparse destination hostile-I/O tests on REAL module.

Only temporary owned regular files and harmless short-lived Python subprocesses.
No QEMU guest, QEMU image, hardware disk, Windows, EFI or writer is touched.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from auto_tests.installer_observer import large_sparse_destination as real

GIB = 1024**3


class SparseDestinationIndependentSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gaslux-safety-128g-")
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.workspace.chmod(0o700)
        self.budget = real.LargeReadOnlyBudget(known_quota_bytes=64 * 1024**2)

    def _fd(self, path: Path, data: bytes):
        path.write_bytes(data)
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

    def test_valid_resource_policy_is_structural_only(self):
        self.assertEqual(self.budget.max_virtual_bytes, 128 * GIB)
        self.assertEqual(self.budget.max_qcow2_apparent_bytes, 64 * 1024**2)
        self.assertEqual(self.budget.max_raw_allocated_bytes, 32 * 1024**2)
        self.assertEqual(self.budget.max_qcow2_allocated_bytes, 32 * 1024**2)
        self.assertEqual(self.budget.max_total_allocated_bytes, 64 * 1024**2)
        self.assertEqual(self.budget.max_checkpoint_bytes, 64 * 1024)
        self.assertEqual(self.budget.max_qemu_info_bytes, 64 * 1024)
        self.assertEqual(self.budget.max_seconds, 15)

    def test_oversized_declared_budgets_are_refused(self):
        for field, invalid in (
            ("max_virtual_bytes", 128 * GIB + 1),
            ("max_qcow2_apparent_bytes", 64 * 1024**2 + 1),
            ("max_raw_allocated_bytes", 32 * 1024**2 + 1),
            ("max_qcow2_allocated_bytes", 32 * 1024**2 + 1),
            ("max_total_allocated_bytes", 64 * 1024**2 + 1),
            ("max_checkpoint_bytes", 64 * 1024 + 1),
            ("max_qemu_info_bytes", 64 * 1024 + 1),
            ("max_seconds", 31),
        ):
            with self.subTest(field=field), self.assertRaises(real.LargeDestinationRefused):
                real.LargeReadOnlyBudget(
                    **{**vars(self.budget), field: invalid},
                )

    def test_missing_or_forged_quota_is_not_proof_of_capacity(self):
        with self.assertRaisesRegex(real.LargeDestinationRefused, "INVALID_QUOTA_CLAIM"):
            real.LargeReadOnlyBudget(known_quota_bytes=0)
        self.assertIsNone(real.LargeReadOnlyBudget(known_quota_bytes=None).known_quota_bytes)

    def test_positive_pinned_sparse_fd_and_foreign_fd_alias(self):
        original = self.workspace / "original.raw"
        other = self.workspace / "foreign.raw"
        for path in (original, other):
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            try:
                os.ftruncate(fd, 128 * GIB)
            finally:
                os.close(fd)
        fd1 = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
        fd2 = os.open(other, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            accepted = real._pin_sparse(fd1, original, self.workspace, 128 * GIB)
            self.assertEqual(accepted.st_size, 128 * GIB)
            with self.assertRaisesRegex(
                real.LargeDestinationRefused, "SPARSE_FOREIGN_FD_OR_GEOMETRY"
            ):
                real._pin_sparse(fd2, original, self.workspace, 128 * GIB)
            # Same external path now names another inode although FD remains open.
            os.replace(other, original)
            with self.assertRaisesRegex(
                real.LargeDestinationRefused, "SPARSE_FOREIGN_FD_OR_GEOMETRY"
            ):
                real._pin_sparse(fd1, original, self.workspace, 128 * GIB)
        finally:
            os.close(fd1)
            os.close(fd2)

    def test_pinned_sparse_descriptor_refuses_closed_and_symlink(self):
        raw = self.workspace / "original.raw"
        fd = os.open(raw, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.ftruncate(fd, 128 * GIB)
        os.close(fd)
        with self.assertRaisesRegex(real.LargeDestinationRefused, "SPARSE_FD_STAT_FAILED"):
            real._pin_sparse(fd, raw, self.workspace, 128 * GIB)
        raw.rename(self.workspace / "real.raw")
        raw.symlink_to("real.raw")
        fd = os.open(self.workspace / "real.raw", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with self.assertRaisesRegex(real.LargeDestinationRefused, "SPARSE_PATH_UNOWNED"):
                real._pin_sparse(fd, raw, self.workspace, 128 * GIB)
        finally:
            os.close(fd)

    def test_pread_full_bytes_success_then_short_refused_even_if_positive(self):
        data = b"Q" * 1024
        path = self.workspace / "private.bin"
        fd = self._fd(path, data)
        try:
            deadline = time.monotonic() + 5
            self.assertEqual(real._read_exact(fd, 0, len(data), deadline), data)
            original_pread = os.pread
            with patch.object(real.os, "pread", side_effect=lambda x, n, off: original_pread(x, n // 2, off)):
                with self.assertRaisesRegex(real.LargeDestinationRefused, "SPARSE_SHORT_READ"):
                    real._read_exact(fd, 0, len(data), deadline)
        finally:
            os.close(fd)

    def test_pread_eio_and_premature_eof_refused(self):
        path = self.workspace / "read.bin"
        fd = self._fd(path, b"A" * 1024)
        try:
            deadline = time.monotonic() + 4
            with self.assertRaisesRegex(real.LargeDestinationRefused, "SPARSE_SHORT_READ"):
                real._read_exact(fd, 512, 1024, deadline)
            with patch.object(real.os, "pread", side_effect=OSError(errno.EIO, "fault")):
                with self.assertRaisesRegex(real.LargeDestinationRefused, "SPARSE_READ_IO_FAILED"):
                    real._read_exact(fd, 0, 1024, deadline)
        finally:
            os.close(fd)

    def test_real_small_digest_accepts_complete_hash_and_denies_prefix(self):
        path = self.workspace / "overlay.qcow2"
        data = b"Z" * 2048
        fd = self._fd(path, data)
        try:
            digest = hashlib.sha256(data).hexdigest()
            self.assertEqual(
                real._small_full_digest(fd, digest, self.budget, time.monotonic() + 5),
                digest,
            )
            original_pread = os.pread
            with patch.object(
                real.os, "pread",
                side_effect=lambda x, n, off: original_pread(x, n // 2, off),
            ):
                with self.assertRaisesRegex(real.LargeDestinationRefused, "SPARSE_SHORT_READ"):
                    real._small_full_digest(
                        fd, hashlib.sha256(data[:1024]).hexdigest(),
                        self.budget, time.monotonic() + 5,
                    )
        finally:
            os.close(fd)

    def test_real_small_digest_concurrent_inplace_mutation_fails_closed(self):
        path = self.workspace / "overlay.qcow2"
        data = b"M" * 1024
        fd = self._fd(path, data)
        original_pread = os.pread
        called = []

        def mutate(x, n, off):
            result = original_pread(x, n, off)
            if x == fd and not called:
                called.append(True)
                with path.open("r+b") as stream:
                    stream.write(b"N")
            return result

        try:
            with patch.object(real.os, "pread", side_effect=mutate):
                with self.assertRaisesRegex(
                    real.LargeDestinationRefused, "HASH_CONCURRENT_MUTATION"
                ):
                    real._small_full_digest(
                        fd, hashlib.sha256(data).hexdigest(),
                        self.budget, time.monotonic() + 5,
                    )
            self.assertTrue(called)
        finally:
            os.close(fd)

    def _run_bounded_subprocess(self, script: str, max_output: int = 64 * 1024, seconds=2):
        path = self.workspace / "fd.bin"
        fd = self._fd(path, b"safe-local-file")
        started = []
        original_popen = subprocess.Popen

        def substitute(_cmd, **kwargs):
            process = original_popen([sys.executable, "-c", script], **kwargs)
            started.append(process)
            return process

        budget = real.LargeReadOnlyBudget(
            known_quota_bytes=64 * 1024**2,
            max_qemu_info_bytes=max_output,
        )
        try:
            with patch.object(real.subprocess, "Popen", side_effect=substitute):
                try:
                    result = real._bounded_info(
                        fd, budget, time.monotonic() + seconds
                    )
                    return result, started
                except real.LargeDestinationRefused as exc:
                    return exc, started
        finally:
            os.close(fd)

    def test_qemu_info_positive_synthetic_chain_is_parser_only(self):
        script = (
            "import json,sys;"
            "sys.stdout.write(json.dumps([{'format':'qcow2'},{'format':'raw'}]));"
            "sys.stdout.flush()"
        )
        result, processes = self._run_bounded_subprocess(script)
        self.assertEqual(len(result), 2)
        self.assertEqual([x["format"] for x in result], ["qcow2", "raw"])
        self.assertEqual(processes[0].returncode, 0)

    def test_qemu_info_output_over_limit_is_denied_and_process_reaped(self):
        script = "import sys;sys.stdout.write('x'*4096);sys.stdout.flush()"
        refused, processes = self._run_bounded_subprocess(script, max_output=256)
        self.assertEqual(refused.code, "QEMU_INFO_OUTPUT_LIMIT")
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_qemu_info_truncated_json_denied_and_reaped(self):
        script = "import sys;sys.stdout.write('{');sys.stdout.flush()"
        refused, processes = self._run_bounded_subprocess(script)
        self.assertEqual(refused.code, "QEMU_INFO_INVALID_JSON")
        self.assertIsNotNone(processes[0].poll())

    def test_qemu_info_bad_depth_denied(self):
        script = "import json;print(json.dumps([{'format':'raw'}]))"
        refused, _ = self._run_bounded_subprocess(script)
        self.assertEqual(refused.code, "QEMU_INFO_BACKING_DEPTH")

    def test_qemu_info_timeout_kills_and_reaps_child(self):
        script = "import time;time.sleep(60)"
        refused, processes = self._run_bounded_subprocess(script, seconds=0.15)
        self.assertIn(
            refused.code,
            ("QEMU_INFO_TIMEOUT", "READONLY_INSPECTION_TIMEOUT"),
        )
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())


if __name__ == "__main__":
    unittest.main()
