"""Safety gate: full-size file quota must be preallocated and cannot claim guest installation."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
from unittest.mock import patch
import unittest

SRC = Path(__file__).resolve().parents[1] / "tools/compact_fullscale_quota_lab.py"
sys.path.insert(0, str(SRC.parent))
SPEC = importlib.util.spec_from_file_location("gaslux_fullscale_quota", SRC)
assert SPEC is not None and SPEC.loader is not None
full = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(full)


class FullscaleQuotaTests(unittest.TestCase):
    def test_exact_pool_size_and_independent_host_reserve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            required = full.POOL_BYTES + full.HOST_RESERVE
            with patch.object(full.shutil, "disk_usage",
                              return_value=SimpleNamespace(free=required)):
                report = full.capacity_only(root)
                self.assertEqual(report["status"], "CAPACITY_PREFLIGHT_OK")
                self.assertFalse(report["guest_writer_admitted"])
                self.assertFalse(report["mint_guest_installed"])
                self.assertFalse(report["real_windows_media_verified"])
            with patch.object(full.shutil, "disk_usage",
                              return_value=SimpleNamespace(free=required - 1)):
                report = full.capacity_only(root)
                self.assertEqual(report["status"], "BLOCKED_STORAGE")
                self.assertEqual(report["deficit_bytes"], 1)
            for size, reserve in (
                (0, full.HOST_RESERVE),
                (59 * full.GIB, full.HOST_RESERVE),
                (61 * full.GIB, full.HOST_RESERVE),
                (full.POOL_BYTES, full.HOST_RESERVE - 1),
                (True, full.HOST_RESERVE),
            ):
                with self.assertRaises(ValueError):
                    full.capacity_only(root, bytes_needed=size, reserve=reserve)

    def test_low_storage_never_creates_or_mounts_anything(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(full.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=20 * full.GIB)), \
             patch.object(full.tempfile, "mkdtemp") as created, \
             patch.object(full.os, "posix_fallocate") as alloc:
            report = full.full_fixture(Path(tmp))
            self.assertEqual(report["status"], "BLOCKED_STORAGE")
            created.assert_not_called()
            alloc.assert_not_called()

    def test_preflight_only_never_allocates_at_sufficient_capacity(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(full.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=100 * full.GIB)), \
             patch.object(full.tempfile, "mkdtemp") as created:
            report = full.full_fixture(Path(tmp), preflight_only=True)
            self.assertEqual(report["status"], "CAPACITY_PREFLIGHT_OK")
            created.assert_not_called()

    def test_source_does_not_claim_windows_boot_or_arbitrary_quota(self):
        raw = SRC.read_text()
        self.assertIn("os.posix_fallocate", raw)
        self.assertIn("st.st_blocks * 512", raw)
        self.assertIn("loop_mount_verified", raw)
        self.assertIn('enospc_60gib_exhaustion_demonstrated": False', raw)
        self.assertNotIn("qemu-system", raw)
        self.assertNotIn("libertix-install-main.sh", raw)
        self.assertNotIn("diskpart", raw)


if __name__ == "__main__":
    unittest.main()
