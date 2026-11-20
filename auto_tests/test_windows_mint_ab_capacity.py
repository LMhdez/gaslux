"""Byte-level fail-closed A/B capacity and evidence tests, no VM."""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows_mint_ab_capacity as cap


def filesystem(free: int):
    blocks = 10_000_000_000
    return SimpleNamespace(f_frsize=4096, f_blocks=blocks,
                           f_bavail=free // 4096, f_bfree=free // 4096)


class MintAbCapacityTests(unittest.TestCase):
    def test_early_capacity_shortfall_is_fail_closed_no_compression_discount(self):
        with tempfile.TemporaryDirectory() as d:
            full = cap.VIRTUAL_BYTES + 256*1024**2
            need = cap.EARLY_IMAGES * full + cap.EARLY_RESERVE
            with patch.object(cap.os, "statvfs", return_value=filesystem(need-4096)):
                report = cap.measure_capacity(
                    directory=Path(d), phase="early", full_allocated_bytes=full)
            self.assertEqual(report["result"], "BLOCKED_CAPACITY")
            self.assertGreater(report["capacityShortfallBytes"], 0)
            self.assertFalse(report["compressionAssumedForCapacity"])
            self.assertIs(report["checkpointReadyForReview"], False)

    def test_exact_free_limit_is_accepted_without_claiming_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            full = cap.VIRTUAL_BYTES
            need = cap.EARLY_IMAGES * full + cap.EARLY_RESERVE
            with patch.object(cap.os, "statvfs", return_value=filesystem(need)):
                r = cap.measure_capacity(directory=Path(d), phase="early",
                                         full_allocated_bytes=full)
            self.assertEqual(r["effectiveAvailableBytes"], need)
            self.assertEqual(r["result"], "PASS")
            self.assertIs(r["checkpointReadyForReview"], False)
            self.assertIs(r["windowsGuestBootsAuthorized"], False)

    def test_quota_lower_than_filesystem_capacity_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            full = cap.VIRTUAL_BYTES
            need = cap.EARLY_IMAGES * full + cap.EARLY_RESERVE
            with patch.object(cap.os, "statvfs", return_value=filesystem(need+4096)):
                r = cap.measure_capacity(
                    directory=Path(d), phase="early",
                    full_allocated_bytes=full, quota_remaining_bytes=need-1)
            self.assertEqual(r["quotaStatus"], "measured")
            self.assertEqual(r["effectiveAvailableBytes"], need-1)
            self.assertEqual(r["result"], "BLOCKED_CAPACITY")

    def test_no_allocation_bound_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(cap.CapacityError, "unproved"):
                cap.measure_capacity(directory=Path(d), phase="early",
                                     full_allocated_bytes=2048)

    def test_late_phase_uses_four_full_images_and_records_actual_source_storage(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root/"backing.qcow2"
            source.write_bytes(b"w"*1024)
            checkpoint = root/"checkpoint"
            checkpoint.mkdir()
            overlay = checkpoint/"overlay.qcow2"
            overlay.write_bytes(b"x"*1024)
            need = cap.LATE_IMAGES*cap.VIRTUAL_BYTES + cap.LATE_RESERVE
            with patch.object(cap.os, "statvfs", return_value=filesystem(need+4096)):
                result = cap.measure_capacity(directory=root, phase="late",
                    full_allocated_bytes=cap.VIRTUAL_BYTES,
                    base=source, overlay=overlay)
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["worstCaseRemainingStandaloneImagesAndRestores"], 4)
            self.assertEqual(result["existingOwnedImageStats"]["windowsBacking"]["apparentBytes"], 1024)
            self.assertGreaterEqual(result["existingOwnedImageStats"]["preparedMintOverlay"]["allocatedBytes"], 1024)

    def test_late_phase_rejects_forged_source_relationship(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            b = root/"base"; b.write_bytes(b"w")
            o = root/"unexpected"/"nested"/"overlay"
            o.parent.mkdir(parents=True)
            o.write_bytes(b"x")
            with self.assertRaisesRegex(cap.CapacityError, "relationship"):
                cap.measure_capacity(directory=root, phase="late",
                    full_allocated_bytes=cap.VIRTUAL_BYTES, base=b, overlay=o)

    def test_late_phase_rejects_volume_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            b = root/"base"; b.write_bytes(b"w")
            sub = root/"checkpoint"; sub.mkdir()
            o = sub/"overlay"; o.write_bytes(b"x")
            original = Path.stat
            def other_volume(self, *args, **kwargs):
                s = original(self, *args, **kwargs)
                if self == o:
                    data = dict((name, getattr(s, name)) for name in
                                ("st_mode", "st_uid", "st_nlink", "st_size",
                                 "st_blocks", "st_dev"))
                    data["st_dev"] = s.st_dev+999
                    return SimpleNamespace(**data)
                return s
            with patch.object(Path, "stat", other_volume):
                with self.assertRaisesRegex(cap.CapacityError, "different filesystems"):
                    cap.measure_capacity(directory=root, phase="late",
                        full_allocated_bytes=cap.VIRTUAL_BYTES, base=b, overlay=o)

    def test_qemu_measure_rejects_incomplete_data(self):
        for payload in ({"required": 100}, {"fully-allocated": 100, "required": 0},
                        {"fully-allocated": cap.VIRTUAL_BYTES, "required": cap.VIRTUAL_BYTES+1}):
            with self.subTest(payload=payload):
                with patch.object(cap.subprocess, "run",
                     return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                    with self.assertRaises(cap.CapacityError):
                        cap.qemu_fully_allocated_bytes()

    def test_exclusive_evidence_is_not_overwritten_or_marked_ready(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root/"mint-ab-capacity-early.json"
            report = {"result": "BLOCKED_CAPACITY", "checkpointReadyForReview": False}
            cap.evidence(p, report)
            self.assertEqual(json.loads(p.read_text()), report)
            with self.assertRaisesRegex(cap.CapacityError, "unsafe"):
                cap.evidence(p, {"result": "PASS"})

    def test_enospc_creating_manifest_is_never_success(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"mint-ab-capacity-early.json"
            with patch.object(cap.os, "open", side_effect=OSError(errno.ENOSPC, "full")):
                with self.assertRaises(OSError) as raised:
                    cap.evidence(p, {"result": "PASS"})
            self.assertEqual(raised.exception.errno, errno.ENOSPC)
            self.assertFalse(p.exists())

    def test_enospc_during_clone_cannot_create_checkpoint_proof(self):
        # Capacity and conversion are separate gates: no success marker can
        # materialise after a failed qemu-img conversion.
        import windows_mint_ab_checkpoint as cp
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with patch.object(cp, "command", side_effect=OSError(errno.ENOSPC, "full")):
                with self.assertRaises(OSError):
                    cp.standalone(root/"source.qcow2", root/"arm-a.qcow2", root)
            self.assertFalse((root/"checkpoint.json").exists())


if __name__ == "__main__":
    unittest.main()
