"""Compact QEMU target ownership and capacity guard regression tests."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/compact_ovmf_target.py"
SPEC = importlib.util.spec_from_file_location("compact_ovmf_target", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class CompactOvmfTargetTests(unittest.TestCase):
    def test_compact_topology_is_below_85_gib(self):
        plan = mod.plan(available_bytes=85 * mod.GIB)
        self.assertEqual(plan["status"], "CAPACITY_ONLY_OK")
        self.assertEqual(plan["planned_peak_bytes"], 80 * mod.GIB)
        self.assertEqual(plan["virtual_disk_bytes"], 60 * mod.GIB)
        self.assertFalse(plan["lab_writer_admitted"])
        self.assertFalse(plan["mint_guest_installed"])
        self.assertFalse(plan["windows_recovery_verified"])

    def test_insufficient_capacity_denied(self):
        p = mod.plan(available_bytes=79 * mod.GIB)
        self.assertEqual(p["status"], "BLOCKED_STORAGE")
        self.assertEqual(p["deficit_bytes"], mod.GIB)
        self.assertFalse(p["lab_writer_admitted"])

    def test_oversized_budget_denied(self):
        with self.assertRaisesRegex(ValueError, "85-GiB"):
            mod.plan(available_bytes=100 * mod.GIB, disk_gib=70)

    def test_bad_numeric_inputs_denied(self):
        for x in (True, 1.5, -1, None, 2**64):
            with self.subTest(x=x), self.assertRaises(ValueError):
                mod.plan(available_bytes=x)
        for value in (True, 0, -1, 90):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mod.plan(available_bytes=90 * mod.GIB, disk_gib=value)

    def test_symlink_workspace_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                mod.trusted_parent(alias)

    def test_untrusted_relative_or_file_workspace_denied(self):
        with self.assertRaisesRegex(ValueError, "absolute"):
            mod.trusted_parent(Path("relative"))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "file"
            p.write_text("data")
            with self.assertRaisesRegex(ValueError, "not a directory"):
                mod.trusted_parent(p)

    def test_hard_deny_host_device_paths(self):
        with self.assertRaises(ValueError):
            mod.trusted_parent(Path("/"))

    def test_reject_backing_file_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "disk.qcow2"
            disk.write_bytes(b"dummy")
            qemu = {
                "format": "qcow2",
                "virtual-size": mod.VIRTUAL_GIB * mod.GIB,
                "actual-size": 65536,
                "backing-filename": "base.qcow2",
            }
            with patch.object(mod.subprocess, "run") as proc:
                proc.return_value.stdout = json.dumps(qemu)
                with self.assertRaisesRegex(ValueError, "Backing"):
                    mod.inspect_qcow2(disk)
                self.assertEqual(proc.call_args.args[0][1], "info")

    def test_wrong_size_and_preallocation_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "disk.qcow2"
            disk.write_bytes(b"dummy")
            for item in (
                {"format": "raw", "virtual-size": mod.VIRTUAL_GIB * mod.GIB},
                {"format": "qcow2", "virtual-size": 50 * mod.GIB},
                {"format": "qcow2", "virtual-size": mod.VIRTUAL_GIB * mod.GIB,
                 "actual-size": 129 * 1024**2},
            ):
                with self.subTest(item=item), patch.object(mod.subprocess, "run") as proc:
                    proc.return_value.stdout = json.dumps(item)
                    with self.assertRaises(ValueError):
                        mod.inspect_qcow2(disk)

    def test_failed_creation_cleans_private_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(mod.shutil, "disk_usage") as free:
                free.return_value.free = 85 * mod.GIB
                with patch.object(mod.subprocess, "run", side_effect=RuntimeError("qemu failed")):
                    with self.assertRaisesRegex(RuntimeError, "qemu failed"):
                        mod.provision(root)
            self.assertFalse(any(root.iterdir()))

    def test_low_capacity_never_invokes_qemu_img(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(mod.shutil, "disk_usage") as free:
                free.return_value.free = 4 * mod.GIB
                with patch.object(mod.subprocess, "run") as proc:
                    p = mod.provision(root)
                    self.assertEqual(p["status"], "BLOCKED_STORAGE")
                    proc.assert_not_called()
            self.assertFalse(any(root.iterdir()))

    def test_qcow2_no_backing_and_no_writer_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = {
                "format": "qcow2", "virtual-size": mod.VIRTUAL_GIB * mod.GIB,
                "actual-size": 196608, "backing-filename": None,
            }
            def fake_run(args, **kwargs):
                if args[1] == "create":
                    Path(args[-2]).write_bytes(b"test")
                return type("Process", (), {"stdout": json.dumps(metadata)})()
            with patch.object(mod.shutil, "disk_usage") as free:
                free.return_value.free = 85 * mod.GIB
                with patch.object(mod.subprocess, "run", side_effect=fake_run):
                    result = mod.provision(root)
            self.assertTrue(Path(result["disk_path"]).is_file())
            self.assertFalse(result["lab_writer_admitted"])
            self.assertFalse(result["writer_enabled"])
            self.assertFalse(result["qemu_img"]["backing_file_present"])


    def test_restore_identity_rejects_foreign_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / "baseline.qcow2"
            overlay = root / "overlay.qcow2"
            baseline.write_bytes(b"base")
            overlay.write_bytes(b"overlay")
            metadata = [
                {"format": "qcow2", "virtual-size": 16 * 1024**2,
                 "full-backing-filename": str(root / "wrong.qcow2")},
                {"format": "qcow2", "virtual-size": 16 * 1024**2,
                 "filename": str(root / "wrong.qcow2")},
            ]
            with patch.object(mod, "_run_qemu", return_value=json.dumps(metadata)):
                with self.assertRaisesRegex(ValueError, "backing identity"):
                    mod._assert_overlay_backing(overlay, baseline)

    def test_restore_owned_file_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "source.qcow2"
            base.write_bytes(b"owned")
            mod._owned_regular(base, root)
            alias = root / "alias.qcow2"
            alias.symlink_to(base)
            with self.assertRaisesRegex(ValueError, "unowned"):
                mod._owned_regular(alias, root)
            alias.unlink()
            import os
            os.link(base, alias)
            with self.assertRaisesRegex(ValueError, "unowned"):
                mod._owned_regular(base, root)

    def test_corrupt_qcow2_auto_detected_as_raw_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            corrupt = Path(tmp) / "corrupt.qcow2"
            corrupt.write_bytes(b"not-a-qcow2")
            with patch.object(mod.subprocess, "run") as proc:
                proc.return_value.returncode = 0
                proc.return_value.stdout = b'{"format":"raw","virtual-size":12}'
                mod._require_corrupt_image_rejected(corrupt, qemu_img="qemu-img")

    def test_corrupt_qcow2_false_validity_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            corrupt = Path(tmp) / "corrupt.qcow2"
            corrupt.write_bytes(b"not-a-qcow2")
            with patch.object(mod.subprocess, "run") as proc:
                proc.return_value.returncode = 0
                proc.return_value.stdout = b'{"format":"qcow2","virtual-size":12}'
                with self.assertRaisesRegex(ValueError, "accepted as QCOW2"):
                    mod._require_corrupt_image_rejected(corrupt, qemu_img="qemu-img")

    def test_missing_ovmf_vars_stops_before_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(FileNotFoundError):
                mod.prove_restore_fixture(root, root / "missing.fd")
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
