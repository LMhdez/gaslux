"""In-memory only QCOW2 native child chain/refusal tests; no block devices."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent/"tools"))

from windows_x64_installed_gpt_ro_audit import DiskAuditError
from windows10_popos_native_child_vm_checkpoint import (
    VM_SIZE, validate_native_child_chain, disposable_native_child,
    require_unchanged_parent_checkpoints,
)


def fixture():
    root = Path("/home/runner/work/_temp/gaslux-win-x64-cowtest")
    base = root / "only-disposable-windows-target.qcow2"
    stage = root / "gaslux-pop-stage.qcow2"
    child = root / "gaslux-pop-native-install.qcow2"
    def record(backing: Path):
        return {
            "format": "qcow2", "virtual-size": VM_SIZE,
            "backing-filename": str(backing), "backing-filename-format": "qcow2",
            "encrypted": False,
        }
    return base, stage, child, record(base), record(stage)


class NativeChildProtectionTests(unittest.TestCase):
    def test_exact_private_nested_stage_child_proposal(self):
        validate_native_child_chain(*fixture())

    def test_refuse_wrong_overlay_backing_or_geometry(self):
        base, stage, child, src_info, dst_info = fixture()
        for field, wrong in (
            ("format", "raw"),
            ("virtual-size", VM_SIZE - 512),
            ("backing-filename", "/dev/nvme0n1"),
            ("backing-filename-format", "raw"),
            ("encrypted", True),
        ):
            for is_stage in (False, True):
                with self.subTest(field=field, stage=is_stage):
                    lhs = copy.deepcopy(src_info)
                    rhs = copy.deepcopy(dst_info)
                    (lhs if is_stage else rhs)[field] = wrong
                    with self.assertRaises(DiskAuditError):
                        validate_native_child_chain(base, stage, child, lhs, rhs)

    def test_refuse_any_disk_file_path_outside_owned_windows_guest(self):
        base, stage, child, src_info, dst_info = fixture()
        for bad_base, bad_stage, bad_child in (
            (Path("/dev/sda"), stage, child),
            (base, Path("/dev/vda"), child),
            (base, stage, Path("/tmp/unowned-pop-native.qcow2")),
            (base, stage, base),
            (base, stage, stage),
            (base, stage, child.with_name("foreign-child.qcow2")),
            (base.with_name("other-win.qcow2"), stage, child),
        ):
            with self.subTest(child=bad_child):
                with self.assertRaises(DiskAuditError):
                    validate_native_child_chain(
                        bad_base, bad_stage, bad_child, src_info, dst_info,
                    )


    def test_refuse_parent_checkpoint_sha_drift_even_when_guest_has_failed(self):
        # Tiny private synthetic files: never a guest, real disk or writer.
        with tempfile.TemporaryDirectory(prefix="gaslux-pop-parent-sha-") as work:
            base = Path(work) / "synthetic-windows.qcow2"
            stage = Path(work) / "synthetic-stage.qcow2"
            original_base = b"windows-readonly-parent"
            original_stage = b"post-windows-boot-gpt-stage"
            base.write_bytes(original_base)
            stage.write_bytes(original_stage)
            base_sha = hashlib.sha256(original_base).hexdigest()
            stage_sha = hashlib.sha256(original_stage).hexdigest()
            require_unchanged_parent_checkpoints(base, stage, base_sha, stage_sha)
            for target, mutated in [
                (base, original_base + b"!"),
                (stage, original_stage + b"!"),
            ]:
                with self.subTest(parent=target.name):
                    saved = target.read_bytes()
                    target.write_bytes(mutated)
                    with self.assertRaises(DiskAuditError):
                        require_unchanged_parent_checkpoints(
                            base, stage, base_sha, stage_sha,
                        )
                    target.write_bytes(saved)
                    require_unchanged_parent_checkpoints(
                        base, stage, base_sha, stage_sha,
                    )
            base.unlink()
            with self.assertRaises(OSError):
                require_unchanged_parent_checkpoints(base, stage, base_sha, stage_sha)

    def test_refuse_absent_live_proof_and_hosted_consent_before_any_create(self):
        base, stage, _, _, _ = fixture()
        with patch.dict(os.environ, {
            "GASLUX_POP_NATIVE_CHILD_COW_CONSENT": "",
        }, clear=True):
            with self.assertRaises(DiskAuditError):
                with disposable_native_child(
                    base, stage, live_guest_gpt_verified=False,
                ):
                    self.fail("not permitted to create child")
        self.assertFalse(base.exists())
        self.assertFalse(stage.exists())


if __name__ == "__main__":
    unittest.main()
