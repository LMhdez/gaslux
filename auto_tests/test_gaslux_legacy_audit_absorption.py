"""Fail-closed tests for exact legacy audit branch preservation.

No network, Git ref mutation, or disk operations.
"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

PATH = Path(__file__).resolve().parent / "tools/gaslux_branch_prune.py"
spec = importlib.util.spec_from_file_location("gaslux_legacy_audit_lease", PATH)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class LegacyAuditAbsorptionTests(TestCase):
    def setUp(self):
        self.branch = "automation/gaslux-15m-integration-audit"
        self.src_sha = "a" * 40
        self.dst_sha = "b" * 40
        self.refs = {self.branch: self.src_sha, mod.CONTROL: self.dst_sha}
        self.approval = {self.branch: {
            "sha": self.src_sha,
            "keeper": mod.CONTROL,
            "keeper_sha": self.dst_sha,
        }}

    def verify(self, *, ancestry=True, protected=()):
        with patch.object(mod, "is_ancestor", return_value=ancestry), \
             patch.object(mod, "git", return_value=SimpleNamespace(stdout="100")), \
             patch.object(mod.time, "time", return_value=100000):
            return mod.exact_absorbed_candidates(
                self.refs, set(protected), self.approval)

    def test_one_pinned_legacy_audit_can_be_preserved(self):
        self.assertEqual(self.verify(), [(
            self.branch, self.src_sha, mod.CONTROL, self.dst_sha)])

    def test_protected_branch_is_never_removed(self):
        with self.assertRaisesRegex(RuntimeError, "protected"):
            self.verify(protected=[self.branch])

    def test_unproven_ancestry_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            self.verify(ancestry=False)

    def test_modified_keeper_sha_is_rejected(self):
        self.refs[mod.CONTROL] = "c" * 40
        with self.assertRaisesRegex(RuntimeError, "changed"):
            self.verify()

    def test_any_other_automation_source_is_rejected(self):
        self.approval = {"automation/another-audit": {
            "sha": self.src_sha, "keeper": mod.CONTROL,
            "keeper_sha": self.dst_sha}}
        with self.assertRaisesRegex(RuntimeError, "malformed"):
            self.verify()
