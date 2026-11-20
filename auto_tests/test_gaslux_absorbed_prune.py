"""Offline gate for branches incorporated into another pinned live ref."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

PATH = Path(__file__).resolve().parent / "tools/gaslux_branch_prune.py"
spec = importlib.util.spec_from_file_location("gaslux_prune_absorbed", PATH)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class AbsorbedGateTests(TestCase):
    def setUp(self):
        self.source = "fix/old-safe"
        self.keeper = "fix/new-safe"
        self.sha = "a" * 40
        self.to_sha = "b" * 40
        self.refs = {self.source: self.sha, self.keeper: self.to_sha}
        self.auth = {self.source: {
            "sha": self.sha, "keeper": self.keeper, "keeper_sha": self.to_sha}}

    def call(self, protect=(), ancestry=True, now=100000):
        with patch.object(mod.time, "time", return_value=now), \
             patch.object(mod, "git", return_value=SimpleNamespace(stdout="100")), \
             patch.object(mod, "is_ancestor", return_value=ancestry):
            return mod.exact_absorbed_candidates(self.refs, set(protect), self.auth)

    def test_verified_source_and_successor(self):
        self.assertEqual(self.call(), [(self.source, self.sha, self.keeper, self.to_sha)])

    def test_rejects_changed_successor_tip(self):
        self.refs[self.keeper] = "c" * 40
        with self.assertRaisesRegex(RuntimeError, "changed"):
            self.call()

    def test_rejects_protected_source(self):
        with self.assertRaisesRegex(RuntimeError, "protected"):
            self.call(protect=[self.source])

    def test_rejects_unrelated_history(self):
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            self.call(ancestry=False)

    def test_rejects_recent_source(self):
        with self.assertRaisesRegex(RuntimeError, "young"):
            self.call(now=1000)

    def test_rejects_bad_or_large_request(self):
        for bad in (None, {}, {f"fix/{i}": {} for i in range(5)},
                    {self.source: {"sha": self.sha}}):
            with self.subTest(value=bad):
                with self.assertRaises(RuntimeError):
                    with patch.object(mod, "git", return_value=SimpleNamespace(stdout="100")):
                        mod.exact_absorbed_candidates(self.refs, set(), bad)
