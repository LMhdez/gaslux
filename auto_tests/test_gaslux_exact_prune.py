"""Safe, offline exact-ancestry pruning selection tests."""
import importlib.util
from pathlib import Path
from unittest import TestCase

PATH = Path(__file__).resolve().parent / "tools/gaslux_branch_prune.py"
spec = importlib.util.spec_from_file_location("gaslux_prune_exact", PATH)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SHA = "a" * 40
SOURCE = "fix/safe-old-branch"
TARGET = "fix/kept-pr-head"

class ExactPruneTests(TestCase):
    def setUp(self):
        self.report = {
            "candidates": [{"branch": SOURCE, "sha": SHA,
                            "reachable_from": [TARGET]}],
            "keeper_refs": ["main", "dev", TARGET],
        }
        self.approval = {SOURCE: {"sha": SHA, "preserved_in": TARGET}}

    def test_exact_source_sha_and_keeper(self):
        selected = mod.exact_prune_candidates(self.report, self.approval)
        self.assertEqual([(x["branch"], keep) for x, keep in selected],
                         [(SOURCE, TARGET)])

    def test_missing_candidate_is_rejected(self):
        self.report["candidates"] = []
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            mod.exact_prune_candidates(self.report, self.approval)

    def test_changed_source_sha_is_rejected(self):
        self.approval[SOURCE]["sha"] = "b" * 40
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            mod.exact_prune_candidates(self.report, self.approval)

    def test_wrong_keeper_is_rejected(self):
        self.approval[SOURCE]["preserved_in"] = "main"
        with self.assertRaisesRegex(RuntimeError, "unproven"):
            mod.exact_prune_candidates(self.report, self.approval)

    def test_bad_or_unbounded_authorization_is_rejected(self):
        for value in (None, {}, {str(i): {} for i in range(4)}):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                mod.exact_prune_candidates(self.report, value)
