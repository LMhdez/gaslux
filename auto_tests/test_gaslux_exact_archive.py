"""Offline fixed-SHA archive selection contract tests."""
import importlib.util
from pathlib import Path
from unittest import TestCase

PATH = Path(__file__).resolve().parent / "tools/gaslux_branch_prune.py"
spec = importlib.util.spec_from_file_location("gaslux_archive_exact", PATH)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ExactArchiveTests(TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.src = "debug/old-q4os"
        self.candidates = [{"branch": self.src, "sha": self.sha}]

    def test_exact_sha_is_selected(self):
        self.assertEqual(mod.exact_archive_candidates(
            self.candidates, {self.src: self.sha}), self.candidates)

    def test_mismatched_sha_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unverified"):
            mod.exact_archive_candidates(self.candidates, {self.src: "b" * 40})

    def test_protected_or_recent_branch_absent_from_candidates_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unverified"):
            mod.exact_archive_candidates([], {self.src: self.sha})

    def test_invalid_authorization_rejected(self):
        for value in (None, {}, {f"fix/x{i}": self.sha for i in range(7)},
                      {self.src: "bad"}, {"main": self.sha}):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                mod.exact_archive_candidates(self.candidates, value)
