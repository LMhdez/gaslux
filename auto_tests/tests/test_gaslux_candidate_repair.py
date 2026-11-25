"""Exact review-bound successor candidate contract."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_candidate_repair as repair


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.base, self.head, self.key = "a" * 40, "b" * 40, "c" * 64
        self.path = "assets/live/gaslux_candidate_handoff.py"
        self.prior = b"def missing(x):\n    return x\n"
        self.row = {"base": self.base, "head": self.head, "key": self.key,
                    "pr": 123, "role": "zorin", "rejected": {
                        self.path: {"ast_sha256": repair.semantic_hash(self.prior),
                                    "addition": self.prior.decode()}},
                    "reviews": [{"id": 77, "actor": 456, "body_sha256": "d" * 64,
                                 "excerpt": "The function ignores the missing evidence."}]}

    def test_bind_context_and_reject_equivalent_code(self):
        with patch.dict(os.environ, {repair.REPAIR_ENV: json.dumps(self.row)}):
            row = repair.context(self.base, self.key)
            self.assertEqual(row, self.row)
            self.assertEqual(repair.suffix(row), "-r123-" + self.head[:12])
            self.assertIn("UNTRUSTED DATA", repair.feedback(row, self.path))
            with self.assertRaises(ValueError):
                repair.context("e" * 40, self.key)
            with self.assertRaises(ValueError):
                repair.require_changed(row, {self.path: b"def missing(x):\n    return (x)\n"})
            with self.assertRaises(ValueError):
                repair.require_changed(row, {"other.py": self.prior})
            repair.require_changed(row, {self.path: b"def missing(x):\n    return False\n"})
            self.assertNotEqual(repair.digest(row), repair.digest(dict(row, pr=124)))

    def test_review_identity_and_exact_commit(self):
        import gaslux_distro_admission as admission
        rows = [
            {"id": 77, "user": {"id": 456}, "commit_id": self.head,
             "state": "CHANGES_REQUESTED", "body": "finding"},
            {"id": 78, "user": {"id": 999}, "commit_id": self.head,
             "state": "CHANGES_REQUESTED", "body": "forged"},
            {"id": 79, "user": {"id": 456}, "commit_id": self.base,
             "state": "CHANGES_REQUESTED", "body": "stale"},
            {"id": 80, "user": {"id": 456}, "commit_id": self.head,
             "state": "COMMENTED", "body": "not rejected"},
        ]
        with patch.object(admission, "api", return_value=rows):
            result = repair.negative_reviews(admission, 123, self.head, (456, 321))
        self.assertEqual([r["id"] for r in result], [77])


if __name__ == "__main__":
    unittest.main()
