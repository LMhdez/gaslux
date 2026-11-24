"""Adversarial tests of the distro admission stage; no GitHub network."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_distro_admission as gate

HEAD = "a" * 40
BASE = "b" * 40


class AdmissionTests(unittest.TestCase):
    def review(self, **updates):
        return {"user": {"id": 2}, "state": "APPROVED", "commit_id": HEAD,
                "body": f"GASLUX-SAFETY-V1 head={HEAD} base={BASE}", **updates}

    def test_exact_review(self):
        self.assertTrue(gate.review_ok([self.review()], 2, 1, HEAD, BASE))

    def test_review_absent_self_or_unconfigured(self):
        for rows, reviewer in [([], 2), ([self.review()], None), ([self.review()], 1)]:
            self.assertFalse(gate.review_ok(rows, reviewer, 1, HEAD, BASE))

    def test_stale_dismissed_wrong_actor_or_comment(self):
        for changes in [{"commit_id": BASE}, {"body": "SAFETY_APPROVED"},
                        {"state": "DISMISSED"}, {"state": "COMMENTED"},
                        {"user": {"id": 3}}]:
            self.assertFalse(gate.review_ok([self.review(**changes)], 2, 1, HEAD, BASE))

    def test_objection(self):
        self.assertFalse(gate.review_ok(
            [self.review(), self.review(state="CHANGES_REQUESTED")], 2, 1, HEAD, BASE))

    def test_page_truncation(self):
        with self.assertRaises(ValueError):
            gate.complete_page([{}] * 100)

    def test_required_ci(self):
        rows = [{"name": name, "head_sha": HEAD, "status": "completed",
                 "conclusion": "success", "app": {"slug": "github-actions"}}
                for name in gate.COMMON_CHECKS | {"read-only-contracts"}]
        data = {"total_count": len(rows), "check_runs": rows}
        self.assertTrue(gate.checks_ok(data, HEAD, "zorin"))
        self.assertFalse(gate.checks_ok(data, HEAD, "cachyos"))
        self.assertFalse(gate.checks_ok({"total_count": 0, "check_runs": []}, HEAD, "zorin"))
        self.assertFalse(gate.checks_ok({**data, "total_count": 101}, HEAD, "zorin"))
        for field, value in [("head_sha", BASE), ("conclusion", "skipped"),
                             ("status", "in_progress"), ("app", {"slug": "other"})]:
            modified = [{**rows[0], field: value}, *rows[1:]]
            self.assertFalse(gate.checks_ok({**data, "check_runs": modified}, HEAD, "zorin"))

    def test_append_no_execution(self):
        before = b"# original\n"
        after = before + b"\ndef assess_zorin_lifecycle(evidence: dict) -> dict:\n    return {}\n"
        with patch.object(gate, "validate_addition") as validator:
            gate.exact_append(before, after, "zorin")
            self.assertEqual(validator.call_args.kwargs, {"execute": False})
        with self.assertRaises(ValueError):
            gate.exact_append(before, b"# replaced\n" + after, "zorin")

    def test_formatted_append_requires_exact_separator(self):
        before = b"# original\n"
        after = before + b"\n\ndef assess_zorin_lifecycle(evidence: dict) -> dict:\n    return {}\n"
        with patch.object(gate, "validate_addition"):
            gate.exact_append(before, after, "zorin", formatted=True)
            with self.assertRaises(ValueError):
                gate.exact_append(before, after, "zorin")

    def test_repaired_candidate_and_semantic_change(self):
        generated = "c" * 40
        path = "assets/live/example.py"
        pr = {"commits": 2, "head": {"ref": f"bot/gaslux-feature-zorin-{BASE[:12]}"}}
        before = b"# original\n"
        original = before + (
            b"\ndef assess_zorin_lifecycle(evidence: dict) -> dict:\n"
            b"    return {'safe': False}\n"
        )
        formatted = before + (
            b'\n\ndef assess_zorin_lifecycle(evidence: dict) -> dict:\n'
            b'    return {"safe": False}\n'
        )
        for final in (formatted, formatted.replace(b"False", b"True")):
            with (
                patch.object(gate, "single_parent", side_effect=[generated, BASE]),
                patch.object(gate, "one_path_commit") as scope,
                patch.object(gate, "source_at", side_effect=[before, original, final]),
                patch.object(gate, "validate_addition") as validator,
                patch.object(gate, "api", return_value={"author": {"id": 9}}),
            ):
                if final == formatted:
                    self.assertEqual(gate.candidate_append(pr, "zorin", HEAD, path), (BASE, 9))
                    self.assertEqual(scope.call_count, 2)
                    self.assertEqual(validator.call_count, 2)
                else:
                    with self.assertRaises(ValueError):
                        gate.candidate_append(pr, "zorin", HEAD, path)

    def test_intermediate_offscope_commit_rejected(self):
        good = {"status": "ahead", "ahead_by": 1, "behind_by": 0, "total_commits": 1,
                "merge_base_commit": {"sha": BASE},
                "files": [{"filename": "allowed.py", "status": "modified"}]}
        with patch.object(gate, "api", return_value=good):
            gate.one_path_commit(BASE, HEAD, "allowed.py")
        for changed in ({**good, "files": good["files"] + [{"filename": "other.py"}]},
                        {**good, "ahead_by": 2}, {**good, "behind_by": 1}):
            with patch.object(gate, "api", return_value=changed):
                with self.assertRaises(ValueError):
                    gate.one_path_commit(BASE, HEAD, "allowed.py")

    def test_unsupported_history_rejected(self):
        for count in (0, 3, True, "2"):
            with self.assertRaises(ValueError):
                gate.candidate_append({"commits": count}, "zorin", HEAD, "allowed.py")

    def test_api_failure_is_blocked(self):
        with patch.object(gate, "api", side_effect=RuntimeError("offline")):
            row = gate.inspect(395, "zorin", 2)
        self.assertEqual(row["status"], "blocked")
        self.assertFalse(row["merge_authorized"])
        self.assertFalse(row["release_eligible"])
        self.assertFalse(row["safety_review_verified"])


if __name__ == "__main__":
    unittest.main()
