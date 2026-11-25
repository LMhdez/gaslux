"""Duplicate closure must preserve both histories and refuse drift."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_agent_reconcile as rec

BASE, OLD, NEW = "a" * 40, "b" * 40, "c" * 40
PICK = {"old": 395, "old_head": OLD, "keep": 409, "keep_head": NEW,
        "role": "zorin", "base": BASE}
ENV = {"GITHUB_REPOSITORY": rec.admission.REPO, "GITHUB_REF": "refs/heads/main",
       "GITHUB_EVENT_NAME": "schedule", "GASLUX_AUTONOMY_PAUSED": "false"}


class ReconcileTests(unittest.TestCase):
    def test_dry_run_and_idle_never_mutate(self):
        with patch.object(rec, "plan", return_value=PICK), patch.object(rec.admission, "api") as api:
            self.assertEqual(rec.reconcile()["status"], "eligible_duplicate")
            api.assert_not_called()
        with patch.object(rec, "plan", return_value=None), patch.object(rec.admission, "api") as api:
            self.assertEqual(rec.reconcile()["status"], "idle")
            api.assert_not_called()

    def test_only_trusted_unpaused_runtime_can_close(self):
        for change in ({"GITHUB_REF": "refs/heads/dev"}, {"GITHUB_EVENT_NAME": "pull_request"},
                       {"GITHUB_REPOSITORY": "other/repo"}, {"GASLUX_AUTONOMY_PAUSED": "TRUE"}):
            with patch.dict("os.environ", {**ENV, **change}, clear=True), patch.object(rec, "plan") as plan:
                with self.assertRaises(RuntimeError):
                    rec.reconcile(execute=True)
                plan.assert_not_called()

    def test_close_exact_duplicate_and_detect_concurrent_drift(self):
        for scenario in ("success", "before", "after"):
            calls = []
            def api(method, route, body=None):
                calls.append((method, route, body))
                if route == "/issues/395/comments?per_page=100":
                    return []
                if route == "/issues/395/comments":
                    self.assertEqual(method, "POST")
                    return {"id": 123}
                if route == "/pulls/395":
                    self.assertEqual((method, body), ("PATCH", {"state": "closed"}))
                    return {"state": "closed", "merged": False,
                            "head": {"sha": "d" * 40 if scenario == "after" else OLD}}
                if route == "/pulls/409":
                    return {"state": "open", "head": {"sha": NEW}}
                if route == "/git/ref/heads/dev":
                    return {"object": {"sha": BASE}}
                self.fail(route)
            with patch.dict("os.environ", ENV, clear=True), \
                 patch.object(rec, "plan", side_effect=[PICK, None if scenario == "before" else PICK]), \
                 patch.object(rec.admission, "api", side_effect=api):
                if scenario == "after":
                    with self.assertRaisesRegex(RuntimeError, "Concurrent metadata drift"):
                        rec.reconcile(execute=True)
                else:
                    result = rec.reconcile(execute=True)
                    self.assertEqual(result["status"], "drift_before_close" if scenario == "before" else "duplicate_closed")
                    self.assertFalse(result["merge_authorized"])
            writes = [(m, r) for m, r, _ in calls if m != "GET"]
            self.assertEqual(writes, [("POST", "/issues/395/comments")] +
                             ([] if scenario == "before" else [("PATCH", "/pulls/395")]))

    def test_plan_refuses_unknown_third_candidate_bad_ci_hold_or_drift(self):
        def row(number, head, current):
            return {"pr": number, "head": head, "base": BASE,
                    "current_base_verified": current, "technical_objection": False,
                    "exact_scope_verified": True, "ci_verified": True,
                    "ci_workflow_provenance_verified": True, "merge_authorized": False,
                    "release_eligible": False}
        for scenario in ("valid", "third", "ci", "hold", "scope", "both_stale", "different"):
            old = row(395, OLD, False)
            new = row(409, NEW, scenario != "both_stale")
            if scenario == "ci":
                new["ci_verified"] = False
            if scenario == "hold":
                old["technical_objection"] = True
            if scenario == "scope":
                new["exact_scope_verified"] = False
            def api(method, route):
                if route == "/git/ref/heads/dev":
                    return {"object": {"sha": BASE}}
                if route == "/pulls?state=open&base=dev&per_page=100":
                    return [{"number": n, "head": {"ref": f"bot/gaslux-feature-zorin-{n:012x}",
                            "repo": {"full_name": rec.admission.REPO}}}
                            for n in ([395, 409, 500] if scenario == "third" else [395, 409])]
                self.fail(route)
            with patch.object(rec.admission, "api", side_effect=api), \
                 patch.object(rec.admission, "discover_candidates", return_value={395: ("zorin", OLD), 409: ("zorin", NEW)}), \
                 patch.object(rec.admission, "inspect", side_effect=[old, new]), \
                 patch.object(rec, "equivalent", return_value=scenario != "different"):
                self.assertEqual(rec.plan(), PICK if scenario == "valid" else None)


if __name__ == "__main__":
    unittest.main()
