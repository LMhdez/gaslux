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

    def test_actual_equivalence_requires_same_prefix_suite_and_fixed_semantics(self):
        from gaslux_agent_feature_factory import repair_addition, TASKS
        role = "zorin"
        path, suite, _ = TASKS[role]
        suite = "auto_tests/tests/" + suite
        parent = "d" * 40
        prefix = b"# original source\n"
        addition = repair_addition(role).encode()
        old = {"pr": 395, "head": OLD}
        new = {"pr": 409, "head": NEW}
        for scenario in ("valid", "source_drift", "test_drift", "semantic_change", "hold"):
            def api(method, route):
                self.assertEqual(method, "GET")
                if route in ("/pulls/395", "/pulls/409"):
                    return {"state": "open", "draft": True,
                            "user": {"login": "github-actions[bot]", "id": 41898282},
                            "head": {"sha": OLD if route.endswith("395") else NEW}}
                if route == f"/compare/{parent}...{BASE}":
                    return {"status": "ahead", "merge_base_commit": {"sha": parent}}
                if route.endswith("comments?per_page=100"):
                    return [{"body": "SAFETY HOLD"}] if scenario == "hold" else []
                self.fail(route)
            def source_at(name, ref):
                if name == suite:
                    return b"# drift\n" if scenario == "test_drift" and ref == BASE else b"# tests\n"
                if ref == parent:
                    return prefix
                if ref == BASE:
                    return b"# drift\n" if scenario == "source_drift" else prefix
                if ref == OLD:
                    return prefix.rstrip(b"\n") + b"\n\n\n" + addition
                if ref == NEW:
                    normalized = addition.replace(b"missing = sorted", b"missingGates = sorted").replace(
                        b'"missingGates": missing,', b'"missingGates": missingGates,')
                    if scenario == "semantic_change":
                        normalized = normalized.replace(b'"releaseEligible": False', b'"releaseEligible": True')
                    return prefix.rstrip(b"\n") + b"\n\n\n" + normalized
                self.fail(ref)
            with patch.object(rec.admission, "api", side_effect=api), \
                 patch.object(rec.admission, "source_at", side_effect=source_at), \
                 patch.object(rec.admission, "candidate_append", side_effect=[(parent, None), (BASE, None)]):
                if scenario == "semantic_change":
                    with self.assertRaises(ValueError):
                        rec.equivalent(old, new, role, BASE)
                else:
                    self.assertEqual(rec.equivalent(old, new, role, BASE), scenario == "valid")

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


    def test_historical_inventory_classifies_without_mutating(self):
        repo = {"full_name": rec.admission.REPO}
        prs = [{"number": n, "state": "open", "draft": True,
                "head": {"sha": sha, "repo": repo},
                "base": {"ref": "dev", "repo": repo}}
               for n, sha in ((1, OLD), (2, NEW))]
        prs.append({"number": 3, "state": "open", "draft": True,
                    "head": {"sha": OLD, "repo": {"full_name": "foreign/repo"}},
                    "base": {"ref": "dev", "repo": repo}})
        def api(method, route):
            self.assertEqual(method, "GET")
            if route.startswith("/git/ref/heads/"):
                return {"object": {"sha": BASE}}
            if route.startswith("/pulls?"):
                return prs
            if route == f"/compare/{OLD}...{BASE}":
                return {"base_commit": {"sha": OLD}, "merge_base_commit": {"sha": OLD},
                        "status": "ahead", "ahead_by": 2, "behind_by": 0}
            if route == f"/compare/{NEW}...{BASE}":
                return {"base_commit": {"sha": NEW}, "merge_base_commit": {"sha": OLD},
                        "status": "diverged", "ahead_by": 2, "behind_by": 1}
            self.fail(route)
        with patch.object(rec.admission, "api", side_effect=api):
            report = rec.historical_inventory(slot=0)
        self.assertEqual(report["total_open"], 3)
        self.assertEqual([row["status"] for row in report["findings"]],
                         ["ANCESTRY_PRESENT_REVIEW_CLOSURE",
                          "UNIQUE_COMMITS_REQUIRE_RECONCILIATION", "UNSUPPORTED_OR_FOREIGN"])
        self.assertFalse(report["close_authorized"])
        self.assertTrue(all(not row["close_authorized"] for row in report["findings"]))

    def test_historical_inventory_rotation_and_drift(self):
        repo = {"full_name": rec.admission.REPO}
        prs = [{"number": n, "state": "open", "draft": True,
                "head": {"sha": OLD, "repo": repo}, "base": {"ref": "dev", "repo": repo}}
               for n in range(1, 102)]
        for drift in (False, True):
            calls = 0
            def api(method, route):
                nonlocal calls
                self.assertEqual(method, "GET")
                if route.startswith("/git/ref/heads/"):
                    calls += 1
                    return {"object": {"sha": NEW if drift and calls > 2 else BASE}}
                if route.startswith("/pulls?"):
                    return prs[:100] if route.endswith("page=1") else prs[100:]
                if route == f"/compare/{OLD}...{BASE}":
                    return {"base_commit": {"sha": OLD}, "merge_base_commit": {"sha": OLD},
                            "status": "ahead", "ahead_by": 1, "behind_by": 0}
                self.fail(route)
            with patch.object(rec.admission, "api", side_effect=api):
                if drift:
                    with self.assertRaises(ValueError):
                        rec.historical_inventory(slot=10)
                else:
                    report = rec.historical_inventory(slot=10)
                    self.assertEqual(report["total_open"], 101)
                    self.assertEqual(report["batches"], 11)
                    self.assertEqual([row["pr"] for row in report["findings"]], [101])


if __name__ == "__main__":
    unittest.main()
