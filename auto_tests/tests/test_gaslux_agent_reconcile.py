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


    def test_exact_historical_closure_requires_identical_tree_and_no_discussion(self):
        repo = {"full_name": rec.admission.REPO}
        row = {"pr": 500, "head": OLD, "base": BASE, "target": "dev", "draft": True,
               "unique_head_commits": 0, "status": "ANCESTRY_PRESENT_REVIEW_CLOSURE"}
        for scenario in ("valid", "different_tree", "advanced_empty_diff", "advanced_nonempty_diff", "comment", "human", "unique", "drift", "squash_equal", "squash_different", "squash_comment"):
            candidate = dict(row)
            if scenario == "unique" or scenario.startswith("squash_"):
                candidate["unique_head_commits"] = 1
            if scenario.startswith("squash_"):
                candidate["status"] = "UNIQUE_COMMITS_REQUIRE_RECONCILIATION"
            def api(method, route):
                self.assertEqual(method, "GET")
                if route == "/pulls/500":
                    return {"state": "open", "draft": True, "merged": False,
                            "changed_files": 0 if scenario.startswith("advanced_") else 1,
                            "user": {"login": "github-actions[bot]", "id": 1 if scenario == "human" else 41898282},
                            "head": {"sha": NEW if scenario == "drift" else OLD, "repo": repo},
                            "base": {"ref": "dev", "repo": repo}}
                if route == "/git/ref/heads/dev":
                    return {"object": {"sha": BASE}}
                if route.startswith("/compare/"):
                    if scenario.startswith("squash_"):
                        return {"status": "diverged", "behind_by": 1, "merge_base_commit": {"sha": NEW}}
                    return {"status": "ahead", "behind_by": 0, "merge_base_commit": {"sha": OLD}}
                if route.startswith("/git/commits/"):
                    return {"tree": {"sha": NEW if scenario in ("different_tree", "advanced_empty_diff", "advanced_nonempty_diff", "squash_different") and route.endswith(BASE) else OLD}}
                if route.endswith("/files?per_page=100"):
                    return [{"filename": "changed.py"}] if scenario == "advanced_nonempty_diff" else []
                if route.endswith("?per_page=100"):
                    return [{"id": 1}] if scenario in ("comment", "squash_comment") else []
                self.fail(route)
            with patch.object(rec.admission, "api", side_effect=api):
                self.assertEqual(rec.historical_close_candidate(candidate), scenario in ("valid", "advanced_empty_diff", "squash_equal"))

    def test_historical_close_revalidates_and_never_deletes_refs(self):
        row = {"pr": 500, "head": OLD, "base": BASE, "target": "dev",
               "status": "ANCESTRY_PRESENT_REVIEW_CLOSURE"}
        for scenario in ("valid", "drift", "dry"):
            def api(method, route, body=None):
                if method == "PATCH":
                    self.assertEqual((route, body), ("/pulls/500", {"state": "closed"}))
                    return {"state": "closed", "merged": False, "head": {"sha": OLD}}
                self.assertEqual((method, route), ("GET", "/git/ref/heads/dev"))
                return {"object": {"sha": BASE}}
            with patch.dict("os.environ", ENV, clear=True), patch.object(rec, "historical_inventory", return_value={"findings": [row]}), patch.object(rec, "historical_close_candidate", side_effect=[True, scenario != "drift"]), patch.object(rec.admission, "api", side_effect=api) as call:
                result = rec.close_integrated_history(execute=scenario != "dry")
                expected = {"valid": "exact_history_closed", "drift": "history_drift_before_close",
                            "dry": "eligible_exact_history"}
                self.assertEqual(result["status"], expected[scenario])
                self.assertFalse(result["refs_deleted"])
                if scenario != "valid":
                    call.assert_not_called()


    def test_historical_stack_exact_parent_and_root(self):
        repo = {"full_name": rec.admission.REPO}
        def pr(n, head, sha, base, base_sha):
            return {"number": n, "state": "open", "draft": True,
                    "head": {"ref": head, "sha": sha, "repo": repo},
                    "base": {"ref": base, "sha": base_sha, "repo": repo}}
        parent = pr(1, "feature/parent", OLD, "dev", BASE)
        child = pr(2, "feature/child", NEW, "feature/parent", OLD)
        leaf = pr(3, "feature/leaf", "d"*40, "feature/child", NEW)
        refs = {"dev": BASE, "main": "e"*40}
        prs = {1: parent, 2: child, 3: leaf}
        result = rec.historical_dependency(prs, 3, refs)
        self.assertEqual(result["dependency_state"], "ROOTED")
        self.assertEqual(result["root_target"], "dev")
        self.assertEqual([r["pr"] for r in result["dependency_chain"]], [2, 1])
        self.assertEqual(rec.historical_dependency({2: child}, 2, refs)["dependency_state"], "ORPHAN_BRANCH")
        duplicate = {**parent, "number": 4}
        self.assertEqual(rec.historical_dependency({**prs, 4: duplicate}, 2, refs)["dependency_state"], "AMBIGUOUS_PARENT")
        drift = {**child, "base": {**child["base"], "sha": BASE}}
        self.assertEqual(rec.historical_dependency({1: parent, 2: drift}, 2, refs)["dependency_state"], "PARENT_HEAD_DRIFT")
        cycle = {**parent, "base": {"ref": "feature/child", "sha": NEW, "repo": repo}}
        self.assertEqual(rec.historical_dependency({1: cycle, 2: child}, 2, refs)["dependency_state"], "CYCLE")
        foreign = {**parent, "base": {**parent["base"], "repo": {"full_name": "foreign/repo"}}}
        self.assertEqual(rec.historical_dependency({1: foreign, 2: child}, 2, refs)["dependency_state"], "FOREIGN_OR_INVALID")

    def test_historical_stack_inventory_is_read_only(self):
        repo = {"full_name": rec.admission.REPO}
        prs = [{"number": 1, "state": "open", "draft": True,
                "head": {"ref": "feature/parent", "sha": OLD, "repo": repo},
                "base": {"ref": "dev", "sha": BASE, "repo": repo}},
               {"number": 2, "state": "open", "draft": True,
                "head": {"ref": "feature/child", "sha": NEW, "repo": repo},
                "base": {"ref": "feature/parent", "sha": OLD, "repo": repo}}]
        def api(method, route):
            self.assertEqual(method, "GET")
            if route.startswith("/git/ref/heads/"):
                return {"object": {"sha": BASE}}
            if route.startswith("/pulls?"):
                return prs
            if route == f"/compare/{OLD}...{BASE}":
                return {"base_commit": {"sha": OLD}, "merge_base_commit": {"sha": BASE},
                        "status": "behind", "ahead_by": 0, "behind_by": 1}
            self.fail(route)
        with patch.object(rec.admission, "api", side_effect=api):
            result = rec.historical_inventory(slot=0)
        row = result["findings"][1]
        self.assertEqual(row["status"], "STACKED_PR_REQUIRES_PARENT_RECONCILIATION")
        self.assertEqual(row["dependency_chain"][0]["pr"], 1)
        self.assertFalse(row["close_authorized"])
        self.assertFalse(rec.historical_close_candidate(row))

    def test_closed_parent_exact_merge_ancestry_is_only_a_replay_hint(self):
        repo = {"full_name": rec.admission.REPO}
        branch = "feature/parent"
        merge = "d" * 40
        parent = {"number": 10, "state": "closed", "merged": True,
                  "head": {"ref": branch, "sha": OLD, "repo": repo},
                  "base": {"ref": "dev", "repo": repo},
                  "merge_commit_sha": merge}
        for scenario in ("valid", "not_merged", "drift", "unrelated", "ambiguous", "absent"):
            def api(method, route):
                self.assertEqual(method, "GET")
                if route.startswith("/pulls?state=closed&head="):
                    self.assertIn("feature%2Fparent", route)
                    return [] if scenario == "absent" else [parent, parent] if scenario == "ambiguous" else [parent]
                if route == "/pulls/10":
                    if scenario == "not_merged":
                        return {**parent, "merged": False}
                    if scenario == "drift":
                        return {**parent, "head": {**parent["head"], "sha": NEW}}
                    return parent
                if route == f"/compare/{merge}...{BASE}":
                    return {"base_commit": {"sha": merge}, "status": "ahead",
                            "behind_by": 1 if scenario == "unrelated" else 0,
                            "merge_base_commit": {"sha": merge}}
                self.fail(route)
            with patch.object(rec.admission, "api", side_effect=api):
                result = rec.historical_merged_parent(branch, OLD, {"dev": BASE})
            expected = {"valid": "MERGED_PARENT_REPLAY_REQUIRED",
                        "not_merged": "CLOSED_PARENT_NOT_MERGED",
                        "drift": "CLOSED_PARENT_DRIFT",
                        "unrelated": "CLOSED_PARENT_ROOT_UNVERIFIED",
                        "ambiguous": "AMBIGUOUS_CLOSED_PARENT",
                        "absent": "ORPHAN_BRANCH"}[scenario]
            self.assertEqual(result["dependency_state"], expected)
            self.assertFalse(rec.historical_close_candidate(result))

    def test_nested_closed_parents_require_containment_at_every_hop(self):
        repo = {"full_name": rec.admission.REPO}
        intermediate = "d" * 40
        outer_head = "e" * 40
        final_merge = "f" * 40
        inner = {"number": 10, "state": "closed", "merged": True,
                 "head": {"ref": "feature/inner", "sha": OLD, "repo": repo},
                 "base": {"ref": "feature/outer", "repo": repo},
                 "merge_commit_sha": intermediate}
        outer = {"number": 20, "state": "closed", "merged": True,
                 "head": {"ref": "feature/outer", "sha": outer_head, "repo": repo},
                 "base": {"ref": "dev", "repo": repo},
                 "merge_commit_sha": final_merge}
        for bad in (None, "unrelated", "root", "ambiguous", "drift", "closed", "cycle"):
            def api(method, route):
                self.assertEqual(method, "GET")
                if route.startswith("/pulls?state=closed&head="):
                    if "feature%2Finner" in route:
                        return [inner]
                    self.assertIn("feature%2Fouter", route)
                    return [outer, outer] if bad == "ambiguous" else [outer]
                if route == "/pulls/10":
                    return inner
                if route == "/pulls/20":
                    if bad == "drift":
                        return {**outer, "head": {**outer["head"], "sha": NEW}}
                    if bad == "closed":
                        return {**outer, "merged": False}
                    if bad == "cycle":
                        return {**outer, "base": {"ref": "feature/inner", "repo": repo}}
                    return outer
                if route in (f"/compare/{intermediate}...{outer_head}", f"/compare/{final_merge}...{BASE}"):
                    first, second = route.rsplit("/", 1)[1].split("...")
                    fail = (bad == "unrelated" and first == intermediate) or (bad == "root" and first == final_merge)
                    return {"base_commit": {"sha": first}, "merge_base_commit": {"sha": first},
                            "status": "diverged" if fail else "ahead", "behind_by": 1 if fail else 0}
                self.fail(route)
            with patch.object(rec.admission, "api", side_effect=api):
                row = rec.historical_merged_parent("feature/inner", OLD, {"dev": BASE})
            self.assertEqual(row["dependency_state"], {
                None: "MERGED_PARENT_REPLAY_REQUIRED", "unrelated": "CLOSED_PARENT_ROOT_UNVERIFIED",
                "root": "CLOSED_PARENT_ROOT_UNVERIFIED", "ambiguous": "AMBIGUOUS_CLOSED_PARENT",
                "drift": "CLOSED_PARENT_DRIFT", "closed": "CLOSED_PARENT_NOT_MERGED",
                "cycle": "CLOSED_PARENT_CYCLE"}[bad])
            if bad is None:
                self.assertEqual([x["pr"] for x in row["closed_chain"]], [10, 20])
                self.assertEqual(row["root_sha"], BASE)
            self.assertFalse(rec.historical_close_candidate(row))

    def test_closed_parent_inventory_never_authorizes_closure(self):
        repo = {"full_name": rec.admission.REPO}
        child = {"number": 11, "state": "open", "draft": True,
                 "head": {"ref": "feature/child", "sha": NEW, "repo": repo},
                 "base": {"ref": "feature/parent", "sha": OLD, "repo": repo}}
        def api(method, route):
            self.assertEqual(method, "GET")
            if route.startswith("/git/ref/heads/"):
                return {"object": {"sha": BASE}}
            if route.startswith("/pulls?state=open"):
                return [child]
            self.fail(route)
        hint = {"dependency_state": "MERGED_PARENT_REPLAY_REQUIRED",
                "root_target": "dev", "root_sha": BASE, "closed_parent": 10}
        with patch.object(rec.admission, "api", side_effect=api), patch.object(
                rec, "historical_merged_parent", return_value=hint) as lookup:
            report = rec.historical_inventory(slot=0)
        lookup.assert_called_once_with("feature/parent", OLD, {"main": BASE, "dev": BASE})
        row = report["findings"][0]
        self.assertEqual(row["status"], "STACKED_PR_REPLAY_ON_ROOT_REQUIRED")
        self.assertFalse(row["close_authorized"])
        self.assertFalse(rec.historical_close_candidate(row))

    def test_replay_range_pins_trees_and_never_grants_authority(self):
        repo = {"full_name": rec.admission.REPO}
        ancestor, t1, t2, t3 = "d"*40, "e"*40, "f"*40, "1"*40
        row = {"pr": 500, "head": NEW, "base": BASE, "target": "dev",
               "root_target": "dev", "root_sha": BASE, "unique_head_commits": 2,
               "status": "UNIQUE_COMMITS_REQUIRE_RECONCILIATION"}
        for scenario in ("valid", "foreign", "head_drift", "target_drift",
                         "bad_count", "bad_tree", "empty", "bad_relation",
                         "stacked", "stacked_open_parent", "stacked_diverged"):
            with self.subTest(scenario=scenario):
                stack = scenario.startswith("stacked")
                r = dict(row)
                if stack:
                    r.update(status="STACKED_PR_REPLAY_ON_ROOT_REQUIRED",
                             dependency_state="MERGED_PARENT_REPLAY_REQUIRED",
                             target="feature/parent", closed_parent_head=OLD,
                             closed_chain=[{"head": OLD, "branch": "feature/parent"}],
                             dependency_chain=[{"pr": 2}] if scenario == "stacked_open_parent" else [])
                expected = OLD if stack else BASE
                start = OLD if stack and scenario != "stacked_diverged" else ancestor
                pr = {"number": 500, "state": "open", "head": {"sha": NEW, "repo": repo},
                      "base": {"sha": expected, "ref": r["target"], "repo": repo}}
                calls = []
                def api(method, route):
                    self.assertEqual(method, "GET")
                    calls.append(route)
                    if route == "/pulls/500":
                        if scenario == "foreign":
                            return {**pr, "head": {"sha": NEW, "repo": {"full_name": "other/repo"}}}
                        if scenario == "head_drift" and calls.count(route) > 1:
                            return {**pr, "head": {"sha": OLD, "repo": repo}}
                        return pr
                    if route == f"/compare/{expected}...{NEW}":
                        return {"base_commit": {"sha": expected},
                                "merge_base_commit": {"sha": start},
                                "status": "ahead" if start == expected else "diverged",
                                "ahead_by": True if scenario == "bad_count" else 2,
                                "behind_by": 0 if start == expected or scenario == "bad_relation" else 1}
                    if route.startswith("/git/commits/"):
                        sha = route.rsplit("/", 1)[1]
                        tree = {start: t1, NEW: t1 if scenario == "empty" else t2, BASE: t3}[sha]
                        return {"sha": OLD if scenario == "bad_tree" else sha, "tree": {"sha": tree}}
                    if route == "/git/ref/heads/dev":
                        return {"object": {"sha": OLD if scenario == "target_drift" else BASE}}
                    self.fail(route)
                with patch.object(rec.admission, "api", side_effect=api) as mock_api:
                    result = rec.historical_replay_hint(r)
                if scenario == "stacked_open_parent":
                    self.assertIsNone(result)
                    mock_api.assert_not_called()
                    continue
                self.assertFalse(result["merge_authorized"])
                self.assertFalse(result["close_authorized"])
                if scenario in ("valid", "stacked"):
                    self.assertEqual(result["status"], "ISOLATED_REPLAY_REQUIRED")
                    self.assertEqual(result["source_base"], start)
                    self.assertEqual(result["source_head_tree"], t2)
                    self.assertEqual(result["target_tree"], t3)
                    self.assertTrue(result["fresh_ci_and_safety_required"])
                else:
                    self.assertEqual(result["status"], "EMPTY_SOURCE_DIFF_REQUIRES_REVIEW"
                                     if scenario == "empty" else "REPLAY_RANGE_UNVERIFIED")

    def test_missing_or_invalid_pause_flag_denies_all_metadata_writes(self):
        for value in (None, "", "unknown", "0"):
            env = dict(ENV)
            if value is None:
                env.pop("GASLUX_AUTONOMY_PAUSED")
            else:
                env["GASLUX_AUTONOMY_PAUSED"] = value
            with patch.dict("os.environ", env, clear=True), patch.object(rec.admission, "api") as api:
                with self.assertRaises(RuntimeError):
                    rec.reconcile(execute=True)
                with self.assertRaises(RuntimeError):
                    rec.close_integrated_history(execute=True)
                api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
