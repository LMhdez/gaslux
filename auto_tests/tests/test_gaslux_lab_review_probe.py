import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_lab_review_probe as L


class LabReviewTests(unittest.TestCase):
    def setUp(self):
        self.ids = {"safety": 101, "owner": 202}
        self.pr = {"number": L.NUMBER, "state": "open", "draft": False,
                   "merged": False, "user": {"id": L.AUTHOR}, "commits": 1,
                   "changed_files": 1, "additions": 2, "deletions": 0,
                   "head": {"sha": L.HEAD, "ref": L.HEAD_REF, "repo": {"full_name": L.A.REPO}},
                   "base": {"sha": L.BASE, "ref": L.BASE_REF, "repo": {"full_name": L.A.REPO}}}
        self.reviews = []
        self.writes = []

    def row(self, role, **changes):
        return {"id": self.ids[role]+1000, "user": {"id": self.ids[role], "type": "Bot"},
                "state": "APPROVED", "commit_id": L.HEAD, "body": L.marker(role), **changes}

    def api(self, method, route, body=None):
        if method != "GET":
            self.writes.append((method, route, body))
            if method == "POST" and route == L.ROUTE + "/reviews":
                row = self.row("safety")
                self.reviews.append(row)
                return row
            self.fail("Unexpected write")
        if route == L.ROUTE:
            return self.pr
        if route == "/git/ref/heads/" + L.BASE_REF:
            return {"object": {"sha": L.BASE}}
        if route == "/git/ref/heads/" + L.HEAD_REF:
            return {"object": {"sha": L.HEAD}}
        if route == "/git/commits/" + L.HEAD:
            return {"sha": L.HEAD, "tree": {"sha": L.TREE}, "parents": [{"sha": L.BASE}]}
        if route == L.ROUTE + "/files?per_page=100":
            return [{"filename": L.FILE, "sha": L.BLOB, "status": "added",
                     "additions": 2, "deletions": 0, "changes": 2}]
        if route == L.ROUTE + "/reviews?per_page=100":
            return self.reviews
        if route.startswith("/rules/branches/"):
            return []
        self.fail(route)

    def test_live_receipt_and_idempotent_retry(self):
        with patch.object(L, "context"), patch.object(L, "actors", return_value=self.ids), \
                patch.object(L.gate, "review_app_actor", return_value=101), \
                patch.object(L.A, "api", side_effect=self.api):
            self.assertTrue(L.approve("safety")["review_capability_verified"])
            self.assertTrue(L.approve("safety")["review_capability_verified"])
        self.assertEqual(len(self.writes), 1)

    def test_reject_target_head_scope_and_author_drift(self):
        from copy import deepcopy
        original = deepcopy(self.pr)
        for change in ("base_ref", "head_ref", "head_sha", "base_sha", "author", "files", "draft"):
            self.pr = deepcopy(original)
            if change == "base_ref":
                self.pr["base"]["ref"] = "dev"
            elif change == "head_ref":
                self.pr["head"]["ref"] = "bot/other"
            elif change == "head_sha":
                self.pr["head"]["sha"] = "a"*40
            elif change == "base_sha":
                self.pr["base"]["sha"] = "b"*40
            elif change == "author":
                self.pr["user"]["id"] = 101
            elif change == "files":
                self.pr["changed_files"] = 2
            else:
                self.pr["draft"] = True
            with self.subTest(change=change), patch.object(L, "context"), \
                    patch.object(L, "actors", return_value=self.ids), \
                    patch.object(L.gate, "review_app_actor", return_value=101), \
                    patch.object(L.A, "api", side_effect=self.api), self.assertRaises(ValueError):
                L.approve("safety")
        self.assertEqual(self.writes, [])

    def test_reject_stale_dismissed_foreign_and_duplicate(self):
        for rows in ([self.row("safety", commit_id="b"*40)],
                     [self.row("safety", state="DISMISSED")],
                     [self.row("safety", state="CHANGES_REQUESTED")],
                     [self.row("safety", user={"id": 303, "type": "Bot"})],
                     [self.row("safety"), self.row("safety")]):
            self.reviews = rows
            with patch.object(L.A, "api", side_effect=self.api), self.assertRaises(ValueError):
                L.verified_reviews(self.ids)
        self.assertEqual(self.writes, [])

    def test_unprotected_lab_never_merges(self):
        self.reviews = [self.row("safety"), self.row("owner")]
        with patch.object(L, "context"), patch.object(L, "actors", return_value=self.ids), \
                patch.object(L.A, "api", side_effect=self.api):
            result = L.audit()
        self.assertTrue(result["independent_reviews_verified"])
        self.assertFalse(result["lab_merge_verified"])
        self.assertFalse(result["production_merge_authorized"])
        self.assertEqual(result["status"], "lab_rule_missing_no_merge")
        self.assertEqual(self.writes, [])

    def test_no_second_approval_no_merge(self):
        self.reviews = [self.row("safety")]
        with patch.object(L, "context"), patch.object(L, "actors", return_value=self.ids), \
                patch.object(L.A, "api", side_effect=self.api), self.assertRaises(ValueError):
            L.audit()
        self.assertEqual(self.writes, [])

    def test_server_not_ready_no_merge(self):
        self.reviews = [self.row("safety"), self.row("owner")]
        with patch.object(L, "context"), patch.object(L, "actors", return_value=self.ids), \
                patch.object(L, "protected", return_value=33), \
                patch.object(L, "decision", return_value={"reviewDecision": "REVIEW_REQUIRED",
                                                          "mergeable": "MERGEABLE",
                                                          "mergeStateStatus": "BLOCKED"}), \
                patch.object(L.A, "api", side_effect=self.api):
            self.assertEqual(L.audit()["status"], "server_merge_not_ready")
        self.assertEqual(self.writes, [])

    def test_wrong_actor_and_untrusted_context(self):
        with patch.object(L, "context"), patch.object(L, "actors", return_value=self.ids), \
                patch.object(L.gate, "review_app_actor", return_value=202), \
                patch.object(L.A, "api", side_effect=self.api), self.assertRaises(ValueError):
            L.approve("safety")
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": L.A.REPO, "GITHUB_REF": "refs/heads/dev",
                                    "GASLUX_AUTONOMY_PAUSED": "true"}, clear=True), \
                patch.object(L.A, "api", side_effect=self.api), self.assertRaises(ValueError):
            L.approve("safety")
        self.assertEqual(self.writes, [])

    def test_server_approved_still_cannot_merge(self):
        self.reviews = [self.row("safety"), self.row("owner")]
        state = {"reviewDecision": "APPROVED", "mergeable": "MERGEABLE",
                 "mergeStateStatus": "CLEAN"}
        with patch.object(L, "context"), patch.object(L, "actors", return_value=self.ids), \
                patch.object(L, "protected", return_value=33), \
                patch.object(L, "decision", return_value=state), \
                patch.object(L.A, "api", side_effect=self.api):
            report = L.audit()
        self.assertEqual(report["status"], "server_approved_merge_disabled")
        self.assertFalse(report["lab_merge_authorized"])
        self.assertFalse(report["write_isolation_verified"])
        self.assertFalse(report["lab_merge_verified"])
        self.assertEqual(self.writes, [])

    def test_drift_during_last_observation_cannot_write(self):
        from copy import deepcopy
        original = deepcopy(self.pr)
        state = {"reviewDecision": "APPROVED", "mergeable": "MERGEABLE",
                 "mergeStateStatus": "CLEAN"}
        for change in ("retarget", "advance_base", "dismiss_review", "replace_review"):
            self.pr = deepcopy(original)
            self.reviews = [self.row("safety"), self.row("owner")]
            def decision():
                if change == "retarget":
                    self.pr["base"]["ref"] = "main"
                elif change == "advance_base":
                    self.pr["base"]["sha"] = "a"*40
                elif change == "dismiss_review":
                    self.reviews[0]["state"] = "DISMISSED"
                else:
                    self.reviews[0]["user"]["id"] = 303
                return state
            with self.subTest(change=change), patch.object(L, "context"), \
                    patch.object(L, "actors", return_value=self.ids), \
                    patch.object(L, "protected", return_value=33), \
                    patch.object(L, "decision", side_effect=decision), \
                    patch.object(L.A, "api", side_effect=self.api), self.assertRaises(ValueError):
                L.audit()
        self.assertEqual(self.writes, [])

    def test_drift_after_final_read_never_enables_merge(self):
        self.reviews = [self.row("safety"), self.row("owner")]
        state = {"reviewDecision": "APPROVED", "mergeable": "MERGEABLE",
                 "mergeStateStatus": "CLEAN"}
        calls = []
        def decision():
            calls.append(1)
            if len(calls) == 2:
                self.pr["base"]["ref"] = "main"
                self.pr["base"]["sha"] = "a"*40
                self.reviews[0]["state"] = "DISMISSED"
            return state
        with patch.object(L, "context"), patch.object(L, "actors", return_value=self.ids), \
                patch.object(L, "protected", return_value=33), \
                patch.object(L, "decision", side_effect=decision), \
                patch.object(L.A, "api", side_effect=self.api):
            report = L.audit()
        self.assertFalse(report["lab_merge_authorized"])
        self.assertFalse(report["lab_merge_verified"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.writes, [])

    def test_no_merge_or_ref_write_api_surface(self):
        for method, route in (("PUT", L.ROUTE + "/merge"),
                              ("PATCH", L.ROUTE),
                              ("PATCH", "/git/refs/heads/main"),
                              ("POST", "/git/refs"),
                              ("POST", "/pulls/430/reviews"),
                              ("DELETE", L.ROUTE + "/reviews/1")):
            with self.subTest(method=method, route=route), \
                    patch.object(L.A, "api") as network, self.assertRaises(ValueError):
                L.api(method, route, {})
            network.assert_not_called()
        with patch.object(L.A, "api") as network, self.assertRaises(ValueError):
            L.api("POST", L.ROUTE + "/reviews", {
                "commit_id": "a"*40, "event": "APPROVE", "body": L.marker("owner")})
        network.assert_not_called()

    def test_no_content_write_permission_or_merge_cli(self):
        import ast
        source = Path(L.__file__).read_text()
        tree = ast.parse(source)
        wrapper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "api")
        allowed = {id(n) for n in ast.walk(wrapper)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "api":
                    self.assertIn(id(node), allowed)
        workflow = (Path(L.__file__).resolve().parents[2] /
                    ".github/workflows/gaslux-agent-integrator.yml").read_text()
        paused = workflow[workflow.index("  paused_safety_credential_probe:"):]
        self.assertNotIn("contents: write", paused)
        self.assertNotIn("pull-requests: write", paused)
        self.assertNotIn("paused_lab_protected_merge:", paused)
        self.assertNotIn("gaslux_lab_review_probe.py merge", paused)
        self.assertNotIn("allow_merge", source)

    def test_observed_manual_merge_is_not_automated_merge(self):
        self.reviews = [self.row("safety"), self.row("owner")]
        self.pr.update(state="closed", merged=True, merge_commit_sha="d"*40)
        with patch.object(L, "context"), patch.object(L, "actors", return_value=self.ids), \
                patch.object(L, "merged_receipt", return_value="d"*40), \
                patch.object(L.A, "api", side_effect=self.api):
            report = L.audit()
        self.assertEqual(report["status"], "lab_merge_observed")
        self.assertFalse(report["lab_merge_verified"])
        self.assertFalse(report["lab_merge_authorized"])
        self.assertEqual(self.writes, [])
