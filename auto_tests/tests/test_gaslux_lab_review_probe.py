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
