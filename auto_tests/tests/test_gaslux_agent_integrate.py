"""Adversarial, no-network tests for the trusted GitHub Actions Integrator."""
from __future__ import annotations
import base64
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gaslux_agent_integrate.py"
SPEC = importlib.util.spec_from_file_location("gaslux_agent_integrate", SCRIPT)
assert SPEC and SPEC.loader
integ = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integ)


class IntegratorContractTests(unittest.TestCase):
    def setUp(self):
        self.dev = "a" * 40
        self.head = "b" * 40
        self.old = (
            'class M {\n'
            '    { "00000809", Mapping("gb") },\n'
            '}\n'
        )
        self.new = (
            'class M {\n'
            '    { "00000809", Mapping("gb") },\n'
            '    { "00000816", Mapping("pt") },\n'
            '}\n'
        )
        self.pr = {
            "number": 123, "state": "open", "draft": True,
            "user": {"login": "github-actions[bot]"},
            "created_at": "2026-11-22T18:00:00Z",
            "head": {"ref": "bot/gaslux-mint-keyboard-" + self.dev[:12],
                     "sha": self.head, "repo": {"full_name": integ.REPO}},
            "base": {"ref": "dev", "sha": self.dev,
                     "repo": {"full_name": integ.REPO}},
        }
        self.files = [{
            "filename": integ.SOURCE, "status": "modified",
            "additions": 1, "deletions": 0, "changes": 1,
        }]
        self.calls = []

    def api(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path == "/pulls?state=open&per_page=100":
            return [self.pr]
        if path == "/pulls/123":
            return self.pr
        if path == "/git/ref/heads/dev":
            return {"object": {"sha": self.dev}}
        if path == "/git/commits/" + self.head:
            return {"parents": [{"sha": self.dev}]}
        if path == "/pulls/123/files?per_page=100":
            return self.files
        if path.startswith("/contents/"):
            data = self.old if path.endswith(self.dev) else self.new
            return {"encoding": "base64", "content": base64.b64encode(data.encode()).decode()}
        if path == "/pulls/123/reviews?per_page=100":
            return []
        if path == "/issues/123/comments?per_page=100":
            return []
        if path == "/commits/" + self.head + "/check-runs?per_page=100":
            return {"check_runs": []}
        if method == "PUT" and path == "/pulls/123/merge":
            return {"merged": True, "sha": "c" * 40}
        raise AssertionError((method, path))

    def test_exact_curated_mapping_allowed(self):
        self.assertTrue(integ.exact_insert(self.old, self.new, "mint"))
        self.assertFalse(integ.exact_insert(self.old, self.old, "mint"))
        self.assertFalse(integ.exact_insert(self.old, self.new, "zorin"))

    def test_never_accept_unrelated_edits(self):
        self.assertFalse(integ.exact_insert(self.old, self.new + "evil()\n", "mint"))
        self.assertFalse(integ.exact_insert(
            self.old, self.new.replace('Mapping("pt")', 'Mapping("br")'), "mint"))
        self.assertFalse(integ.exact_insert(
            self.old, self.new.replace('Mapping("gb")', 'Mapping("us")'), "mint"))
        self.assertFalse(integ.exact_insert(
            self.old, self.new.replace("class M", "class E"), "mint"))

    def test_bot_proposal_with_exact_dev_ancestry_is_selected(self):
        with patch.object(integ, "api", side_effect=self.api):
            result = integ.select()
        self.assertEqual(result["status"], "selected")
        self.assertEqual(result["task"], "MINT-PT-KEYBOARD-01")
        self.assertEqual(result["head"], self.head)

    def test_idle_without_bot_proposals(self):
        with patch.object(integ, "api", return_value=[]):
            self.assertEqual(integ.select(), {"status": "idle"})

    def test_user_created_lookalike_branch_is_rejected(self):
        self.pr["user"]["login"] = "attacker"
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(ValueError):
                integ.inspect(123, self.head)
            self.assertEqual(integ.select(), {"status": "idle"})

    def test_unreviewed_extra_file_denied(self):
        self.files.append(dict(self.files[0], filename=".github/workflows/evil.yml"))
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaisesRegex(ValueError, "exceeds"):
                integ.inspect(123, self.head)

    def test_stale_head_rejected_before_any_write(self):
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(ValueError):
                integ.inspect(123, "c" * 40)
        self.assertFalse(any(c[0] != "GET" for c in self.calls))

    def test_dev_moved_denied(self):
        self.pr["base"]["sha"] = "c" * 40
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(ValueError):
                integ.inspect(123, self.head)

    def test_untrusted_event_denied_without_network(self):
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": integ.REPO,
            "GITHUB_REF": "refs/heads/dev",
            "GITHUB_EVENT_NAME": "push",
            "GASLUX_WINDOWS_ACCEPTANCE": "success",
        }), patch.object(integ, "api") as api:
            with self.assertRaisesRegex(RuntimeError, "default branch"):
                integ.merge(123, self.head)
            api.assert_not_called()

    def test_no_windows_validation_means_no_merge(self):
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": integ.REPO,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "schedule",
            "GASLUX_WINDOWS_ACCEPTANCE": "skipped",
        }), patch.object(integ, "api") as api:
            with self.assertRaisesRegex(RuntimeError, "Windows"):
                integ.merge(123, self.head)
            api.assert_not_called()

    def test_exact_windows_accepted_bot_pr_can_merge_only_dev(self):
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": integ.REPO,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "schedule",
            "GASLUX_WINDOWS_ACCEPTANCE": "success",
        }), patch.object(integ, "api", side_effect=self.api):
            result = integ.merge(123, self.head)
        self.assertEqual(result["status"], "merged")
        writes = [(m, p, b) for m, p, b in self.calls if m != "GET"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], "/pulls/123/merge")
        self.assertEqual(writes[0][2]["sha"], self.head)
        self.assertEqual(writes[0][2]["merge_method"], "squash")

    def test_unsupported_backends_have_no_merge_grant(self):
        self.pr["head"]["ref"] = "bot/gaslux-cachyos-keyboard-" + self.dev[:12]
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(ValueError):
                integ.inspect(123, self.head)


if __name__ == "__main__":
    unittest.main()
