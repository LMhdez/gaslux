"""Adversarial, no-network tests for the trusted GitHub Actions Integrator."""
from __future__ import annotations
import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gaslux_agent_integrate.py"
SPEC = importlib.util.spec_from_file_location("gaslux_agent_integrate", SCRIPT)
assert SPEC and SPEC.loader
integ = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integ)
REAL_REVIEWS = integ.independent_merge_reviews
REAL_POLICY = integ.strict_merge_policy


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
        self.live = self.dev
        self.changed = []
        self.merged = "d" * 40
        self.tree = "e" * 40
        self.merge_parent = self.dev
        self.merge_tree = self.tree
        policy = patch.object(integ, "strict_merge_policy", return_value=True)
        self.policy = policy.start()
        self.addCleanup(policy.stop)
        reviews = patch.object(integ, "independent_merge_reviews", return_value=True)
        self.review_gate = reviews.start()
        self.addCleanup(reviews.stop)
        server = patch.object(integ, "server_role_protection", return_value=True)
        self.server_gate = server.start()
        self.addCleanup(server.stop)

    def api(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path == "/pulls?state=open&per_page=100":
            return [self.pr]
        if path == "/pulls/123":
            return self.pr
        if path == "/git/ref/heads/dev":
            return {"object": {"sha": self.live}}
        if path == "/git/commits/" + self.head:
            return {"parents": [{"sha": self.dev}], "tree": {"sha": self.tree}}
        if path == "/git/commits/" + self.merged:
            return {"parents": [{"sha": self.merge_parent}], "tree": {"sha": self.merge_tree}}
        if path == f"/compare/{self.dev}...{self.live}":
            return {"status": "ahead", "merge_base_commit": {"sha": self.dev},
                    "ahead_by": 2, "total_commits": 2, "files": self.changed}
        if path == "/pulls/123/files?per_page=100":
            return self.files
        if path.startswith("/contents/"):
            data = self.old if path.endswith(self.dev) or path.endswith(self.live) else self.new
            return {"encoding": "base64", "content": base64.b64encode(data.encode()).decode()}
        if path == "/pulls/123/reviews?per_page=100":
            return []
        if path == "/issues/123/comments?per_page=100":
            return []
        if path == "/commits/" + self.head + "/check-runs?per_page=100":
            return {"check_runs": []}
        if method == "PUT" and path == "/pulls/123/merge":
            self.live = self.merged
            self.pr.update(state="closed", merged=True, merge_commit_sha=self.merged)
            return {"merged": True, "sha": self.merged}
        raise AssertionError((method, path))

    def test_legacy_merge_policy_requires_confinement(self):
        with patch.object(integ, "strict_merge_policy", wraps=REAL_POLICY), \
             patch.object(integ, "shared_admission") as shared:
            shared.return_value.strict_dev_protected.return_value = True
            shared.return_value.production_merge_policy.return_value = False
            self.assertFalse(integ.strict_merge_policy(self.dev))
            shared.return_value.production_merge_policy.assert_called_once_with(self.dev)

    def test_live_compare_api_path_is_allowed_but_traversal_is_not(self):
        with patch.dict(os.environ, {"GH_TOKEN": "test"}):
            with patch.object(integ.urllib.request, "urlopen") as opener:
                opener.return_value.__enter__.return_value.read.return_value = b"{}"
                self.assertEqual(
                    integ.api("GET", f"/compare/{self.dev}...{self.head}"), {}
                )
                request = opener.call_args.args[0]
                self.assertTrue(request.full_url.endswith(
                    f"/compare/{self.dev}...{self.head}"
                ))
                with self.assertRaisesRegex(ValueError, "Untrusted"):
                    integ.api("GET", "/compare/../../secrets")
                with self.assertRaisesRegex(ValueError, "Untrusted"):
                    integ.api("GET", "/compare/" + self.dev + "...." + self.head)

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

    def test_negative_safety_comment_blocks_merge(self):
        def response(method, route, body=None):
            if route == "/issues/123/comments?per_page=100":
                return [{"body": "BLOCKED_SAFETY — evidence insufficient"}]
            return self.api(method, route, body)
        with patch.object(integ, "api", side_effect=response):
            with self.assertRaisesRegex(ValueError, "Safety hold"):
                integ.inspect(123, self.head)
        self.assertFalse(any(m != "GET" for m, _, _ in self.calls))

    def test_requested_changes_block_merge(self):
        def response(method, route, body=None):
            if route == "/pulls/123/reviews?per_page=100":
                return [{"state": "CHANGES_REQUESTED"}]
            return self.api(method, route, body)
        with patch.object(integ, "api", side_effect=response):
            with self.assertRaisesRegex(ValueError, "review objection"):
                integ.inspect(123, self.head)

    def test_unfinished_candidate_head_checks_block_merge(self):
        def response(method, route, body=None):
            if route == "/commits/" + self.head + "/check-runs?per_page=100":
                return {"check_runs": [{"status": "in_progress", "conclusion": None}]}
            return self.api(method, route, body)
        with patch.object(integ, "api", side_effect=response):
            with self.assertRaisesRegex(ValueError, "not green"):
                integ.inspect(123, self.head)

    def test_nonproduct_dev_advance_preserves_candidate(self):
        self.live = "c" * 40
        # GitHub retains the historical PR base SHA after dev has advanced.
        self.assertEqual(self.pr["base"]["sha"], self.dev)
        self.changed = [
            {"filename": "docs/CI_VM_EVIDENCE_INDEX.md", "status": "modified"},
            {"filename": "auto_tests/tests/test_auth_dest_128g_readonly.py", "status": "added"},
            {"filename": ".github/workflows/auth-dest-342-346-canonical.yml", "status": "added"},
        ]
        with patch.object(integ, "api", side_effect=self.api):
            checked = integ.inspect(123, self.head)
        self.assertEqual(checked["base"], self.live)
        self.assertEqual(checked["original_base"], self.dev)

    def test_relevant_dev_advance_is_stale_and_skipped(self):
        self.live = "c" * 40
        self.pr["base"]["sha"] = self.live
        self.changed = [{"filename": "Installation/Other.cs", "status": "modified"}]
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(integ.StaleProposal):
                integ.inspect(123, self.head)
            self.assertEqual(integ.select(), {"status": "idle"})
        self.assertFalse(any(method != "GET" for method, _, _ in self.calls))

    def test_sensitive_drift_and_noncanonical_paths_refused(self):
        self.live = "c" * 40
        self.pr["base"]["sha"] = self.live
        self.changed = [{"filename": "auto_tests/tools/gaslux_agent_integrate.py",
                         "status": "modified"}]
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(integ.StaleProposal):
                integ.inspect(123, self.head)
        self.assertFalse(integ.harmless_drift_file({
            "filename": "../escape.md", "status": "modified"}))
        self.assertFalse(integ.harmless_drift_file({
            "filename": "docs/safety.md", "status": "removed"}))

    def test_non_direct_parent_blocks_proposal(self):
        def response(method, route, body=None):
            if route == "/git/commits/" + self.head:
                return {"parents": [{"sha": "c" * 40}]}
            return self.api(method, route, body)
        with patch.object(integ, "api", side_effect=response):
            with self.assertRaisesRegex(ValueError, "original-base"):
                integ.inspect(123, self.head)

    def test_stale_head_rejected_before_any_write(self):
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(ValueError):
                integ.inspect(123, "c" * 40)
        self.assertFalse(any(c[0] != "GET" for c in self.calls))

    def test_live_dev_product_change_denied_even_with_historical_pr_base(self):
        self.live = "c" * 40
        self.changed = [{"filename": "Libertix.sln", "status": "modified"}]
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(integ.StaleProposal):
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

    def test_untrusted_workflow_completion_blocks_without_network(self):
        payload = {"workflow_run": {
            "name": "Unrelated workflow", "conclusion": "success",
            "head_branch": "main", "head_repository": {"full_name": integ.REPO},
            "event": "push",
        }}
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp) / "event.json"
            event_path.write_text(json.dumps(payload))
            with patch.dict(os.environ, {
                "GITHUB_REPOSITORY": integ.REPO,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_run",
                "GITHUB_EVENT_PATH": str(event_path),
                "GASLUX_WINDOWS_ACCEPTANCE": "success",
            }), patch.object(integ, "api") as api:
                with self.assertRaisesRegex(RuntimeError, "provenance"):
                    integ.merge(123, self.head)
                api.assert_not_called()

    def test_verified_successful_producer_event_is_admissible(self):
        payload = {"workflow_run": {
            "name": "Gaslux autonomous GitHub agents", "conclusion": "success",
            "head_branch": "main", "head_repository": {"full_name": integ.REPO},
            "event": "push",
        }}
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp) / "event.json"
            event_path.write_text(json.dumps(payload))
            with patch.dict(os.environ, {
                "GITHUB_REPOSITORY": integ.REPO,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_run",
                "GITHUB_EVENT_PATH": str(event_path),
                "GASLUX_WINDOWS_ACCEPTANCE": "success",
            }), patch.object(integ, "api", side_effect=self.api):
                result = integ.merge(123, self.head)
        self.assertEqual(result["status"], "merged")
        self.assertEqual(sum(m == "PUT" for m, _, _ in self.calls), 1)

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

    def test_legacy_merge_rejects_unknown_protection_and_stale_base(self):
        env = {"GITHUB_REPOSITORY": integ.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_WINDOWS_ACCEPTANCE": "success",
               "GASLUX_AUTONOMY_PAUSED": "false"}
        with patch.dict(os.environ, env), patch.object(integ, "api", side_effect=self.api):
            self.policy.return_value = False
            result = integ.merge(123, self.head)
            self.assertEqual(result["reason"], "strict_base_protection_required")
            self.policy.return_value = True
            self.live = "c" * 40
            self.changed = [{"filename": "docs/CI_VM_EVIDENCE_INDEX.md", "status": "modified"}]
            result = integ.merge(123, self.head)
            self.assertEqual(result["reason"], "exact_base_required")
            self.assertFalse(any(m != "GET" for m, _, _ in self.calls))

    def test_legacy_merge_refuses_to_report_wrong_parent_or_tree(self):
        env = {"GITHUB_REPOSITORY": integ.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_WINDOWS_ACCEPTANCE": "success",
               "GASLUX_AUTONOMY_PAUSED": "false"}
        for field in ("merge_parent", "merge_tree"):
            with self.subTest(field=field), patch.dict(os.environ, env), \
                    patch.object(integ, "api", side_effect=self.api):
                self.live = self.dev
                self.pr.update(state="open", draft=True, merged=False)
                self.calls.clear()
                old = getattr(self, field)
                setattr(self, field, "f" * 40)
                try:
                    with self.assertRaisesRegex(RuntimeError, "Merged tree or parent"):
                        integ.merge(123, self.head)
                    self.assertEqual(sum(m == "PUT" for m, _, _ in self.calls), 1)
                finally:
                    setattr(self, field, old)

    def test_isolated_python_loads_trusted_policy_without_network(self):
        code = ("import runpy; m = runpy.run_path(" + repr(str(SCRIPT)) +
                "); assert m['strict_merge_policy']('invalid') is False")
        subprocess.run([sys.executable, "-I", "-c", code], check=True, timeout=30)

    def test_readiness_and_merge_require_independent_reviews(self):
        env = {"GITHUB_REPOSITORY": integ.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_WINDOWS_ACCEPTANCE": "success",
               "GASLUX_AUTONOMY_PAUSED": "false"}
        with patch.dict(os.environ, env), patch.object(integ, "api", side_effect=self.api):
            self.review_gate.return_value = False
            with self.assertRaisesRegex(RuntimeError, "independent exact reviews"):
                integ.verify_before_ready(123, self.head)
            self.assertEqual(integ.merge(123, self.head)["reason"], "independent_reviews_required")
            self.assertFalse(any(m != "GET" for m, _, _ in self.calls))

    def test_actual_legacy_role_reviews_reject_unrelated_and_stale_approvals(self):
        self.pr["user"]["id"] = 41898282
        env = {"GASLUX_SAFETY_REVIEWER_ID": "101",
               "GASLUX_SUPERVISED_OWNER_IDS": '{"mint":102}'}
        reviews = [
            {"user": {"id": 101}, "state": "APPROVED", "commit_id": self.head,
             "body": f"GASLUX-SAFETY-V1 head={self.head} base={self.dev}"},
            {"user": {"id": 102}, "state": "APPROVED", "commit_id": self.head,
             "body": f"GASLUX-BACKEND-OWNER-V1 role=mint head={self.head} base={self.dev}"},
        ]

        def response(method, route, body=None):
            if route == "/pulls/123/reviews?per_page=100":
                return reviews
            return self.api(method, route, body)

        with patch.dict(os.environ, env), patch.object(integ, "api", side_effect=response):
            checked = integ.inspect(123, self.head)
            self.assertTrue(REAL_REVIEWS(checked))
            reviews[1]["user"]["id"] = 103
            self.assertFalse(REAL_REVIEWS(checked))
            reviews[1]["user"]["id"] = 102
            reviews[0]["commit_id"] = "f" * 40
            self.assertFalse(REAL_REVIEWS(checked))

    def test_server_role_gate_blocks_before_ready_and_merge(self):
        env = {"GITHUB_REPOSITORY": integ.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_WINDOWS_ACCEPTANCE": "success",
               "GASLUX_AUTONOMY_PAUSED": "false"}
        with patch.dict(os.environ, env), patch.object(integ, "api", side_effect=self.api):
            self.server_gate.return_value = False
            with self.assertRaises(RuntimeError):
                integ.verify_before_ready(123, self.head)
            self.assertEqual(integ.merge(123, self.head)["reason"], "server_role_review_protection_required")
            self.assertFalse(any(m != "GET" for m, _, _ in self.calls))

    def test_windows_acceptance_uses_exact_head_and_prebuilt_tests(self):
        yaml = (
            SCRIPT.parents[2] / ".github/workflows/gaslux-agent-integrator.yml"
        ).read_text()
        windows = yaml.split("\n  windows_acceptance:\n", 1)[1].split(
            "\n  trusted_integrator:\n", 1
        )[0]
        self.assertIn("needs.select.outputs.head", windows)
        self.assertIn("git rev-parse HEAD", windows)
        self.assertIn("msbuild Libertix.sln /restore", windows)
        self.assertIn("--no-restore --no-build", windows)
        self.assertIn("windows-2022", windows)
        self.assertNotIn("contents: write", windows)
        trusted = yaml.split("\n  trusted_integrator:\n", 1)[1]
        self.assertIn("needs.windows_acceptance.result == 'success'", trusted)
        self.assertIn("pull-requests: write", trusted)
        self.assertIn("gh pr ready", trusted)
        self.assertIn("Gaslux Goal Supervisor - read-only progress", yaml)
        self.assertIn("github.ref == 'refs/heads/main'", trusted)

    def test_unsupported_backends_have_no_merge_grant(self):
        self.pr["head"]["ref"] = "bot/gaslux-cachyos-keyboard-" + self.dev[:12]
        with patch.object(integ, "api", side_effect=self.api):
            with self.assertRaises(ValueError):
                integ.inspect(123, self.head)


    def test_f38902_exact_clock_completion_names_reach_real_merge(self):
        """RED before fix: actual merge() must admit each exact trusted new title."""
        for title in ("GASLUX-CLOCK/auto", "GASLUX-CLOCK/mint",
                      "GASLUX-CLOCK/zorin"):
            with self.subTest(title=title), tempfile.TemporaryDirectory() as tmp:
                # Each event exercises a distinct unmerged candidate; the previous
                # simulated squash merge closed its PR and advanced dev.
                self.setUp()
                event_path = Path(tmp) / "event.json"
                event_path.write_text(json.dumps({"workflow_run": {
                    "name": title,
                    "conclusion": "success",
                    "head_branch": "main",
                    "head_repository": {"full_name": integ.REPO},
                    "event": "workflow_dispatch",
                }}), encoding="utf-8")
                env = {
                    "GITHUB_REPOSITORY": integ.REPO,
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_EVENT_NAME": "workflow_run",
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GASLUX_WINDOWS_ACCEPTANCE": "success",
                    "GASLUX_AUTONOMY_PAUSED": "false",
                }
                with patch.dict(os.environ, env), patch.object(
                    integ, "api", side_effect=self.api
                ):
                    result = integ.merge(123, self.head)
                self.assertEqual(result["status"], "merged")
                writes = [(method, path, body) for method, path, body in self.calls
                          if method != "GET"]
                self.assertEqual(len(writes), 1)
                self.assertEqual(writes[0][1], "/pulls/123/merge")
                self.assertEqual(writes[0][2]["sha"], self.head)

    def test_f38902_foreign_or_modified_clock_provenance_denied_before_network(self):
        """Do not admit unlisted titles, foreign repos, branches or conclusions."""
        baseline = {"name": "GASLUX-CLOCK/auto", "conclusion": "success",
                    "head_branch": "main",
                    "head_repository": {"full_name": integ.REPO},
                    "event": "workflow_dispatch"}
        variants = [
            {"name": "GASLUX-CLOCK/custom"},
            {"name": "GASLUX-CLOCK/auto-extra"},
            {"name": "GASLUX-FACTORY/default"},
            {"head_branch": "dev"},
            {"head_branch": "feature/attacker"},
            {"head_repository": {"full_name": "attacker/gaslux"}},
            {"conclusion": "failure"},
            {"conclusion": "cancelled"},
            {"event": "pull_request"},
        ]
        for change in variants:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                event_path = Path(tmp) / "event.json"
                event_path.write_text(json.dumps({"workflow_run": {
                    **baseline, **change,
                }}), encoding="utf-8")
                with patch.dict(os.environ, {
                    "GITHUB_REPOSITORY": integ.REPO,
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_EVENT_NAME": "workflow_run",
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GASLUX_WINDOWS_ACCEPTANCE": "success",
                    "GASLUX_AUTONOMY_PAUSED": "false",
                }), patch.object(integ, "api") as api:
                    with self.assertRaisesRegex(RuntimeError, "provenance"):
                        integ.merge(123, self.head)
                    api.assert_not_called()

    def test_f38902_typed_clock_still_requires_windows_and_unpaused(self):
        """Provenance admission cannot disable Windows or emergency pause."""
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp) / "event.json"
            event_path.write_text(json.dumps({"workflow_run": {
                "name": "GASLUX-CLOCK/auto",
                "conclusion": "success",
                "head_branch": "main",
                "head_repository": {"full_name": integ.REPO},
                "event": "workflow_dispatch",
            }}), encoding="utf-8")
            env = {
                "GITHUB_REPOSITORY": integ.REPO,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_run",
                "GITHUB_EVENT_PATH": str(event_path),
                "GASLUX_WINDOWS_ACCEPTANCE": "skipped",
                "GASLUX_AUTONOMY_PAUSED": "false",
            }
            with patch.dict(os.environ, env), patch.object(integ, "api") as api:
                with self.assertRaisesRegex(RuntimeError, "Windows"):
                    integ.merge(123, self.head)
                api.assert_not_called()
            env.update({"GASLUX_WINDOWS_ACCEPTANCE": "success",
                        "GASLUX_AUTONOMY_PAUSED": "true"})
            with patch.dict(os.environ, env), patch.object(integ, "api") as api:
                with self.assertRaisesRegex(RuntimeError, "AUTONOMY_PAUSED"):
                    integ.merge(123, self.head)
                api.assert_not_called()

    def test_workflow_run_admits_existing_and_typed_clock_titles_only(self):
        yaml = (SCRIPT.parents[2] / ".github/workflows/gaslux-agent-integrator.yml").read_text()
        for title in ("Gaslux autonomous GitHub agents",
                      "GASLUX-CLOCK/auto", "GASLUX-CLOCK/mint",
                      "GASLUX-CLOCK/zorin"):
            self.assertIn("github.event.workflow_run.name == '" + title + "'", yaml)
        self.assertIn("github.event.workflow_run.head_repository.full_name == 'LMhdez/gaslux'", yaml)
        self.assertIn("github.event.workflow_run.head_branch == 'main'", yaml)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", yaml)



if __name__ == "__main__":
    unittest.main()
