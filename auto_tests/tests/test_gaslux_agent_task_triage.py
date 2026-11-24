"""Offline, adversarial task-triage tests. No GH writes in tests."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gaslux_agent_task_triage.py"
SPEC = importlib.util.spec_from_file_location("gaslux_agent_task_triage", SCRIPT)
assert SPEC and SPEC.loader
import sys
sys.path.insert(0, str(SCRIPT.parent))
triage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(triage)


def example_goal(root: Path) -> None:
    platforms = [
        "windows10-bios-mbr", "windows10-uefi-gpt", "windows11-uefi-gpt",
    ]
    goal = {
        "schema_version": 1, "platforms": platforms,
        "gates": list(triage.discover_goal_backlog.__globals__["GATES"]),
        "automatic_safe_gates": [
            "source-authenticity", "windows-preflight",
        ],
        "protected_gates": list(
            triage.discover_goal_backlog.__globals__["GATES"][2:]
        ),
        "backends": [
            {
                "id": role, "priority": i,
                "platforms": platforms[1:] if role == "bazzite" else platforms,
                "issue_numbers": [3, 71] if role == "cachyos"
                                 else [254] if role == "bazzite" else [],
            }
            for i, role in enumerate(triage.TASKS)
        ],
    }
    docs = root / "docs/autonomy"
    docs.mkdir(parents=True)
    (docs / "goal.json").write_text(json.dumps(goal))
    (docs / "evidence.json").write_text(json.dumps({
        "schema_version": 1, "records": [],
    }))


class TaskTriageTests(unittest.TestCase):
    def backlog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            example_goal(root)
            return triage.discover_goal_backlog(root)

    def test_requires_exact_status_and_denies_code_authority(self):
        backlog = self.backlog()
        self.assertEqual(triage.choose(backlog, [], [])["role"], "mint")
        self.assertEqual(triage.choose(backlog, [], [])["status"],
                         "ready_for_scope_review")
        for tamper in ("pending", "idle", "verified"):
            with self.subTest(tamper=tamper):
                bad = dict(backlog, status=tamper)
                with self.assertRaises(ValueError):
                    triage.choose(bad, [], [])
        backlog["next_gates"][0]["code_authorized"] = True
        with self.assertRaises(ValueError):
            triage.choose(backlog, [], [])

    def test_existing_bot_pr_and_existing_issue_defer_not_duplicate(self):
        backlog = self.backlog()
        prs = [{
            "head": {"ref": "bot/gaslux-feature-mint-" + "a" * 12},
            "base": {"ref": "dev"},
        }]
        self.assertEqual(triage.choose(backlog, prs, [])["role"], "zorin")
        marker = triage.issue_payload({
            "role": "mint", "platform": "windows10-bios-mbr",
            "gate": "source-authenticity",
        }, "a" * 40)["body"]
        self.assertEqual(triage.choose(backlog, [], [{"body": marker}])["role"],
                         "zorin")
        self.assertEqual(
            triage.choose(backlog, [], [{"body": marker}])["pending"][0]["status"],
            "already_queued",
        )

    def test_bazzite_existing_issue_and_prohibited_bios(self):
        backlog = self.backlog()
        bazzite = backlog["next_gates"][-1]
        self.assertEqual(bazzite["platform"], "windows10-uefi-gpt")
        self.assertEqual(bazzite["related_issues"], [254])
        for b in backlog["next_gates"][:-1]:
            b["related_issues"] = [9]
        self.assertEqual(triage.choose(backlog, [], [])["status"],
                         "waiting_for_review")
        backlog["next_gates"][-1]["related_issues"] = []
        self.assertEqual(triage.choose(backlog, [], [])["role"], "bazzite")
        backlog["next_gates"][-1]["gate"] = "install"
        with self.assertRaises(ValueError):
            triage.choose(backlog, [], [])

    def test_publisher_requires_unpaused_trusted_main(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            example_goal(root)
            common = {
                "GITHUB_REPOSITORY": triage.REPO,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "schedule",
                "GASLUX_AUTONOMY_PAUSED": "false",
            }
            for key, invalid in [
                ("GITHUB_REPOSITORY", "foreign/gaslux"),
                ("GITHUB_REF", "refs/heads/dev"),
                ("GITHUB_EVENT_NAME", "pull_request"),
                ("GASLUX_AUTONOMY_PAUSED", "true"),
            ]:
                with self.subTest(key=key), patch.dict(
                    "os.environ", dict(common, **{key: invalid}), clear=True
                ), patch.object(triage, "api") as call:
                    with self.assertRaises(RuntimeError):
                        triage.sync(root)
                    call.assert_not_called()

    def test_dry_run_never_posts_and_real_run_creates_one_scoped_issue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            example_goal(root)
            sha = "b" * 40
            requests = []
            def fake_api(method, route, payload=None):
                requests.append((method, route, payload))
                if route == "/git/ref/heads/dev":
                    return {"object": {"sha": sha}}
                if route == "/pulls?state=open&per_page=100":
                    return []
                if route.startswith("/issues?"):
                    return []
                if method == "POST":
                    return {"number": 403}
                raise AssertionError("Unexpected API request")

            env = {
                "GITHUB_REPOSITORY": triage.REPO,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GASLUX_AUTONOMY_PAUSED": "false",
            }
            with patch.dict("os.environ", env, clear=True), \
                 patch.object(triage.subprocess, "check_output",
                              return_value=sha + "\n"), \
                 patch.object(triage, "api", side_effect=fake_api):
                dry = triage.sync(root, dry_run=True)
                self.assertEqual(dry["status"], "dry_run")
                self.assertFalse(any(req[0] == "POST" for req in requests))
                actual = triage.sync(root)
                self.assertEqual(actual["status"], "review_issue_created")
                posts = [req for req in requests if req[0] == "POST"]
                self.assertEqual(len(posts), 1)
                self.assertIn("NEEDS_SCOPE_REVIEW", posts[0][2]["body"])
                self.assertIn("GASLUX-AUTOTASK:mint", posts[0][2]["body"])
                self.assertIn("no", posts[0][2]["body"].lower())

    def test_dev_moved_fails_before_issue_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            example_goal(root)
            env = {
                "GITHUB_REPOSITORY": triage.REPO,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "schedule",
            }
            with patch.dict("os.environ", env, clear=True), \
                 patch.object(triage.subprocess, "check_output",
                              return_value="a" * 40 + "\n"), \
                 patch.object(triage, "api", return_value={
                     "object": {"sha": "b" * 40},
                 }) as call:
                with self.assertRaisesRegex(RuntimeError, "Dev moved"):
                    triage.sync(root)
                self.assertEqual(call.call_count, 1)

    def test_api_cannot_be_used_for_arbitrary_write_or_secret_endpoint(self):
        for method, route in [
            ("POST", "/pulls"), ("DELETE", "/issues/3"),
            ("GET", "/actions/secrets"), ("POST", "/git/refs"),
        ]:
            with self.subTest(method=method, route=route):
                with self.assertRaises(ValueError):
                    triage.api(method, route)

    def test_workflow_temporary_write_token_only_in_trusted_triage_job(self):
        workflow = (SCRIPT.parents[2] /
                    ".github/workflows/gaslux-agent-feature-factory.yml").read_text()
        before, triage_job = workflow.split("  triage_missing_gates:\n", 1)
        self.assertNotIn("issues: write", before)
        self.assertIn("      issues: write", triage_job)
        self.assertIn("github.ref == 'refs/heads/main'", triage_job)
        self.assertIn("vars.GASLUX_AUTONOMY_PAUSED != 'true'", triage_job)
        self.assertIn("needs.select.outputs.blocked == 'true'", triage_job)
        self.assertNotIn("GASLUX_PUBLISH_APP_PRIVATE_KEY", triage_job)
        self.assertNotIn("pull_request_target:", workflow)


if __name__ == "__main__":
    unittest.main()
