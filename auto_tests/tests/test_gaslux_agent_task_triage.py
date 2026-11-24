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

    def task_marker_issue(self, *, author="github-actions[bot]", repo=None):
        task = {"role": "mint", "platform": "windows10-bios-mbr",
                "gate": "source-authenticity"}
        payload = triage.issue_payload(task, "a" * 40)
        return {
            "number": 99, "title": payload["title"], "body": payload["body"],
            "state": "open", "repository_url": repo or triage.API,
            "user": {"login": author, "type": "Bot"},
        }

    def task_claim_pr(self, *, repo=None, author="github-actions[bot]"):
        return {
            "head": {"ref": "bot/gaslux-feature-mint-" + "a" * 12,
                     "repo": {"full_name": repo or triage.REPO}},
            "base": {"ref": "dev", "repo": {"full_name": triage.REPO}},
            "user": {"login": author, "type": "Bot"},
        }

    def test_existing_bot_pr_and_existing_issue_defer_not_duplicate(self):
        backlog = self.backlog()
        self.assertEqual(
            triage.choose(backlog, [self.task_claim_pr()], [])["role"],
            "zorin",
        )
        issue = self.task_marker_issue()
        self.assertEqual(triage.choose(backlog, [], [issue])["role"], "zorin")
        self.assertEqual(
            triage.choose(backlog, [], [issue])["pending"][0]["status"],
            "already_queued",
        )

    def test_f40301_foreign_fork_or_author_cannot_claim_bot_pr(self):
        backlog = self.backlog()
        for forged in [
            self.task_claim_pr(repo="attacker/gaslux"),
            self.task_claim_pr(author="outside-contributor"),
        ]:
            with self.subTest(forged=forged):
                result = triage.choose(backlog, [forged], [])
                self.assertEqual(result["role"], "mint")
                self.assertEqual(result["status"], "ready_for_scope_review")

    def test_f40301_foreign_issue_marker_cannot_claim_task(self):
        backlog = self.backlog()
        for forged in [
            self.task_marker_issue(author="external-user"),
            self.task_marker_issue(repo="https://api.github.com/repos/other/gaslux"),
            dict(self.task_marker_issue(), title="unrelated support request"),
            dict(self.task_marker_issue(), body=(
                "User pasted a marker\n" + self.task_marker_issue()["body"]
            )),
        ]:
            with self.subTest(forged=forged):
                result = triage.choose(backlog, [], [forged])
                self.assertEqual(result["role"], "mint")
        self.assertEqual(
            triage.trusted_task_keys([self.task_marker_issue()]),
            {("mint", "windows10-bios-mbr", "source-authenticity")},
        )

    def test_f40301_owner_issue_unrelated_to_platform_and_gate_not_deduped(self):
        backlog = self.backlog()
        backlog["next_gates"][0]["related_issues"] = [90017]
        issue = {
            "number": 90017, "title": "Mint application icon design",
            "state": "open", "repository_url": triage.API,
            "user": {"login": "LMhdez", "type": "User"},
        }
        # Owner identity and backend word do not prove source-authenticity scope.
        result = triage.choose(backlog, [], [issue])
        self.assertEqual(result["role"], "mint")

    def test_f40301_vetted_cachyos_bazzite_issue_scope_is_exact(self):
        backlog = self.backlog()
        for task in backlog["next_gates"][:-1]:
            task["related_issues"] = [3]
        legacy_cachyos = {
            "number": 3,
            "title": "CachyOS production-stability acceptance criteria (UEFI, dual boot, rollback)",
            "state": "open", "repository_url": triage.API,
            "user": {"login": "Dinisiho", "type": "User"},
        }
        # A legitimate broad source/provenance work tracker may match CachyOS,
        # but never Mint, Zorin, Pop!_OS or Q4OS through fake dev references.
        self.assertEqual(triage.choose(backlog, [], [legacy_cachyos])["role"], "mint")
        for task in backlog["next_gates"][:-1]:
            if task["role"] != "cachyos":
                task["related_issues"] = []
        self.assertEqual(
            triage.trusted_related_issues(
                [legacy_cachyos], "cachyos", "windows10-bios-mbr",
                "source-authenticity", [3]
            ),
            [3],
        )
        # #254 covers only Bazzite UEFI, no unrelated backend/firmware.
        bazzite = {
            "number": 254,
            "title": "Bazzite: bloquear promoção até provar ISO autenticada, write-set e recuperação Windows",
            "state": "open", "repository_url": triage.API,
            "user": {"login": "LMhdez", "type": "User"},
        }
        self.assertEqual(
            triage.trusted_related_issues(
                [bazzite], "bazzite", "windows10-uefi-gpt", "source-authenticity", [254]
            ), [254],
        )
        self.assertEqual(
            triage.trusted_related_issues(
                [bazzite], "bazzite", "windows10-bios-mbr", "source-authenticity", [254]
            ), [],
        )
        altered = dict(bazzite, title="Bazzite application icon design")
        self.assertEqual(
            triage.trusted_related_issues(
                [altered], "bazzite", "windows10-uefi-gpt", "source-authenticity", [254]
            ), [],
        )

    def test_f40303_known_app_bot_is_deduped_unknown_bot_fails_closed(self):
        backlog = self.backlog()
        app_name = "example-gaslux-app[bot]"  # fixture, NOT a claimed real app actor
        app = self.task_claim_pr(author=app_name)
        app["user"]["type"] = "Bot"
        result = triage.choose(backlog, [app], [], app_bot_login=app_name)
        self.assertEqual(result["role"], "zorin")
        self.assertEqual(result["pending"][0]["status"], "pending_existing_pr")
        with self.assertRaises(ValueError):
            triage.choose(backlog, [app], [], app_bot_login="")
        with self.assertRaises(ValueError):
            triage.choose(backlog, [app], [], app_bot_login="another-app[bot]")
        with self.assertRaises(ValueError):
            triage.choose(backlog, [app], [], app_bot_login="malformed-app")
        spoof = self.task_claim_pr(author="outside-user")
        spoof["user"]["type"] = "User"
        self.assertEqual(
            triage.choose(backlog, [spoof], [], app_bot_login=app_name)["role"], "mint"
        )

    def test_f40301_untrusted_dev_issue_reference_cannot_claim_task(self):
        backlog = self.backlog()
        backlog["next_gates"][0]["related_issues"] = [99999999]
        self.assertEqual(triage.choose(backlog, [], [])["role"], "mint")
        # Reusing an unrelated trusted issue ID is not sufficient.
        unrelated = {
            "number": 99999999, "title": "Zorin unrelated support request",
            "repository_url": triage.API, "state": "open",
            "user": {"login": "LMhdez"},
        }
        self.assertEqual(triage.choose(backlog, [], [unrelated])["role"],
                         "mint")
        unrelated["title"] = "Mint media authenticity scope review"
        # A title alone is NOT a trusted canonical gate binding.
        self.assertEqual(triage.choose(backlog, [], [unrelated])["role"],
                         "mint")
        unrelated["user"]["login"] = "external-user"
        self.assertEqual(triage.choose(backlog, [], [unrelated])["role"],
                         "mint")

    def test_bazzite_existing_issue_and_prohibited_bios(self):
        backlog = self.backlog()
        bazzite = backlog["next_gates"][-1]
        self.assertEqual(bazzite["platform"], "windows10-uefi-gpt")
        self.assertEqual(bazzite["related_issues"], [254])
        manual = []
        for role, issue_id in [
            ("mint", 10), ("zorin", 11), ("cachyos", 3),
            ("popos", 12), ("q4os", 13), ("bazzite", 254),
        ]:
            for task in backlog["next_gates"]:
                if task["role"] == role:
                    task["related_issues"] = [issue_id]
            manual.append({
                "number": issue_id, "state": "open",
                "title": f"{role.title()} lifecycle acceptance issue",
                "repository_url": triage.API,
                "user": {"login": "LMhdez"},
            })
        # Only explicit main-source issue-to-gate mappings may defer work.
        self.assertEqual(triage.choose(backlog, [], manual)["role"], "mint")
        backlog["next_gates"][-1]["related_issues"] = []
        self.assertEqual(triage.choose(backlog, [], manual)["role"], "bazzite")
        backlog["next_gates"][-1]["gate"] = "install"
        with self.assertRaises(ValueError):
            triage.choose(backlog, [], manual)

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
        push, rest = workflow.split("  push:\n", 1)
        push_paths, pr_and_jobs = rest.split("  pull_request:\n", 1)
        pr_paths = pr_and_jobs.split("\npermissions:", 1)[0]
        for filename in (
            "auto_tests/tools/gaslux_agent_task_triage.py",
            "auto_tests/tests/test_gaslux_agent_task_triage.py",
        ):
            self.assertIn("      - " + filename, push_paths)
            self.assertIn("      - " + filename, pr_paths)


if __name__ == "__main__":
    unittest.main()
