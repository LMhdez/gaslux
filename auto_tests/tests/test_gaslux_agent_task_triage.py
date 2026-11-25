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
        outsider = self.task_claim_pr(author="outside-contributor")
        outsider["user"]["type"] = "User"
        for forged in [
            self.task_claim_pr(repo="attacker/gaslux"), outsider,
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
        # Isolate the Bazzite gate so upstream pending roles cannot short-circuit
        # the scope negative fixture.
        backlog["next_gates"] = [bazzite]
        bazzite["related_issues"] = []
        self.assertEqual(triage.choose(backlog, [], manual)["role"], "bazzite")
        bazzite["gate"] = "install"
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

    def test_workflow_passes_only_trusted_main_app_actor_setting(self):
        workflow = (SCRIPT.parents[2] /
                    ".github/workflows/gaslux-agent-feature-factory.yml").read_text()
        _, triage_job = workflow.split("  triage_missing_gates:\n", 1)
        # The fallback is the exact GitHub App actor observed on PR #407,
        # never a wildcard Bot or a value copied from untrusted dev.
        expected_actor_setting = (
            "GASLUX_PUBLISH_APP_BOT_LOGIN: "
            "${{ vars.GASLUX_PUBLISH_APP_BOT_LOGIN || "
            "'gaslux-autonomous-publisher[bot]' }}"
        )
        self.assertIn(expected_actor_setting, triage_job)
        self.assertEqual(triage_job.count(expected_actor_setting), 1)
        self.assertNotIn("GASLUX_PUBLISH_APP_PRIVATE_KEY", triage_job)

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


class AdmissionRepairTests(unittest.TestCase):
    HEAD, BASE = "a" * 40, "b" * 40
    ENV = {"GITHUB_REPOSITORY": triage.REPO, "GITHUB_REF": "refs/heads/main",
           "GITHUB_EVENT_NAME": "schedule"}

    def row(self, **changes):
        return {
            "pr": 395, "role": "zorin", "head": self.HEAD, "base": self.BASE,
            "exact_scope_verified": True, "current_base_verified": False,
            "ci_verified": True, "ci_workflow_provenance_verified": True,
            "technical_objection": False, "merge_authorized": False,
            "release_eligible": False, "next_action": "REFRESH_CANDIDATE_BASE",
            **changes,
        }

    def issue(self, **changes):
        return {
            **triage.repair_issue_payload(395, self.HEAD, self.BASE, "zorin"),
            "repository_url": triage.API, "state": "closed",
            "user": {"login": "github-actions[bot]", "id": 41898282},
            **changes,
        }

    def test_repair_requires_exact_stale_non_objection_verified_candidate(self):
        self.assertTrue(triage.repair_eligible(self.row(), 395, "zorin", self.HEAD))
        for changes in (
            {"head": self.BASE}, {"role": "bazzite"}, {"base": "bad"},
            {"pr": 396}, {"exact_scope_verified": False},
            {"current_base_verified": True}, {"ci_verified": False},
            {"ci_workflow_provenance_verified": False},
            {"technical_objection": True}, {"technical_objection": None},
            {"merge_authorized": True}, {"release_eligible": True},
            {"next_action": "VERIFY_IDENTITY_AND_SCOPE"},
        ):
            self.assertFalse(triage.repair_eligible(self.row(**changes), 395, "zorin", self.HEAD))

    def test_stable_issue_identity_ignores_base_and_closed_state(self):
        key = {(395, self.HEAD)}
        self.assertEqual(triage.repair_keys([self.issue()]), key)
        other = triage.repair_issue_payload(395, self.HEAD, "c" * 40, "zorin")
        self.assertEqual(triage.repair_keys([self.issue(**other)]), key)
        for changes in (
            {"user": {"login": "github-actions[bot]", "id": 1}},
            {"repository_url": "https://api.github.com/repos/fork/gaslux"},
            {"title": "unrelated"}, {"pull_request": {}},
            {"body": "copied marker\n" + self.issue()["body"]},
        ):
            self.assertEqual(triage.repair_keys([self.issue(**changes)]), set())

    def test_repair_creation_rechecks_live_scope_and_never_duplicates(self):
        import gaslux_distro_admission as admission
        inventory = {395: ("zorin", self.HEAD)}
        for scenario in ("created", "dry", "tracked", "objection", "drift", "race", "head"):
            with self.subTest(scenario=scenario):
                rows = [self.row(), self.row()]
                if scenario == "objection":
                    rows[1] = self.row(technical_objection=True)
                elif scenario == "drift":
                    rows[1] = self.row(base="c" * 40)
                history = [[self.issue()] if scenario == "tracked" else [],
                           [self.issue()] if scenario == "race" else []]
                inventories = [inventory, {} if scenario == "head" else inventory]
                with patch.dict("os.environ", self.ENV, clear=True), \
                     patch.object(admission, "discover_candidates", side_effect=inventories), \
                     patch.object(admission, "inspect", side_effect=rows), \
                     patch.object(triage, "all_issues", side_effect=history), \
                     patch.object(triage, "api", side_effect=[
                         {"object": {"sha": self.BASE}}, {"number": 800}
                     ]) as api:
                    result = triage.sync_admission_repair(dry_run=scenario == "dry")
                expected = {
                    "created": "repair_issue_created", "dry": "repair_dry_run",
                    "tracked": "no_repair_action", "objection": "repair_retry",
                    "drift": "repair_retry", "race": "repair_already_queued",
                    "head": "repair_retry",
                }
                self.assertEqual(result["status"], expected[scenario])
                posts = [call for call in api.call_args_list if call.args[0] == "POST"]
                self.assertEqual(len(posts), int(scenario == "created"))
                if posts:
                    self.assertEqual(posts[0].args[1], "/issues")
                    self.assertIn("NEEDS_SCOPE_REVIEW", posts[0].args[2]["body"])

    def test_repair_is_blocked_before_api_on_untrusted_event(self):
        for key, value in (("GITHUB_REF", "refs/heads/dev"),
                           ("GITHUB_REPOSITORY", "fork/gaslux"),
                           ("GITHUB_EVENT_NAME", "pull_request"),
                           ("GASLUX_AUTONOMY_PAUSED", "true")):
            with patch.dict("os.environ", dict(self.ENV, **{key: value}), clear=True), \
                 patch.object(triage, "api") as api:
                with self.assertRaises(RuntimeError):
                    triage.sync_admission_repair()
                api.assert_not_called()


class ImplementationDiscoveryTests(unittest.TestCase):
    def test_detects_explicit_stub_not_pass_or_conditional_or_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / triage.TASKS["zorin"][0]
            path.parent.mkdir(parents=True)
            path.write_text(
                'def new_capability():\n    """Pending native implementation."""\n'
                '    raise NotImplementedError("missing")\n'
                'def conditional(x):\n    if x:\n        raise NotImplementedError\n'
                'def noop():\n    pass\n'
                'def _private():\n    raise NotImplementedError\n'
                'raise RuntimeError("must never execute source")\n')
            rows = triage.discover_missing_implementations(root)
            self.assertEqual([(r["role"], r["symbol"]) for r in rows],
                             [("zorin", "new_capability")])
            self.assertFalse(rows[0]["code_authorized"])
            self.assertFalse(rows[0]["release_eligible"])
            key = rows[0]["key"]
            path.write_text("# unrelated revision\n" + path.read_text())
            self.assertEqual(triage.discover_missing_implementations(root)[0]["key"], key)

    def test_rejects_symlink_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / triage.TASKS["zorin"][0]
            path.parent.mkdir(parents=True)
            outside = root / "untrusted.py"
            outside.write_text("def missing():\n    raise NotImplementedError\n")
            path.symlink_to(outside)
            with self.assertRaises(ValueError):
                triage.discover_missing_implementations(root)


    def test_missing_api_has_existing_test_witness_and_no_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, test, _ = triage.TASKS["zorin"]
            path = root / source
            path.parent.mkdir(parents=True)
            path.write_text("def available():\n    return 1\n")
            suite = root / "auto_tests/tests" / test
            suite.parent.mkdir(parents=True)
            module = path.stem
            suite.write_text(
                f"from {module} import missing_api, available, unused_api\n"
                "def test_requested():\n    assert missing_api() == available()\n"
            )
            rows = triage.discover_missing_implementations(root)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["symbol"], "missing_api")
            self.assertEqual(rows[0]["reason"], "TEST_REQUIRES_MISSING_API")
            self.assertEqual(rows[0]["witness"], "auto_tests/tests/" + test)
            self.assertFalse(rows[0]["code_authorized"])
            path.write_text("def __getattr__(name):\n    return None\n")
            self.assertEqual(triage.discover_missing_implementations(root), [])


if __name__ == "__main__":
    unittest.main()
