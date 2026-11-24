"""Offline independent Safety contract tests for trusted default-branch publisher."""
from __future__ import annotations
import ast
import base64
import re
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gaslux_agent_trusted_publish.py"
SPEC = importlib.util.spec_from_file_location("gaslux_agent_trusted_publish", SCRIPT)
assert SPEC and SPEC.loader
pub = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pub)


class TrustedPublisherTests(unittest.TestCase):
    def setUp(self):
        self.original = b'using System;\nclass Map {\n    { "00000809", Mapping("gb") },\n}\n'
        self.changed = b'using System;\nclass Map {\n    { "00000809", Mapping("gb") },\n    { "00000816", Mapping("pt") },\n}\n'
        self.report = {
            "role": "mint", "task_id": "MINT-PT-KEYBOARD-01",
            "target": pub.SOURCE, "base_commit": "f" * 40,
            "model": pub.MODEL, "model_digest": pub.DIGEST,
            "status": "candidate_green", "candidate_valid": True,
            "source_sha256": pub.sha(self.original),
            "candidate_sha256": pub.sha(self.changed),
            "task_identifier": "00000816", "expected_layout": "pt",
            "attempts": [{"attempt": 1, "passed": True}],
        }

    def test_exact_feature_passes(self):
        self.assertEqual(pub.validate(self.report, self.original, self.changed),
                         ("MINT-PT-KEYBOARD-01", "mint"))

    def test_wrong_code_and_extra_statement_denied(self):
        attack = self.changed.replace(b'    { "00000816", Mapping("pt") },',
            b'    { "00000816", Mapping("pt") },\n    DoDanger();')
        self.report["candidate_sha256"] = pub.sha(attack)
        with self.assertRaises(ValueError):
            pub.validate(self.report, self.original, attack)

    def test_unapproved_model_and_role_denied(self):
        for field, value in (("model", "qwen-other"), ("role", "safety"),
                             ("status", "claimed_success"), ("candidate_valid", False)):
            item = dict(self.report)
            item[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                pub.validate(item, self.original, self.changed)

    def test_corrupt_or_missing_evidence_denied(self):
        for key, value in (("source_sha256", "a" * 40), ("candidate_sha256", "b" * 64),
                           ("base_commit", "dev"), ("attempts", [])):
            item = dict(self.report)
            item[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                pub.validate(item, self.original, self.changed)

    def test_wrong_authorized_identifier_denied(self):
        item = dict(self.report)
        item["task_identifier"] = "00000416"
        with self.assertRaises(ValueError):
            pub.validate(item, self.original, self.changed)

    def test_stale_dev_with_product_change_is_rejected(self):
        def fake_api(method, route, body=None, missing_ok=False):
            if route == "/git/ref/heads/dev":
                return {"object": {"sha": "a" * 40}}
            if route.startswith("/contents/"):
                return {"content": base64.b64encode(self.original).decode()}
            if route.startswith("/compare/"):
                return {"status": "ahead", "behind_by": 0, "ahead_by": 1,
                        "total_commits": 1, "files": [
                            {"filename": "Installation/InstallationEngine.cs", "status": "modified"}]}
            raise AssertionError(route)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "report.json").write_text(json.dumps(self.report))
            (root / "candidate.cs").write_bytes(self.changed)
            with patch.object(pub, "ARTIFACT", root), patch.object(pub, "request", side_effect=fake_api):
                with self.assertRaisesRegex(RuntimeError, "product or agent-sensitive"):
                    pub.verify_evidence()

    def test_nonproduct_docs_dev_advance_admitted_only_with_same_source(self):
        def fake_api(method, route, body=None, missing_ok=False):
            if route == "/git/ref/heads/dev":
                return {"object": {"sha": "a" * 40}}
            if route.startswith("/contents/"):
                return {"content": base64.b64encode(self.original).decode()}
            if route.startswith("/compare/"):
                return {"status": "ahead", "behind_by": 0, "ahead_by": 25,
                        "total_commits": 25, "files": [
                            {"filename": "docs/distro-backends/SHARED_CONTRACTS.md", "status": "modified"},
                            {"filename": "auto_tests/installer_observer/authenticated_destination.py", "status": "added"},
                            {"filename": ".github/workflows/contracts-authenticated-destination-readonly.yml", "status": "added"},
                        ]}
            raise AssertionError(route)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "report.json").write_text(json.dumps(self.report))
            (root / "candidate.cs").write_bytes(self.changed)
            with patch.object(pub, "ARTIFACT", root), patch.object(pub, "request", side_effect=fake_api):
                report, candidate, task, role = pub.verify_evidence()
                self.assertEqual(report["effective_base_commit"], "a" * 40)
                self.assertEqual(report["base_commit"], "f" * 40)
                self.assertEqual(candidate, self.changed)
                self.assertEqual((task, role), ("MINT-PT-KEYBOARD-01", "mint"))

    def test_nonproduct_claim_with_modified_csharp_source_is_rejected(self):
        def fake_api(method, route, body=None, missing_ok=False):
            if route == "/git/ref/heads/dev":
                return {"object": {"sha": "a" * 40}}
            if route.startswith("/contents/"):
                blob = self.changed if route.endswith("a" * 40) else self.original
                return {"content": base64.b64encode(blob).decode()}
            if route.startswith("/compare/"):
                return {"status": "ahead", "behind_by": 0, "ahead_by": 1,
                        "total_commits": 1,
                        "files": [{"filename": "docs/README.md", "status": "modified"}]}
            raise AssertionError(route)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "report.json").write_text(json.dumps(self.report))
            (root / "candidate.cs").write_bytes(self.changed)
            with patch.object(pub, "ARTIFACT", root), patch.object(pub, "request", side_effect=fake_api):
                with self.assertRaisesRegex(RuntimeError, "C# source changed"):
                    pub.verify_evidence()

    def test_agent_runtime_or_workflow_change_blocks_source_reuse(self):
        for file in ("auto_tests/tools/gaslux_agent_implement.py",
                     ".github/workflows/gaslux-agent-builder.yml",
                     "Libertix.csproj"):
            with self.subTest(file=file), patch.object(pub, "request",
                 return_value={"status": "ahead", "behind_by": 0, "ahead_by": 1,
                               "total_commits": 1,
                               "files": [{"filename": file, "status": "modified"}]}):
                with self.assertRaisesRegex(RuntimeError, "product or agent-sensitive"):
                    pub.admit_nonproduct_dev_advance("f" * 40, "a" * 40)

    def test_workflow_cannot_publish_on_pr_or_dev(self):
        for event, ref in (("pull_request", "refs/pull/1/merge"),
                           ("push", "refs/heads/dev"),
                           ("schedule", "refs/heads/dev")):
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": pub.REPO,
                                          "GITHUB_EVENT_NAME": event, "GITHUB_REF": ref}):
                with patch.object(pub, "request") as api:
                    with self.assertRaisesRegex(RuntimeError, "trusted main"):
                        pub.publish()
                    api.assert_not_called()

    def test_authenticated_fake_rest_creates_only_draft(self):
        calls = []
        branches = {}
        encoded = base64.b64encode(self.original).decode()
        def fake_api(method, route, body=None, missing_ok=False):
            calls.append((method, route, body))
            if method == "GET" and route == "/git/ref/heads/dev":
                return {"object": {"sha": "f" * 40}}
            if method == "GET" and route.startswith("/contents/"):
                return {"content": encoded, "sha": "blob-id"}
            if method == "GET" and route.startswith("/git/ref/heads/bot/"):
                return branches.get(route)
            if method == "POST" and route == "/git/refs":
                branches["/git/ref/heads/" + body["ref"].removeprefix("refs/heads/")] = {
                    "object": {"sha": body["sha"]}}
                return {}
            if method == "PUT" and route.startswith("/contents/"):
                return {"commit": {"sha": "e" * 40}}
            if method == "POST" and route == "/pulls":
                return {"html_url": "https://github.com/LMhdez/gaslux/pull/999"}
            raise AssertionError((method, route))
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "report.json").write_text(json.dumps(self.report))
            (folder / "candidate.cs").write_bytes(self.changed)
            with patch.object(pub, "ARTIFACT", folder), patch.object(
                pub, "request", side_effect=fake_api
            ), patch.dict(os.environ, {"GITHUB_REPOSITORY": pub.REPO,
                                      "GITHUB_EVENT_NAME": "schedule",
                                      "GITHUB_REF": "refs/heads/main"}):
                pub.publish()
        writes = [(m, r, body) for m, r, body in calls if m in ("PUT", "POST", "DELETE")]
        self.assertEqual([(m, r) for m, r, _ in writes],
            [("POST", "/git/refs"), ("PUT", "/contents/" + pub.SOURCE), ("POST", "/pulls")])
        self.assertTrue(writes[-1][2]["draft"])
        self.assertEqual(writes[-1][2]["base"], "dev")
        self.assertTrue(writes[1][2]["branch"].startswith("bot/gaslux-mint-keyboard-"))

    def test_windows_job_uses_reviewed_worker_sha_across_partial_reruns(self):
        # Failed-jobs re-run can retry only backend_developer, while prior
        # supervisor outputs stay unchanged. The Windows job must bind to the
        # actual artifact SHA that independent Safety validated, never to a
        # stale supervisor output. Artifacts must live outside checkout.
        yaml = (SCRIPT.parents[2] / ".github/workflows/gaslux-agent-clock.yml").read_text()
        start = yaml.index("  windows_wpf_acceptance:")
        end = yaml.index("\n  integrator_publisher:", start)
        segment = yaml[start:end]
        self.assertIn("id: worker_source", segment)
        self.assertIn("steps.worker_source.outputs.sha", segment)
        self.assertIn("runner.temp", segment)
        self.assertIn("git\",\"show\",\"HEAD:Installation/WindowsKeyboardLayout.cs", segment)
        self.assertIn("report.candidate_sha256", segment)
        self.assertNotIn("needs.supervisor.outputs.base_sha", segment)

    def test_windows_contract_tests_use_prebuilt_msbuild_binaries(self):
        yaml = (SCRIPT.parents[2] / ".github/workflows/gaslux-agent-clock.yml").read_text()
        segment = yaml.split("  windows_wpf_acceptance:", 1)[1].split(
            "\n  integrator_publisher:", 1
        )[0]
        self.assertIn("msbuild Libertix.sln /restore", segment)
        self.assertIn("dotnet test Libertix.Tests/Libertix.Tests.csproj --configuration Release --no-restore --no-build", segment)
        self.assertLess(segment.index("msbuild Libertix.sln"), segment.index("dotnet test Libertix.Tests"))

    def test_candidate_source_wrong_location_denied(self):
        item = dict(self.report)
        item["target"] = "/dev/sda"
        with self.assertRaises(ValueError):
            pub.validate(item, self.original, self.changed)



    @staticmethod
    def _job_allowed(workflow: str, job: str, facts: dict[str, str]) -> bool:
        """Evaluate the actual YAML if expression, with no eval/exec."""
        section = re.split(r"(?m)^  [A-Za-z0-9_]+:\s*$", workflow.split(f"  {job}:\n", 1)[1], maxsplit=1)[0]
        header = section.split("    runs-on:", 1)[0]
        predicate = header.split("    if: >-\n", 1)[1].split(
            "    environment:", 1
        )[0]
        expression = " ".join(line.strip() for line in predicate.splitlines())
        expression = re.sub(
            r"\b(?:github|vars|needs)\.[A-Za-z0-9_.]+",
            lambda match: "facts[" + repr(match.group()) + "]",
            expression,
        ).replace("&&", " and ").replace("||", " or ")
        tree = ast.parse(expression, mode="eval")

        def interpret(node):
            if isinstance(node, ast.Expression):
                return interpret(node.body)
            if isinstance(node, ast.BoolOp):
                values = [bool(interpret(value)) for value in node.values]
                if isinstance(node.op, ast.And):
                    return all(values)
                if isinstance(node.op, ast.Or):
                    return any(values)
            if isinstance(node, ast.Compare) and len(node.ops) == 1:
                left, right = interpret(node.left), interpret(node.comparators[0])
                if isinstance(node.ops[0], ast.Eq):
                    return left == right
                if isinstance(node.ops[0], ast.NotEq):
                    return left != right
            if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                    and node.value.id == "facts"
                    and isinstance(node.slice, ast.Constant)):
                return facts[node.slice.value]
            if isinstance(node, ast.Constant):
                return node.value
            raise AssertionError("Unexpected workflow predicate node: " + type(node).__name__)

        return bool(interpret(tree))

    def test_f_397_01_nonmain_dispatch_cannot_reach_app_publisher(self):
        workflow = (SCRIPT.parents[2] / ".github/workflows/gaslux-agent-clock.yml").read_text()
        trusted = {
            "github.repository": "LMhdez/gaslux",
            "github.ref": "refs/heads/main",
            "github.event_name": "workflow_dispatch",
            "vars.GASLUX_AUTONOMY_PAUSED": "false",
            "needs.backend_developer.outputs.candidate_ready": "true",
            "needs.safety_review.result": "success",
            "needs.windows_wpf_acceptance.result": "success",
        }
        for event in ("schedule", "workflow_dispatch", "push"):
            main = dict(trusted, **{"github.event_name": event})
            self.assertTrue(self._job_allowed(workflow, "supervisor", main), event)
            self.assertTrue(self._job_allowed(workflow, "integrator_publisher", main), event)
        for untrusted_ref in ("refs/heads/attacker-controlled", "refs/heads/dev",
                              "refs/tags/attacker"):
            attempt = dict(trusted, **{"github.ref": untrusted_ref})
            self.assertFalse(self._job_allowed(workflow, "supervisor", attempt))
            self.assertFalse(self._job_allowed(workflow, "integrator_publisher", attempt))
        self.assertFalse(self._job_allowed(
            workflow, "integrator_publisher", dict(trusted, **{
                "needs.safety_review.result": "failure",
            }),
        ))
        self.assertFalse(self._job_allowed(
            workflow, "integrator_publisher", dict(trusted, **{
                "vars.GASLUX_AUTONOMY_PAUSED": "true",
            }),
        ))
        self.assertFalse(self._job_allowed(
            workflow, "integrator_publisher", dict(trusted, **{
                "github.repository": "attacker/gaslux",
            }),
        ))

    def test_publishers_require_protected_environment_and_no_key_fallback(self):
        for file, job in (
            (".github/workflows/gaslux-agent-clock.yml", "integrator_publisher"),
            (".github/workflows/gaslux-agent-feature-factory.yml", "publish_draft"),
        ):
            workflow = (SCRIPT.parents[2] / file).read_text()
            section = re.split(r"(?m)^  [A-Za-z0-9_]+:\s*$", workflow.split(f"  {job}:\n", 1)[1], maxsplit=1)[0]
            before, credential = section.split("    steps:\n", 1)
            self.assertIn("github.repository == 'LMhdez/gaslux'", before)
            self.assertIn("github.ref == 'refs/heads/main'", before)
            self.assertIn("    environment: gaslux-main-publisher", before)
            self.assertIn("id: publish_identity", credential)
            self.assertIn("if: ${{ vars.GASLUX_PUBLISH_APP_CLIENT_ID != '' }}", credential)
            self.assertIn("private-key: ${{ secrets.GASLUX_PUBLISH_APP_PRIVATE_KEY }}", credential)
            self.assertIn("repositories: gaslux", credential)
            self.assertIn("permission-contents: write", credential)
            self.assertIn("permission-pull-requests: write", credential)
            self.assertNotIn("continue-on-error: true", credential)
            # GitHub's pinned create-token action has required: true for private-key.
            # If App ID is set and env secret is missing, the token action fails,
            # so the publishing step cannot use the GH_TOKEN fallback.
            self.assertLess(credential.index("id: publish_identity"),
                            credential.index("GH_TOKEN:"))
            self.assertNotIn("pull_request_target:", workflow)

    def test_clock_pr_publish_token_is_not_shared_with_untrusted_worker(self):
        workflow = (
            SCRIPT.parents[2] / ".github/workflows/gaslux-agent-clock.yml"
        ).read_text(encoding="utf-8")
        developer, publisher = workflow.split("  integrator_publisher:\n", 1)
        self.assertNotIn("GASLUX_PUBLISH_APP_PRIVATE_KEY", developer)
        self.assertIn("id: publish_identity", publisher)
        self.assertIn("vars.GASLUX_PUBLISH_APP_CLIENT_ID != ''", publisher)
        self.assertIn("secrets.GASLUX_PUBLISH_APP_PRIVATE_KEY", publisher)
        self.assertIn("repositories: gaslux", publisher)
        self.assertIn("permission-contents: write", publisher)
        self.assertIn("permission-pull-requests: write", publisher)
        self.assertIn(
            "GH_TOKEN: ${{ steps.publish_identity.outputs.token || secrets.GITHUB_TOKEN }}",
            publisher,
        )
        self.assertNotIn("pull_request_target:", workflow)

if __name__ == "__main__":
    unittest.main()
