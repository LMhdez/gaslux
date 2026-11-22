"""Offline independent Safety contract tests for trusted default-branch publisher."""
from __future__ import annotations
import base64
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

    def test_stale_dev_denied_before_publishing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "report.json").write_text(json.dumps(self.report))
            (root / "candidate.cs").write_bytes(self.changed)
            with patch.object(pub, "ARTIFACT", root), patch.object(pub, "request") as api:
                api.return_value = {"object": {"sha": "a" * 40}}
                with self.assertRaisesRegex(RuntimeError, "stale"):
                    pub.verify_evidence()
                self.assertEqual(api.call_count, 1)

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


if __name__ == "__main__":
    unittest.main()
