#!/usr/bin/env python3
"""Adversarial no-network tests for the privileged Draft PR publisher."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "auto_tests/tools/ai_rank_draft_publisher.py"
SPEC = importlib.util.spec_from_file_location("ai_rank_draft_publisher", SCRIPT)
assert SPEC and SPEC.loader
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class DraftPublisherTests(unittest.TestCase):
    def setUp(self):
        original = (ROOT / publisher.TARGET).read_bytes()
        self.assertEqual(original.count(publisher.FIXED.encode()), 1)
        self.good = original
        self.bad = original.replace(
            publisher.FIXED.encode(), publisher.FAULT.encode(), 1
        )
        self.head = "a" * 40
        self.report = {
            "model": "qwen3.5:9b", "target": publisher.TARGET,
            "source_sha256": publisher.sha256(self.bad),
            "candidate_sha256": publisher.sha256(self.good),
            "simulated": False, "passed": True, "status": "candidate_green",
            "baseline_red": True, "attempts": [{"attempt": 1, "passed": True}],
        }

    def test_exact_known_safe_change_accepted(self):
        publisher.validate_patch(self.bad, self.good)

    def test_noop_rejected(self):
        with self.assertRaises(ValueError):
            publisher.validate_patch(self.bad, self.bad)

    def test_arbitrary_code_rejected(self):
        attack = self.bad.replace(
            publisher.FAULT.encode(), b'return __import__("os").system("id")', 1
        )
        with self.assertRaises(ValueError):
            publisher.validate_patch(self.bad, attack)

    def test_outside_function_change_rejected(self):
        extra = self.good.replace(b"import argparse\n", b"import argparse\nimport os\n", 1)
        with self.assertRaises(ValueError):
            publisher.validate_patch(self.bad, extra)

    def test_simulated_evidence_rejected(self):
        self.report["simulated"] = True
        with self.assertRaises(ValueError):
            publisher.validate_evidence(self.report, self.good, self.head)

    def test_unverified_red_green_rejected(self):
        self.report["baseline_red"] = False
        with self.assertRaises(ValueError):
            publisher.validate_evidence(self.report, self.good, self.head)

    def test_wrong_model_rejected(self):
        self.report["model"] = "qwen2.5-coder:1.5b"
        with self.assertRaises(ValueError):
            publisher.validate_evidence(self.report, self.good, self.head)

    def test_sha256_mismatch_rejected(self):
        self.report["candidate_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            publisher.validate_evidence(self.report, self.good, self.head)

    def test_short_source_digest_rejected(self):
        self.report["source_sha256"] = "e" * 40
        with self.assertRaises(ValueError):
            publisher.validate_evidence(self.report, self.good, self.head)

    def test_invalid_trigger_rejected_before_any_network(self):
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/pull/123/merge",
            "GITHUB_REPOSITORY": publisher.REPO,
        }):
            with patch.object(publisher, "request_json") as remote:
                with self.assertRaisesRegex(RuntimeError, "trusted dev"):
                    publisher.main()
                remote.assert_not_called()

    def run_mock_publish(self, current_sha=None, source=None, post_forbidden=False):
        current_sha = current_sha or self.head
        source = source or self.bad
        calls = []

        def fake_api(method, route, payload=None, allow_missing=False):
            calls.append((method, route, payload))
            if method == "GET" and route == "/git/ref/heads/dev":
                return {"object": {"sha": current_sha}}
            if method == "GET" and route == (
                f"/contents/{publisher.TARGET}?ref={self.head}"
            ):
                # Actual GitHub base64 content is line-wrapped.
                encoded = base64.b64encode(source).decode("ascii")
                wrapped = "\n".join(encoded[i:i+60] for i in range(0, len(encoded), 60))
                return {"content": wrapped, "sha": "blob-sha"}
            if method == "GET" and route.startswith("/git/ref/heads/bot/"):
                # The first lookup is absent; a second one occurs on cleanup.
                if post_forbidden and sum(1 for m, p, _ in calls if m == "GET" and p == route) > 1:
                    return {"object": {"sha": "b" * 40}}
                return None
            if method == "POST" and route == "/pulls":
                if post_forbidden:
                    raise RuntimeError("GitHub POST /pulls returned HTTP 403")
                return {"html_url": "https://github.com/LMhdez/gaslux/pull/999"}
            if method == "PUT":
                return {"commit": {"sha": "b" * 40}}
            if method in ("POST", "DELETE"):
                return {"ok": True}
            raise AssertionError((method, route))

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = root / "ai-rank-repair.json"
            candidate = root / "ai-rank-candidate.py"
            report.write_text(json.dumps(self.report))
            candidate.write_bytes(self.good)
            with patch.object(publisher, "REPORT", report), patch.object(
                publisher, "CANDIDATE", candidate
            ), patch.object(publisher, "request_json", side_effect=fake_api), patch.dict(
                os.environ, {
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/heads/dev",
                    "GITHUB_REPOSITORY": publisher.REPO,
                    "GITHUB_SHA": self.head,
                    "GH_TOKEN": "fake-token-not-used",
                }
            ):
                if current_sha != self.head or source != self.bad or post_forbidden:
                    with self.assertRaises((ValueError, RuntimeError)):
                        publisher.main()
                else:
                    publisher.main()
        return calls

    def test_dry_run_creates_only_one_draft_pr_and_allowed_file(self):
        calls = self.run_mock_publish()
        mutations = [(m, p, d) for m, p, d in calls if m in ("POST", "PUT")]
        self.assertEqual([m for m, _, _ in mutations], ["POST", "PUT", "POST"])
        self.assertEqual(mutations[0][1], "/git/refs")
        self.assertEqual(mutations[1][1], f"/contents/{publisher.TARGET}")
        self.assertEqual(mutations[2][1], "/pulls")
        self.assertTrue(mutations[2][2]["draft"])
        self.assertEqual(mutations[2][2]["base"], "dev")

    def test_permission_denial_deletes_only_own_orphan_branch(self):
        calls = self.run_mock_publish(post_forbidden=True)
        mutations = [(m, p) for m, p, _ in calls if m in ("POST", "PUT", "DELETE")]
        self.assertEqual([m for m, _ in mutations], ["POST", "PUT", "POST", "DELETE"])
        self.assertTrue(mutations[-1][1].startswith("/git/refs/heads/bot/"))

    def test_changed_dev_base_blocks_all_mutations(self):
        calls = self.run_mock_publish(current_sha="b" * 40)
        self.assertFalse(any(m in ("POST", "PUT") for m, _, _ in calls))

    def test_mismatched_source_blocks_all_mutations(self):
        calls = self.run_mock_publish(source=self.good)
        self.assertFalse(any(m in ("POST", "PUT") for m, _, _ in calls))


if __name__ == "__main__":
    unittest.main()
