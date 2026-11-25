"""Offline tests: no GitHub access, no credentials and no LLM."""

import datetime as dt
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "tools" / "gaslux_zero_credit_monitor.py"
SPEC = importlib.util.spec_from_file_location("monitor", PATH)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 11, 22, 16, 0, tzinfo=dt.timezone.utc)
        self.pull = {
            "number": 10,
            "title": "fix(mint): recover Windows boot",
            "base": {"ref": "dev"},
            "draft": True,
            "created_at": "2026-11-21T12:00:00Z",
            "updated_at": "2026-11-22T15:00:00Z",
            "html_url": "https://github.com/LMhdez/gaslux/pull/10",
        }

    def test_lane_core(self):
        self.assertEqual(monitor.lane(self.pull), "core")
        self.assertEqual(monitor.lane({"title": "test(bazzite): OCI signed"}), "backends")

    def test_snapshot_does_not_promote_ci_green(self):
        data = monitor.snapshot(
            "LMhdez/gaslux",
            [self.pull],
            [{"merged_at": "2026-11-22T14:00:00Z", "base": {"ref": "dev"}}],
            {"commit": {"sha": "d" * 40}},
            {"commit": {"sha": "m" * 40}},
            {"workflow_runs": [{"status": "completed", "conclusion": "success"}]},
            self.now,
        )
        self.assertEqual(data["open_prs"], 1)
        self.assertEqual(data["draft_prs"], 1)
        self.assertEqual(data["dev_merges_last_24h"], 1)
        self.assertEqual(data["full_native_installation_verified"], "NOT_ASSESSED_BY_THIS_MONITOR")
        self.assertEqual(data["ai_api_calls"], 0)
        self.assertEqual(data["writes_to_github"], 0)

    def test_old_merge_not_counted(self):
        data = monitor.snapshot(
            "LMhdez/gaslux", [],
            [{"merged_at": "2026-11-20T14:00:00Z", "base": {"ref": "dev"}}],
            {"commit": {"sha": "x"}}, {"commit": {"sha": "y"}},
            {"workflow_runs": []}, self.now,
        )
        self.assertEqual(data["dev_merges_last_24h"], 0)

    def test_external_api_url_rejected(self):
        with self.assertRaises(ValueError):
            monitor.api_get("https://example.org/api", "fake")

    def test_report_explicitly_says_no_llm(self):
        data = monitor.snapshot(
            "LMhdez/gaslux", [self.pull], [],
            {"commit": {"sha": "abc"}}, {"commit": {"sha": "xyz"}},
            {"workflow_runs": []}, self.now,
        )
        report = monitor.md_report(data)
        self.assertIn("não chama modelos de IA", report)
        self.assertIn("#10", report)


if __name__ == "__main__":
    unittest.main()
