"""Offline adversarial contracts: Pi mirrors ALL FOUR scheduled GitHub workflows."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("raspberrypi_scheduler.py")
SPEC = importlib.util.spec_from_file_location("pi_scheduler", SCRIPT)
assert SPEC and SPEC.loader
pi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pi)
NOW = datetime(2026, 11, 23, 7, 0, tzinfo=timezone.utc)
SHA = "a" * 40


def run(when=None, **kw):
    row = {"id": 101, "head_branch": "main", "head_sha": SHA,
           "event": "schedule", "status": "completed", "conclusion": "success",
           "created_at": (when or (NOW - timedelta(hours=3))).isoformat()}
    row.update(kw)
    return row


class Response(io.BytesIO):
    def __init__(self, content=b"", status=200):
        super().__init__(content)
        self.status = status


def mock_api(calls, rows=None):
    def opener(req, timeout):
        calls.append((req.full_url, req.get_method(), req.data))
        if req.get_method() == "POST":
            return Response(status=204)
        items = rows.get(req.full_url, []) if isinstance(rows, dict) else (rows or [])
        return Response(json.dumps({"total_count": len(items),
                                    "workflow_runs": items}).encode())
    return opener


@contextmanager
def mock_lock():
    yield


class ScheduleTests(unittest.TestCase):
    def home(self, root, enabled=True, dry_run=True, token=True):
        home = Path(root)
        directory = home / ".config" / "gaslux"
        directory.mkdir(parents=True)
        os.chmod(directory, 0o700)
        conf = directory / pi.CONFIG_NAME
        conf.write_text(json.dumps({"enabled": enabled, "dry_run": dry_run}))
        os.chmod(conf, 0o600)
        if token:
            secret = directory / pi.TOKEN_NAME
            secret.write_text("offline-unit-test-token-123456\n")
            os.chmod(secret, 0o600)
        return home

    def tick(self, home, now=NOW, opener=None):
        with patch.object(pi, "exclusive_session", mock_lock):
            return pi.tick(home=home, now=now, opener=opener)

    def test_fixed_allowlist_matches_four_actual_workflows(self):
        self.assertEqual(len({row[0] for row in pi.TASKS}), 4)
        self.assertEqual(len(pi.TASKS), 5)
        self.assertEqual([r[1] for r in pi.TASKS],
                         ["clock", "factory", "integrator", "lifecycle", "mint_daily"])
        self.assertEqual(pi.TASKS[-1][4], {"mint_live_boot": "true"})
        self.assertEqual(pi.TASKS[0][4], {"role": "auto"})

    def test_exact_15_30_minute_and_daily_utc_schedule(self):
        expected = {"clock": (3,18,33,48), "factory": (6,21,36,51),
                    "integrator": (10,25,40,55), "lifecycle": (16,46)}
        for row in pi.TASKS:
            if row[1] == "mint_daily":
                self.assertEqual(pi.last_due(
                    datetime(2026,11,23,3,31,1,tzinfo=timezone.utc),
                    row[2], row[3]).isoformat(), "2026-11-23T03:31:00+00:00")
            else:
                self.assertEqual(row[2], expected[row[1]])
        self.assertEqual(pi.last_due(NOW, (3,18,33,48), None),
                         datetime(2026,11,23,6,48,tzinfo=timezone.utc))

    def test_fixed_times_match_actual_yaml_and_daily_mint_guard(self):
        workflows = Path(__file__).resolve().parents[3] / ".github" / "workflows"
        for name, task_key, minutes, hour, inputs in pi.TASKS:
            text = (workflows / name).read_text()
            minute_str = ",".join(str(x) for x in minutes)
            cron = minute_str + (" * * * *" if hour is None
                                 else " " + str(hour) + " * * *")
            self.assertIn("- cron: '" + cron + "'", text, name)
            self.assertIn("workflow_dispatch:", text)
            if task_key == "mint_daily":
                self.assertIn("github.event.schedule == '" + cron + "'", text)
                self.assertIn("inputs.mint_live_boot == true", text)

    def test_paused_default_never_calls_github(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.tick(Path(tmp), opener=lambda *_args, **_kw:
                               self.fail("API called while paused"))
        self.assertEqual(result["status"], "PAUSED")

    def test_all_four_workflows_dispatch_at_due_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            calls = []
            result = self.tick(home, opener=mock_api(calls))
            posts = [x for x in calls if x[1] == "POST"]
            self.assertEqual(len(posts), 4)
            self.assertEqual({url.split("/")[8] for url, _, _ in posts},
                             {task[0] for task in pi.TASKS})
            self.assertEqual(result["status"], "OK")
            self.assertTrue(all(x["status"] == "DISPATCH_REQUESTED" for x in result["decisions"]))
            for url, _method, body in posts:
                self.assertEqual(json.loads(body)["ref"], "main")
                self.assertIn(url.split("/")[8],
                              {row[0] for row in pi.TASKS})
            self.assertEqual(pi.get_state(home)["mint_daily"],
                             "2026-11-23T03:31:00+00:00")

    def test_daily_mint_dispatch_uses_true_not_readonly_only(self):
        now = datetime(2026,11,23,3,31,3,tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            calls = []
            self.tick(home, now, opener=mock_api(calls))
            lifecycle = [json.loads(body) for url, method, body in calls if
                         method == "POST" and "lifecycle" in url]
            self.assertEqual(lifecycle, [{
                "ref":"main","inputs":{"mint_live_boot":"true"}}])

    def test_no_repeat_same_slot_when_github_list_is_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            first = []
            self.tick(home, opener=mock_api(first))
            second = []
            result = self.tick(home, NOW+timedelta(minutes=1), mock_api(second))
            self.assertEqual(len([x for x in first if x[1] == "POST"]), 4)
            self.assertEqual(len([x for x in second if x[1] == "POST"]), 0)
            self.assertEqual(result["status"], "OK")

    def test_slot_progresses_next_period_without_success_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            self.tick(home, opener=mock_api([]))
            calls = []
            # A new slot is due 16 minutes later, even if previous runs failed.
            self.tick(home, NOW+timedelta(minutes=16), mock_api(calls))
            self.assertEqual({url.split("/")[8] for url, method, _ in calls if
                              method == "POST"},
                             {row[0] for row in pi.TASKS[:4]})

    def test_queued_in_progress_or_waiting_prevents_all_duplicates(self):
        for status in ("queued", "in_progress", "waiting", "pending", "requested"):
            with self.subTest(status=status):
                with tempfile.TemporaryDirectory() as tmp:
                    home = self.home(tmp, dry_run=False)
                    calls = []
                    result = self.tick(home, opener=mock_api(
                        calls, [run(status=status, conclusion=None)]))
                    self.assertFalse(any(x[1] == "POST" for x in calls))
                    self.assertEqual(len(result["decisions"]), 4)
                    self.assertTrue(all(row["status"] == "ALREADY_RUNNING"
                                        for row in result["decisions"]))

    def test_failure_is_not_a_reason_to_stop_next_tick(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            calls = []
            self.tick(home, opener=mock_api(calls, [
                run(conclusion="failure"), run(conclusion="cancelled",id=102)]))
            self.assertEqual(len([x for x in calls if x[1] == "POST"]), 4)

    def test_native_event_covers_slot_without_duplicate(self):
        # Clock last due 06:48; a native 06:49 schedule means no second run.
        slot = datetime(2026, 11, 23, 6,49,tzinfo=timezone.utc)
        rows = {pi.API+"gaslux-agent-clock.yml/runs?branch=main&per_page=100":
                [run(when=slot)]}
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            calls = []
            result = self.tick(home, opener=mock_api(calls, rows))
            self.assertNotIn("gaslux-agent-clock.yml",
                             [url.split("/")[8] for url, method, _ in calls
                              if method == "POST"])
            self.assertEqual(result["decisions"][0]["status"],"ALREADY_TRIGGERED")

    def test_dry_run_zero_post_even_when_every_task_due(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=True)
            calls = []
            result = self.tick(home, opener=mock_api(calls))
            self.assertFalse(any(method=="POST" for _,method,_ in calls))
            self.assertEqual(len([x for x in result["decisions"] if
                                  x["status"] == "WOULD_DISPATCH"]), 4)

    def test_missing_token_blocks_first_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=self.home(tmp, dry_run=False, token=False)
            calls=[]
            with self.assertRaises((FileNotFoundError,ValueError)):
                self.tick(home, opener=mock_api(calls))
            self.assertFalse(any(x[1]=="POST" for x in calls))

    def test_malformed_run_identity_rejected(self):
        for row in [run(head_sha="bad"),run(head_branch="dev"),
                    run(status="unrecognized"),run(created_at="not-date")]:
            with self.subTest(row=row):
                with self.assertRaises((ValueError,TypeError)):
                    pi.parse_runs({"total_count":1,"workflow_runs":[row]})

    def test_unexpected_history_shape_rejected(self):
        for document in ({}, {"total_count":"100","workflow_runs":[]},
                         {"total_count":120,"workflow_runs":[run()]*101}):
            with self.assertRaises(ValueError):
                pi.parse_runs(document)

    def test_config_symlink_hardlink_and_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=self.home(tmp)
            path=home/".config"/"gaslux"/pi.CONFIG_NAME
            alias=home/"alias"
            os.link(path,alias)
            with self.assertRaises(ValueError): pi.configuration(home)
            alias.unlink()
            path.unlink()
            path.symlink_to(home/"missing")
            with self.assertRaises(OSError): pi.configuration(home)

    def test_state_persists_without_symlink_and_atomic_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=self.home(tmp)
            pi.set_state(home,{"clock":"2026-11-23T06:48:00+00:00"})
            self.assertEqual(pi.get_state(home)["clock"], "2026-11-23T06:48:00+00:00")
            os.chmod(home/".config"/"gaslux"/pi.STATE_NAME,0o644)
            with self.assertRaises(ValueError): pi.get_state(home)

    def test_time_restart_catches_up_latest_slot_not_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=self.home(tmp,dry_run=False)
            pi.set_state(home, {"clock":"2026-11-23T06:03:00+00:00"})
            calls=[]
            result=self.tick(home, opener=mock_api(calls))
            self.assertEqual(result["status"],"OK")
            self.assertEqual(pi.get_state(home)["clock"],
                             "2026-11-23T06:48:00+00:00")

    def test_systemd_poll_minutely_and_existing_safety_unmodified(self):
        base=Path(__file__).parent
        unit=(base/"gaslux-fallback.service").read_text()
        timer=(base/"gaslux-fallback.timer").read_text()
        self.assertIn("Type=oneshot",unit)
        self.assertIn("NoNewPrivileges=true",unit)
        self.assertIn("OnCalendar=*-*-* *:*:00 UTC",timer)
        self.assertIn("Persistent=true",timer)
        self.assertNotIn("sudo ",unit)
        self.assertNotIn("ExecStartPre=",unit)


if __name__ == "__main__":
    unittest.main()
