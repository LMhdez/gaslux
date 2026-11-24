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
           "created_at": (when or (NOW - timedelta(hours=3))).isoformat(),
           "display_title": "GASLUX-CLOCK/auto"}
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

    def test_safety_f38901_manual_mint_false_does_not_cover_daily(self):
        slot = datetime(2026, 11, 23, 3, 31, tzinfo=timezone.utc)
        other = run(when=slot + timedelta(minutes=1), event="workflow_dispatch",
                    display_title="GASLUX-LIFECYCLE/research")
        self.assertEqual(pi.decision([other], slot, daily=True, task="mint_daily"),
                         "DISPATCH")

    def test_safety_f38901_delayed_regular_lifecycle_does_not_cover_daily(self):
        slot = datetime(2026, 11, 23, 3, 31, tzinfo=timezone.utc)
        regular = run(when=slot + timedelta(minutes=1), event="schedule",
                      display_title="GASLUX-LIFECYCLE/research")
        self.assertEqual(pi.decision([regular], slot, daily=True, task="mint_daily"),
                         "DISPATCH")

    def test_safety_f38901_manual_role_mint_does_not_cover_auto(self):
        slot = datetime(2026, 11, 23, 7, 3, tzinfo=timezone.utc)
        manual = run(when=slot + timedelta(minutes=1), event="workflow_dispatch",
                     display_title="GASLUX-CLOCK/mint")
        self.assertEqual(pi.decision([manual], slot, task="clock"), "DISPATCH")

    def test_safety_f38901_missing_title_is_not_proof_of_same_work(self):
        clock_slot = datetime(2026, 11, 23, 7, 3, tzinfo=timezone.utc)
        past = run(when=clock_slot + timedelta(minutes=1),
                   event="workflow_dispatch", display_title=None)
        self.assertEqual(pi.decision([past], clock_slot, task="clock"), "DISPATCH")
        mint_slot = datetime(2026, 11, 23, 3, 31, tzinfo=timezone.utc)
        unknown = run(when=mint_slot + timedelta(minutes=1), event="schedule",
                      display_title="GASLUX-LIFECYCLE/unknown")
        self.assertEqual(pi.decision([unknown], mint_slot, task="mint_daily", daily=True),
                         "DISPATCH")

    def test_safety_f38901_matching_daily_identity_counts_as_delivered(self):
        slot = datetime(2026, 11, 23, 3, 31, tzinfo=timezone.utc)
        daily = run(when=slot + timedelta(minutes=1), event="schedule",
                    display_title="GASLUX-LIFECYCLE/mint-daily")
        self.assertEqual(pi.decision([daily], slot, daily=True, task="mint_daily"),
                         "ALREADY_TRIGGERED")

    def test_safety_f38901_no_false_daily_ledger_or_dropped_dispatch(self):
        now = datetime(2026, 11, 23, 3, 33, tzinfo=timezone.utc)
        false_daily = run(when=now - timedelta(minutes=1), event="workflow_dispatch",
                          display_title="GASLUX-LIFECYCLE/research")
        url = pi.API + "gaslux-agent-lifecycle-research.yml/runs?branch=main&per_page=100"
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            calls = []
            self.tick(home, now=now, opener=mock_api(calls, {url: [false_daily]}))
            lifecycle_posts = [json.loads(body) for uri, method, body in calls
                               if method == "POST" and "lifecycle" in uri]
            self.assertEqual(lifecycle_posts, [
                {"ref": "main", "inputs": {"mint_live_boot": "true"}}])
            self.assertIn("mint_daily", pi.get_state(home))

    def test_safety_f38901_matching_daily_covers_regular_without_duplicate(self):
        now = datetime(2026, 11, 23, 3, 33, tzinfo=timezone.utc)
        native_daily = run(when=now - timedelta(minutes=1), event="schedule",
                           display_title="GASLUX-LIFECYCLE/mint-daily")
        url = pi.API + "gaslux-agent-lifecycle-research.yml/runs?branch=main&per_page=100"
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            calls = []
            self.tick(home, now=now, opener=mock_api(calls, {url: [native_daily]}))
            self.assertFalse(any(method == "POST" and "lifecycle" in uri
                                 for uri, method, _ in calls))
            state = pi.get_state(home)
            self.assertIn("mint_daily", state)
            self.assertIn("lifecycle", state)

    def test_safety_f38901_workflow_run_names_encode_semantic_inputs(self):
        workflows = Path(__file__).resolve().parents[3] / ".github" / "workflows"
        clock = (workflows / "gaslux-agent-clock.yml").read_text()
        mint = (workflows / "gaslux-agent-lifecycle-research.yml").read_text()
        factory = (workflows / "gaslux-agent-feature-factory.yml").read_text()
        integrator = (workflows / "gaslux-agent-integrator.yml").read_text()
        self.assertIn("run-name:", clock)
        self.assertIn("inputs.role", clock)
        self.assertIn("GASLUX-CLOCK/", clock)
        self.assertIn("run-name:", mint)
        self.assertIn("inputs.mint_live_boot == true", mint)
        self.assertIn("github.event.schedule == '31 3 * * *'", mint)
        self.assertIn("GASLUX-LIFECYCLE/", mint)
        self.assertIn("run-name: GASLUX-FACTORY/default", factory)
        self.assertIn("run-name: GASLUX-INTEGRATOR/default", integrator)

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

    def test_one_api_failure_does_not_starve_other_workflows(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            calls = []
            fallback = mock_api(calls)
            def opener(req, timeout):
                if req.get_method() == "GET" and "gaslux-agent-clock.yml/" in req.full_url:
                    raise OSError("offline sample")
                return fallback(req, timeout)
            result = self.tick(home, opener=opener)
            self.assertEqual(result["decisions"][0]["status"], "API_RETRY_NEXT_TICK")
            self.assertEqual(len([c for c in calls if c[1] == "POST"]), 3)

    def test_ambiguous_post_not_repeated_until_visibility_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.home(tmp, dry_run=False)
            calls = []
            fallback = mock_api(calls)
            def uncertain(req, timeout):
                if req.get_method()=="POST" and "gaslux-agent-clock.yml/" in req.full_url:
                    raise OSError("response lost after GitHub may have accepted")
                return fallback(req, timeout)
            first = self.tick(home, opener=uncertain)
            self.assertEqual(first["decisions"][0]["status"], "POST_UNCONFIRMED")
            self.assertIn("post:gaslux-agent-clock.yml", pi.get_state(home))
            second_calls = []
            second = self.tick(home, NOW+timedelta(minutes=1), mock_api(second_calls))
            self.assertIn("WAITING_FOR_VISIBILITY",
                          [item["status"] for item in second["decisions"]])
            self.assertFalse(any(method=="POST" for _url,method,_body in second_calls))
            third_calls=[]
            self.tick(home, NOW+timedelta(minutes=3), mock_api(third_calls))
            self.assertEqual(len([x for x in third_calls if x[1]=="POST"]),1)
            self.assertIn("gaslux-agent-clock.yml",
                          [url for url,method,_ in third_calls if method=="POST"][0])

    def test_github_history_over_256_kib_remains_available_with_finite_cap(self):
        # GitHub run metadata can be ~12 KiB per item, >1 MiB for 100 runs.
        # The old 256-KiB response limit eventually stopped scheduled dispatches.
        rows = [run(id=1000 + index, metadata="x" * 11000)
                for index in range(pi.MAX_RUNS)]
        response = json.dumps({"total_count": len(rows),
                               "workflow_runs": rows}).encode("utf-8")
        self.assertGreater(len(response), 256 * 1024)
        self.assertLess(len(response), pi.MAX_API_RESPONSE_BYTES)
        def valid_history(_request, timeout):
            return Response(response)
        history = pi.api_json(valid_history, pi.API +
                              "gaslux-agent-clock.yml/runs?branch=main&per_page=100",
                              token="offline-test-token")
        self.assertEqual(len(pi.parse_runs(history)), 100)
        # Keep a fail-closed finite cap against unexpectedly oversized inputs.
        oversized = b" " * (pi.MAX_API_RESPONSE_BYTES + 1)
        def oversized_history(_request, timeout):
            return Response(oversized)
        with self.assertRaisesRegex(ValueError, "Oversized GitHub response"):
            pi.api_json(oversized_history, pi.API +
                        "gaslux-agent-clock.yml/runs?branch=main&per_page=100",
                        token="offline-test-token")

    def test_authenticated_github_reads_not_anonymous_rate_limited(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=self.home(tmp,dry_run=True)
            calls=[]
            fallback=mock_api(calls)
            def checked(req, timeout):
                self.assertTrue(req.has_header("Authorization"))
                return fallback(req,timeout)
            self.tick(home,opener=checked)
            self.assertEqual(len([x for x in calls if x[1]=="GET"]),4)

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
