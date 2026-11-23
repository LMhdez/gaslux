"""Offline adversarial contracts for Raspberry Pi readonly GitHub Actions timer."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import contextmanager

SCRIPT = Path(__file__).with_name("raspberrypi_scheduler.py")
SPEC = importlib.util.spec_from_file_location("pi_scheduler", SCRIPT)
assert SPEC and SPEC.loader
pi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pi)
NOW = datetime(2026, 11, 23, 7, tzinfo=timezone.utc)
SHA = "a" * 40


def run(minutes=60, **kw):
    return {"id": 101, "head_branch": "main", "head_sha": SHA,
            "event": "schedule", "status": "completed", "conclusion": "success",
            "created_at": (NOW - timedelta(minutes=minutes)).isoformat(),
            **kw}


class FakeResponse(io.BytesIO):
    def __init__(self, content=b"", status=200):
        super().__init__(content)
        self.status = status


def fake_open(runs, calls):
    data = json.dumps({"total_count": len(runs), "workflow_runs": runs}).encode()
    def opener(req, timeout):
        calls.append((req.full_url, req.get_method(), req.data))
        if req.get_method() == "POST":
            return FakeResponse(status=204)
        return FakeResponse(data)
    return opener


@contextmanager
def fake_lock():
    yield


class SchedulerTests(unittest.TestCase):
    def test_paused_without_config_never_calls_github(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(pi, "exclusive_session", fake_lock):
                output = pi.tick(home=Path(td), now=NOW, opener=lambda *a, **k: self.fail("API accessed"))
        self.assertEqual(output["status"], "PAUSED")
        self.assertFalse(output["dispatched"])

    def setup(self, td, enabled=True, dry_run=True):
        home = Path(td)
        cfg = home / ".config" / "gaslux"
        cfg.mkdir(parents=True)
        os.chmod(cfg, 0o700)
        file = cfg / pi.CONFIG_NAME
        file.write_text(json.dumps({"enabled": enabled, "dry_run": dry_run}))
        os.chmod(file, 0o600)
        return home

    def test_recent_run_no_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            home = self.setup(td, dry_run=False)
            calls = []
            with patch.object(pi, "exclusive_session", fake_lock):
                output = pi.tick(home=home, now=NOW,
                                 opener=fake_open([run(minutes=10)], calls))
        self.assertEqual(output["status"], "RECENT")
        self.assertEqual([v[1] for v in calls], ["GET"])

    def test_stale_run_dry_run_no_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            home = self.setup(td)
            calls = []
            with patch.object(pi, "exclusive_session", fake_lock):
                output = pi.tick(home=home, now=NOW,
                                 opener=fake_open([run(minutes=80)], calls))
        self.assertEqual(output["status"], "WOULD_DISPATCH")
        self.assertEqual([v[1] for v in calls], ["GET"])

    def test_stale_success_dispatches_only_readonly_lifecycle(self):
        with tempfile.TemporaryDirectory() as td:
            home = self.setup(td, dry_run=False)
            token = home / ".config" / "gaslux" / pi.TOKEN_NAME
            token.write_text("test-token-not-real-123\n")
            os.chmod(token, 0o600)
            calls = []
            with patch.object(pi, "exclusive_session", fake_lock):
                output = pi.tick(home=home, now=NOW,
                                 opener=fake_open([run(minutes=80)], calls))
        self.assertEqual(output["status"], "DISPATCH_REQUESTED")
        self.assertEqual([v[1] for v in calls], ["GET", "POST"])
        self.assertTrue(calls[-1][0].endswith("/gaslux-agent-lifecycle-research.yml/dispatches"))
        self.assertEqual(json.loads(calls[-1][2]), {
            "ref": "main", "inputs": {"mint_live_boot": "false"}})

    def test_pending_and_failed_runs_halt(self):
        for variant in [dict(status="queued", conclusion=None),
                        dict(status="in_progress", conclusion=None),
                        dict(conclusion="failure"), dict(conclusion="cancelled")]:
            with self.subTest(variant=variant):
                status = pi.decision(run(minutes=80, **variant), NOW)
                self.assertNotEqual(status, "STALE_READONLY")

    def test_duplicate_runs_take_newest_real_heartbeat(self):
        data = {"total_count": 4, "workflow_runs": [
            run(minutes=120), run(minutes=6, id=104, event="workflow_dispatch"),
            run(minutes=3, id=105, event="push"),
            run(minutes=1, id=106, event="pull_request")]}
        newest = pi.latest_run(data)
        self.assertEqual(newest["id"], 104)
        self.assertEqual(pi.decision(newest, NOW), "RECENT")

    def test_invalid_run_identity_denied(self):
        for kw in [dict(head_branch="dev"), dict(head_sha="bogus"),
                   dict(id=0), dict(status="untrusted"), dict(created_at="bad")]:
            with self.subTest(change=kw):
                with self.assertRaises((ValueError, TypeError)):
                    pi.latest_run({"total_count": 1, "workflow_runs": [run(**kw)]})

    def test_no_history_is_not_authorization(self):
        self.assertIsNone(pi.latest_run({"total_count": 0, "workflow_runs": []}))
        self.assertEqual(pi.decision(None, NOW), "NO_ATTESTED_RUN")

    def test_future_time_is_denied(self):
        with self.assertRaises(ValueError):
            pi.decision(run(minutes=-1), NOW)

    def test_directory_link_or_public_mode_denied(self):
        with tempfile.TemporaryDirectory() as td:
            home = self.setup(td)
            cfg = home / ".config" / "gaslux"
            os.chmod(cfg, 0o777)
            with self.assertRaises(ValueError):
                pi.configuration(home)
            os.chmod(cfg, 0o700)
            real = home / ".config" / "secure-dir"
            cfg.rename(real)
            cfg.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                pi.secure_file(cfg / pi.CONFIG_NAME)

    def test_secret_hardlink_and_symlink_denied(self):
        with tempfile.TemporaryDirectory() as td:
            home = self.setup(td)
            file = home / ".config" / "gaslux" / pi.CONFIG_NAME
            alias = home / "alias"
            os.link(file, alias)
            with self.assertRaises(ValueError):
                pi.configuration(home)
            alias.unlink()
            file.unlink()
            file.symlink_to(home / "nothing")
            with self.assertRaises(OSError):
                pi.configuration(home)

    def test_untrusted_config_fields_denied(self):
        with tempfile.TemporaryDirectory() as td:
            home = self.setup(td)
            target = home / ".config" / "gaslux" / pi.CONFIG_NAME
            target.write_text(json.dumps({
                "enabled": True, "dry_run": False, "workflow": "dangerous"}))
            with self.assertRaises(ValueError):
                pi.configuration(home)

    def test_job_with_invalid_GitHub_response_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            home = self.setup(td)
            class BadResponse(FakeResponse):
                pass
            with patch.object(pi, "exclusive_session", fake_lock):
                with self.assertRaises(ValueError):
                    pi.tick(home=home, now=NOW, opener=lambda *a, **k: BadResponse(
                        json.dumps({"total_count": 100,
                                    "workflow_runs": [run()] * 31}).encode()))

    def test_service_timer_no_write_or_guest_rights(self):
        unit = Path(__file__).with_name("gaslux-fallback.service").read_text()
        timer = Path(__file__).with_name("gaslux-fallback.timer").read_text()
        self.assertIn("Type=oneshot", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("Persistent=true", timer)
        self.assertIn("OnCalendar=", timer)
        for prohibited in ("sudo ", "ExecStartPre=/bin/bash", "mint_live_boot=true"):
            self.assertNotIn(prohibited, unit + timer)


if __name__ == "__main__":
    unittest.main()
