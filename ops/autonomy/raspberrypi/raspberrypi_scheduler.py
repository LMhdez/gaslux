#!/usr/bin/env python3
"""Raspberry Pi trigger for ALL FOUR existing Gaslux scheduled GitHub workflows.

The Pi dispatches the same main-branch workflows with the same scheduled inputs.
It does not execute model output or replace GitHub-side Safety and branch gates.
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timezone, timedelta
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.request

API = "https://api.github.com/repos/LMhdez/gaslux/actions/workflows/"
HEAD_SHA = re.compile(r"^[a-f0-9]{40}$")
CONFIG_NAME = "raspberrypi-scheduler.json"
TOKEN_NAME = "github-actions-token"
STATE_NAME = "last-dispatched-slots.json"
MAX_RUNS = 100
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}
RUN_EVENTS = {"schedule", "workflow_dispatch"}

# Exact matching of the four scheduled GitHub Actions workflows in PR #389.
# Inputs match their scheduled semantics, including the daily official Mint guest.
TASKS = (
    ("gaslux-agent-clock.yml", "clock", (3, 18, 33, 48), None, {"role": "auto"}),
    ("gaslux-agent-feature-factory.yml", "factory", (6, 21, 36, 51), None, {}),
    ("gaslux-agent-integrator.yml", "integrator", (10, 25, 40, 55), None, {}),
    ("gaslux-agent-lifecycle-research.yml", "lifecycle", (16, 46), None,
     {"mint_live_boot": "false"}),
    ("gaslux-agent-lifecycle-research.yml", "mint_daily", (31,), 3,
     {"mint_live_boot": "true"}),
)

# GitHub Actions evaluates the trusted run-name expression on main.
# display_title is returned by the existing REST workflow runs endpoint.
# Never claim that an unrelated manual/regular run delivered a different slot.
TASK_TITLES = {
    "clock": "GASLUX-CLOCK/auto",
    "factory": "GASLUX-FACTORY/default",
    "integrator": "GASLUX-INTEGRATOR/default",
    "lifecycle": "GASLUX-LIFECYCLE/research",
    "mint_daily": "GASLUX-LIFECYCLE/mint-daily",
}


def secure_file(path: Path, *, required: bool = True) -> str | None:
    """Open only a regular, single-link, private file in our owned config dir."""
    parent = path.parent
    parent_stat = parent.lstat() if parent.exists() else None
    if (parent_stat is None or not stat.S_ISDIR(parent_stat.st_mode) or
            parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o022):
        raise ValueError("Config directory must be owned and not group/world writable")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        if not required:
            return None
        raise
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        info = os.fstat(f.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 8192):
            raise ValueError("Secret/config must be private 0600, regular and unaliased")
        return f.read(8193)


def configuration(home: Path) -> dict:
    name = home / ".config" / "gaslux" / CONFIG_NAME
    if not name.parent.exists():
        return {"enabled": False, "dry_run": True}
    raw = secure_file(name, required=False)
    if raw is None:
        return {"enabled": False, "dry_run": True}
    conf = json.loads(raw)
    if (not isinstance(conf, dict) or set(conf) != {"enabled", "dry_run"} or
            type(conf["enabled"]) is not bool or type(conf["dry_run"]) is not bool):
        raise ValueError("Invalid configuration: only enabled/dry_run booleans")
    return conf


@contextlib.contextmanager
def exclusive_session() -> object:
    """Single local watchdog run; GitHub and the Pi may still race read-only."""
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    path = Path(runtime) if runtime.startswith("/") else None
    if path is None or path.is_symlink():
        raise ValueError("No private systemd runtime directory")
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise ValueError("Unsafe systemd runtime directory")
    fd = os.open(path / "gaslux-schedule-trigger.lock",
                 os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError("Unsafe lock inode")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another watchdog execution is running")
        yield
    finally:
        os.close(fd)


def parse_time(raw: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError("Missing run timestamp")
    instant = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        raise ValueError("Naive run timestamp")
    return instant.astimezone(timezone.utc)


def last_due(now: datetime, minutes: tuple[int, ...], hour: int | None) -> datetime:
    """Most recent schedule slot in UTC; a Pi reboot catches up once per task."""
    if now.tzinfo is None:
        raise ValueError("UTC clock required")
    moment = now.astimezone(timezone.utc).replace(second=0, microsecond=0)
    for delta in range(24 * 60 + 1):
        slot = moment - timedelta(minutes=delta)
        if slot.minute in minutes and (hour is None or slot.hour == hour):
            return slot
    raise ValueError("No due schedule slot")


def get_state(home: Path) -> dict[str, str]:
    raw = secure_file(home / ".config" / "gaslux" / STATE_NAME, required=False)
    if raw is None:
        return {}
    document = json.loads(raw)
    valid_keys = {entry[1] for entry in TASKS} | {"post:" + entry[0] for entry in TASKS}
    if (not isinstance(document, dict) or set(document) - valid_keys or
            any(not isinstance(value, str) or len(value) > 40 or
                parse_time(value).isoformat() != value
                for value in document.values())):
        raise ValueError("Invalid durable scheduler state")
    return document


def set_state(home: Path, state: dict[str, str]) -> None:
    """Atomic 0600 state replacement within private config directory."""
    path = home / ".config" / "gaslux"
    payload = json.dumps(state, sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > 8192:
        raise ValueError("Oversized state")
    parent_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    tmp_name = "state-" + os.urandom(8).hex() + ".tmp"
    try:
        metadata = os.fstat(parent_fd)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o022):
            raise ValueError("Unsafe state directory")
        fd = os.open(tmp_name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(tmp_name, STATE_NAME, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(parent_fd)


def parse_runs(data: dict) -> list[dict]:
    if (not isinstance(data, dict) or not isinstance(data.get("workflow_runs"), list)
            or type(data.get("total_count")) is not int or
            len(data["workflow_runs"]) > MAX_RUNS):
        raise ValueError("Malformed GitHub workflow runs")
    runs = []
    for run in data["workflow_runs"]:
        if not isinstance(run, dict):
            raise ValueError("Malformed GitHub run")
        if (type(run.get("id")) is not int or run["id"] < 1 or
                run.get("head_branch") != "main" or
                not HEAD_SHA.fullmatch(str(run.get("head_sha", ""))) or
                run.get("status") not in ACTIVE | {"completed"} or
                not isinstance(run.get("event"), str)):
            raise ValueError("Unexpected GitHub run identity or state")
        parse_time(run.get("created_at"))
        runs.append(run)
    return runs


def decision(runs: list[dict], slot: datetime, *, task: str, daily: bool = False) -> str:
    """Suppress only truly equivalent completed slots or a workflow in progress.

    GitHub lists event/time but does NOT expose a schedule cron or dispatched
    inputs directly in the workflow-runs response. The trusted, main-branch
    run-name labels those semantics; display_title is the observable proof.
    """
    expected_title = TASK_TITLES[task]
    if any(row["status"] in ACTIVE for row in runs):
        return "ALREADY_RUNNING"
    for run in runs:
        if run["event"] not in RUN_EVENTS or run.get("display_title") != expected_title:
            continue
        when = parse_time(run["created_at"])
        delta = (when - slot).total_seconds()
        if 0 <= delta < (180 if daily else 60 * 15):
            return "ALREADY_TRIGGERED"
    return "DISPATCH"

def api_json(opener, url: str, *, token: str | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "gaslux-raspberrypi-readonly-watchdog",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with opener(urllib.request.Request(url, headers=headers), timeout=12) as response:
        if response.status != 200:
            raise ValueError("GitHub Actions listing HTTP status is not 200")
        raw = response.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError("Oversized GitHub response")
    return json.loads(raw)


def dispatch(opener, token: str, workflow: str, inputs: dict) -> None:
    body = json.dumps({"ref": "main", "inputs": inputs}).encode("utf-8")
    request = urllib.request.Request(
        API + workflow + "/dispatches", method="POST",
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": "Bearer " + token,
                 "User-Agent": "gaslux-raspberrypi-schedule-trigger",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"},
        data=body)
    with opener(request, timeout=12) as response:
        if response.status not in (204, 200):
            raise ValueError("GitHub dispatch failed")


def tick(*, home: Path, now: datetime, opener=urllib.request.urlopen) -> dict:
    """At-least-once attempt for due slots, no duplicates for active workflows."""
    conf = configuration(home)
    if not conf["enabled"]:
        return {"status": "PAUSED", "decisions": []}
    with exclusive_session():
        state = get_state(home)
        outcomes = []
        # Authenticate EVERY read to avoid unauthenticated GitHub REST's
        # 60-request/hour limit. Four workflows queried each minute would
        # exhaust that quota after about 15 minutes.
        token = secure_file(home / ".config" / "gaslux" / TOKEN_NAME,
                            required=not conf["dry_run"])
        if token is not None:
            token = token.strip()
            if len(token) < 8:
                raise ValueError("Invalid GitHub Actions token")
        for workflow in dict.fromkeys(task[0] for task in TASKS):
            tasks = [task for task in TASKS if task[0] == workflow]
            due = [(last_due(now, task[2], task[3]), task) for task in tasks]
            # Preserve a missed daily Mint run, but never submit two runs of
            # the same workflow concurrently in one watchdog invocation.
            due.sort(key=lambda item: (item[1][1] != "mint_daily", item[0]))
            due = [(slot, task) for slot, task in due
                   if state.get(task[1]) != slot.isoformat()]
            if not due:
                continue
            try:
                data = api_json(opener, API + workflow +
                                "/runs?branch=main&per_page=100", token=token)
                runs = parse_runs(data)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                # One unavailable workflow must not starve other scheduled agents.
                # Never print a token, HTTP response body, or URL query.
                outcomes.append({"task": workflow, "status": "API_RETRY_NEXT_TICK",
                                 "error_type": type(exc).__name__})
                continue
            # A successful POST may take time to appear in GitHub run listings.
            # Suppress further POSTs to this workflow briefly after our own
            # confirmed dispatch, even when the API response is still stale.
            previous_post = state.get("post:" + workflow)
            if previous_post is not None:
                elapsed = (now - parse_time(previous_post)).total_seconds()
                if elapsed < 0:
                    raise ValueError("Future local dispatch ledger timestamp")
                if elapsed < 120:
                    outcomes.append({"task": workflow, "status": "WAITING_FOR_VISIBILITY"})
                    continue
            # If an earlier/later slot is already covered by the native
            # GitHub scheduler we record that slot without a POST.
            for slot, task in due:
                key = task[1]
                # A verified daily Mint run can cover the regular Lifecycle
                # slot earlier in this SAME tick; do not re-dispatch it.
                if state.get(key) == slot.isoformat():
                    continue
                verdict = decision(runs, slot, task=key, daily=(key == "mint_daily"))
                if verdict == "ALREADY_TRIGGERED":
                    state[key] = slot.isoformat()
                    # A semantically proven Mint guest dispatch includes all
                    # ordinary Lifecycle research. Avoid firing it again.
                    if key == "mint_daily":
                        for regular_slot, regular_task in due:
                            if regular_task[1] == "lifecycle":
                                state["lifecycle"] = regular_slot.isoformat()
                    set_state(home, state)
                    outcomes.append({"task": key, "status": verdict})
                    continue
                if verdict == "ALREADY_RUNNING":
                    outcomes.append({"task": key, "status": verdict})
                    break
                if conf["dry_run"]:
                    outcomes.append({"task": key, "status": "WOULD_DISPATCH"})
                    break
                if token is None:
                    raise ValueError("GitHub Actions dispatch credential required")
                try:
                    dispatch(opener, token, workflow, task[4])
                except (OSError, ValueError) as exc:
                    # GitHub might have accepted POST before a timeout. Record
                    # an uncertainty window instead of instantly retrying.
                    state["post:" + workflow] = now.astimezone(timezone.utc).isoformat()
                    set_state(home, state)
                    outcomes.append({"task": key, "status": "POST_UNCONFIRMED",
                                     "error_type": type(exc).__name__})
                    break
                state[key] = slot.isoformat()
                # One workflow run already executes all its regular jobs:
                # a daily Mint run also covers any older lifecycle research.
                for earlier_slot, earlier_task in due:
                    if earlier_task[1] != key and (key == "mint_daily" or earlier_slot <= slot):
                        state[earlier_task[1]] = earlier_slot.isoformat()
                state["post:" + workflow] = now.astimezone(timezone.utc).isoformat()
                set_state(home, state)
                outcomes.append({"task": key, "status": "DISPATCH_REQUESTED"})
                break
        return {"status": "OK", "decisions": outcomes}


def main() -> int:
    try:
        result = tick(home=Path.home(), now=datetime.now(timezone.utc))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        # No token, raw response body or exception details in journal.
        print(json.dumps({"status": "BLOCKED_FAIL_CLOSED",
                          "error_type": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
