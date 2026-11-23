#!/usr/bin/env python3
"""Fail-closed Raspberry Pi watchdog for the EXISTING Gaslux read-only Lifecycle.

Never invokes a shell, writes repository code, starts installers or authenticates a guest.
Not a substitute for independent Safety approval.
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.request

API = "https://api.github.com/repos/LMhdez/gaslux/actions/workflows/"
WORKFLOW = "gaslux-agent-lifecycle-research.yml"
LIST_URL = API + WORKFLOW + "/runs?branch=main&per_page=30"
DISPATCH_URL = API + WORKFLOW + "/dispatches"
HEAD_SHA = re.compile(r"^[a-f0-9]{40}$")
EVENTS = {"schedule", "workflow_dispatch"}
CONFIG_NAME = "raspberrypi-scheduler.json"
TOKEN_NAME = "github-actions-token"
MAX_STALE_SECONDS = 45 * 60
MAX_RUNS = 30


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
    fd = os.open(path / "gaslux-readonly-fallback.lock",
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


def latest_run(data: dict) -> dict | None:
    if (not isinstance(data, dict) or not isinstance(data.get("workflow_runs"), list)
            or type(data.get("total_count")) is not int or
            len(data["workflow_runs"]) > MAX_RUNS):
        raise ValueError("Malformed GitHub Actions run list")
    candidates = []
    for run in data["workflow_runs"]:
        if not isinstance(run, dict):
            raise ValueError("Malformed run")
        if run.get("event") not in EVENTS:
            continue  # PR and push contract tests do not count as the cron heartbeat
        if (type(run.get("id")) is not int or run["id"] <= 0 or
                run.get("head_branch") != "main" or
                not HEAD_SHA.fullmatch(str(run.get("head_sha", ""))) or
                run.get("status") not in {"completed", "in_progress", "queued",
                                          "waiting", "pending", "requested"}):
            raise ValueError("Untrusted run identity/status")
        run_date = parse_time(run.get("created_at"))
        candidates.append((run_date, run["id"], run))
    return max(candidates, key=lambda r: (r[0], r[1]))[2] if candidates else None


def decision(run: dict | None, now: datetime) -> str:
    """Safety verdict is never inferred from the aggregate workflow conclusion."""
    if run is None:
        return "NO_ATTESTED_RUN"
    age = (now - parse_time(run["created_at"])).total_seconds()
    if age < 0:
        raise ValueError("Future timestamp")
    if run["status"] != "completed":
        return "RUN_IN_PROGRESS"
    if age < MAX_STALE_SECONDS:
        return "RECENT"
    if run.get("conclusion") != "success":
        return "FAILED_HALT"  # no automatic repeat of rejected unsafe generation
    return "STALE_READONLY"


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


def dispatch(opener, token: str) -> None:
    req = urllib.request.Request(
        DISPATCH_URL, method="POST",
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": "Bearer " + token,
                 "User-Agent": "gaslux-raspberrypi-readonly-watchdog",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"},
        data=b'{"ref":"main","inputs":{"mint_live_boot":"false"}}')
    with opener(req, timeout=12) as response:
        if response.status not in (204, 200):
            raise ValueError("GitHub workflow_dispatch rejected")


def tick(*, home: Path, now: datetime, opener=urllib.request.urlopen) -> dict:
    conf = configuration(home)
    if not conf["enabled"]:
        return {"status": "PAUSED", "dispatched": False}
    with exclusive_session():
        payload = api_json(opener, LIST_URL)
        run = latest_run(payload)
        status = decision(run, now)
        if status != "STALE_READONLY":
            return {"status": status, "last_run_id": run["id"] if run else None,
                    "dispatched": False}
        if conf["dry_run"]:
            return {"status": "WOULD_DISPATCH", "last_run_id": run["id"],
                    "dispatched": False}
        token = secure_file(home / ".config" / "gaslux" / TOKEN_NAME)
        if not token or not token.strip() or len(token.strip()) < 8:
            raise ValueError("GitHub Actions token missing")
        dispatch(opener, token.strip())
        return {"status": "DISPATCH_REQUESTED", "last_run_id": run["id"],
                "dispatched": True}


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
