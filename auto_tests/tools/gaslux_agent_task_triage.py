#!/usr/bin/env python3
"""Trusted, main-only task-queue admission for genuine six-distro gate gaps.

This publishes *review requests*, never model code, installer authority, or
an evidence pass. The caller's job must have issues:write but no App private key.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

from gaslux_agent_feature_factory import (
    REPO, SHA, TASKS, discover_goal_backlog,
)

API = "https://api.github.com/repos/" + REPO
BOT_BRANCH = re.compile(
    r"bot/gaslux-feature-(mint|zorin|cachyos|popos|q4os|bazzite)-[0-9a-f]{12}\Z"
)
KEY = re.compile(
    r"<!-- GASLUX-AUTOTASK:(mint|zorin|cachyos|popos|q4os|bazzite):"
    r"(windows10-bios-mbr|windows10-uefi-gpt|windows11-uefi-gpt):"
    r"(source-authenticity|windows-preflight|install|linux-first-boot|"
    r"windows-return|linux-update-reboot|uninstall-windows-integrity|"
    r"fault-injection-rollback) -->"
)


def api(method: str, route: str, payload: dict | None = None):
    """No arbitrary endpoint or token ever originates from dev JSON."""
    if not (method == "GET" and route in (
        "/git/ref/heads/dev", "/pulls?state=open&per_page=100"
    ) or method == "GET" and re.fullmatch(
        r"/issues\?state=all&per_page=100&page=(?:[1-9]|1[0-9]|20)", route
    ) or method == "POST" and route == "/issues"):
        raise ValueError("Unapproved task-triage API operation")
    if method == "POST" and (
        type(payload) is not dict or set(payload) != {"title", "body"} or
        type(payload["title"]) is not str or len(payload["title"]) > 160 or
        type(payload["body"]) is not str or len(payload["body"]) > 6000
    ):
        raise ValueError("Invalid bounded task issue")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise RuntimeError("Missing read/write identity")
    req = urllib.request.Request(
        API + route, method=method,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if payload else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub task-triage API HTTP {exc.code}") from exc


def all_issues() -> list[dict]:
    """Read the full bounded history; never rely on eventually indexed search."""
    found = []
    for page in range(1, 21):
        batch = api("GET", f"/issues?state=all&per_page=100&page={page}")
        if type(batch) is not list or any(type(x) is not dict for x in batch):
            raise ValueError("Unexpected issue history")
        found.extend(x for x in batch if "pull_request" not in x)
        if len(batch) < 100:
            return found
    raise RuntimeError("Issue history exceeds bounded dedup scope")


def choose(backlog: dict, prs: list[dict], issues: list[dict]) -> dict:
    """Select a single reviewable missing gate, not an executable code patch."""
    if backlog.get("status") != "blocked" or type(backlog.get("next_gates")) is not list:
        raise ValueError("Unreviewed task-discovery status")
    if type(prs) is not list or len(prs) > 100:
        raise ValueError("Unbounded PR history")
    open_roles = set()
    for pr in prs:
        if type(pr) is not dict:
            raise ValueError("Malformed PR")
        head, base = pr.get("head"), pr.get("base")
        if type(head) is not dict or type(base) is not dict:
            raise ValueError("Malformed PR refs")
        name = head.get("ref", "")
        match = BOT_BRANCH.fullmatch(name) if type(name) is str else None
        if match and base.get("ref") == "dev":
            open_roles.add(match.group(1))
    tracked = set()
    for issue in issues:
        if type(issue) is not dict:
            raise ValueError("Malformed issue")
        body = issue.get("body") or ""
        if type(body) is not str:
            raise ValueError("Malformed issue body")
        tracked.update(KEY.findall(body))
    pending = []
    for task in backlog["next_gates"]:
        if (type(task) is not dict or task.get("role") not in TASKS or
            task.get("code_authorized") is not False or
            task.get("release_eligible") is not False or
            task.get("state") not in ("missing_evidence", "declared_unverified") or
            task.get("gate") != "source-authenticity"):
            raise ValueError("Task authority or gate mismatch")
        role = task["role"]
        key = (role, task["platform"], task["gate"])
        if role in open_roles:
            pending.append({"role": role, "status": "pending_existing_pr"})
            continue
        # Existing manually tracked backend issues take precedence.
        if task["related_issues"]:
            pending.append({"role": role, "status": "linked_existing_issue",
                            "issues": task["related_issues"]})
            continue
        if key in tracked:
            pending.append({"role": role, "status": "already_queued"})
            continue
        return {"status": "ready_for_scope_review", "role": role,
                "platform": task["platform"], "gate": task["gate"],
                "key": key, "pending": pending}
    return {"status": "waiting_for_review", "pending": pending}


def issue_payload(task: dict, base: str) -> dict:
    role = task["role"]
    source, test, _ = TASKS[role]
    marker = f"<!-- GASLUX-AUTOTASK:{role}:{task['platform']}:{task['gate']} -->"
    return {
        "title": f"[GASLUX-AUTO] {role} / {task['platform']} / {task['gate']}: scope & acceptance",
        "body": (
            f"{marker}\n"
            "**Autonomously identified goal gap — scope review required.**\n\n"
            f"- Backend: `{role}`; Windows platform: `{task['platform']}`; "
            f"missing gate: `{task['gate']}`\n"
            f"- Source snapshot (dev): `{base}`\n"
            f"- Candidate source for owner review: `{source}`\n"
            f"- Existing regression suite: `auto_tests/tests/{test}`\n"
            "- Next step: backend owner defines a **real** missing capability, precise "
            "code paths and positive/negative tests. Reconcile existing PRs first.\n"
            "- Required evidence: authentic release/media provenance, Windows preflight "
            "and reproducible read-only contracts; do not confuse declared JSON with "
            "independent proof.\n"
            "- Safety status: **NEEDS_SCOPE_REVIEW**. Qwen has **no** code authorization "
            "from this issue, even for a gate labelled automatic_safe.\n"
            "- Installation, disk/ESP/BCD/WinRE changes, VM writes, boot, uninstall "
            "and release remain prohibited until their separate approvals and evidence.\n"
            "- Dedup identity is backend/platform/gate; no duplicate issue on source "
            "revision. No force-push or auto-merge.\n\n"
            "Parent: #401. Product objective: AGENTS.md and "
            "dev:docs/autonomy/goal.json.\n"
        ),
    }


def sync(root: Path, *, dry_run: bool = False) -> dict:
    if (os.getenv("GITHUB_REPOSITORY") != REPO or
        os.getenv("GITHUB_REF") != "refs/heads/main" or
        os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true" or
        os.getenv("GITHUB_EVENT_NAME") not in ("push", "schedule", "workflow_dispatch")):
        raise RuntimeError("Trusted unpaused main event required")
    base = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True, timeout=12
    ).strip()
    if not SHA.fullmatch(base):
        raise ValueError("Untrusted dev checkout SHA")
    current = api("GET", "/git/ref/heads/dev")
    if current.get("object", {}).get("sha") != base:
        raise RuntimeError("Dev moved; refuse stale task issue")
    backlog = discover_goal_backlog(root)
    prs = api("GET", "/pulls?state=open&per_page=100")
    issues = all_issues()
    picked = choose(backlog, prs, issues)
    if picked["status"] != "ready_for_scope_review":
        return {"base": base, **picked}
    payload = issue_payload(picked, base)
    if dry_run:
        return {"base": base, "status": "dry_run", "title": payload["title"]}
    if api("GET", "/git/ref/heads/dev").get("object", {}).get("sha") != base:
        raise RuntimeError("Dev changed during triage")
    # Re-read issue history immediately before create. A concurrent runner
    # must never create a second issue with the same stable marker.
    if picked["key"] in {
        key for issue in all_issues()
        for key in KEY.findall(issue.get("body") or "")
    }:
        return {"status": "already_queued", "base": base, "role": picked["role"]}
    created = api("POST", "/issues", payload)
    if (type(created) is not dict or type(created.get("number")) is not int or
        created["number"] <= 0):
        raise RuntimeError("GitHub did not confirm task issue")
    return {"status": "review_issue_created", "base": base, "role": picked["role"],
            "issue": created["number"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(json.dumps(sync(args.repo.resolve(strict=True), dry_run=args.dry_run),
                     sort_keys=True))


if __name__ == "__main__":
    main()
