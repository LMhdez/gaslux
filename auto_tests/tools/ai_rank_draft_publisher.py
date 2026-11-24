#!/usr/bin/env python3
"""Privileged but narrowly allowlisted Draft PR publisher (not a code executor).

This file MUST only be run from the trusted 'dev' push workflow publisher job.
The unprivileged Ollama job provides evidence + candidate artifact; no token
is supplied to inference.  This job does NOT run model-generated Python.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request


REPO = "LMhdez/gaslux"
BASE = "dev"
TARGET = "auto_tests/tools/rank_capture_changes.py"
API_ROOT = f"https://api.github.com/repos/{REPO}"
REPORT = Path("evidence/ai-rank-repair.json")
CANDIDATE = Path("evidence/ai-rank-candidate.py")
COMMITTED = re.compile(r"^[0-9a-f]{40}$")
FAULT = "return sorted(changes, reverse=False, key=lambda item: item[0])"
FIXED = "return sorted(changes, reverse=True, key=lambda item: item[0])"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_patch(before: bytes, after: bytes) -> None:
    """Allow ONLY the known noncritical ranking reversal in one return line."""
    old = before.decode("utf-8", errors="strict")
    new = after.decode("utf-8", errors="strict")
    if len(new) > 12000 or old == new or len(old.splitlines()) != len(new.splitlines()):
        raise ValueError("One short same-line-count Python change required")
    if old.count(FAULT) != 1 or new.count(FIXED) != 1:
        raise ValueError("Unexpected source/target regression")
    if new != old.replace(FAULT, FIXED, 1):
        raise ValueError("Candidate differs from single allowed correction")
    old_tree, new_tree = ast.parse(old), ast.parse(new)
    functions = [x for x in old_tree.body if isinstance(x, ast.FunctionDef)
                 and x.name == "ranked_changes"]
    if len(functions) != 1:
        raise ValueError("Ambiguous ranked_changes function")
    returns = [x for x in ast.walk(functions[0]) if isinstance(x, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
        raise ValueError("Ranking return is ambiguous or not a call")
    statement = old.splitlines()[returns[0].lineno - 1].strip()
    if statement != FAULT:
        raise ValueError("Changed line is not exact ranking return")
    if not any(isinstance(x, ast.FunctionDef) and x.name == "ranked_changes"
               for x in new_tree.body):
        raise ValueError("Ranking function removed")


def validate_evidence(report: dict, candidate: bytes, git_sha: str) -> None:
    if not COMMITTED.fullmatch(git_sha):
        raise ValueError("Invalid initiating dev SHA")
    if set(report.keys()) < {
        "model", "target", "source_sha256", "simulated", "passed",
        "status", "baseline_red", "candidate_sha256", "attempts"
    }:
        raise ValueError("Missing mandatory worker evidence")
    attempts = report["attempts"]
    if not (
        report["model"] == "qwen3.5:9b"
        and report["target"] == TARGET
        and report["simulated"] is False
        and report["passed"] is True
        and report["baseline_red"] is True
        and report["status"] == "candidate_green"
        and isinstance(attempts, list)
        and 1 <= len(attempts) <= 2
        and attempts[-1].get("passed") is True
    ):
        raise ValueError("No valid genuine failing-baseline/repair evidence")
    if not isinstance(report["source_sha256"], str) or not re.fullmatch(
        r"^[0-9a-f]{64}$", report["source_sha256"]
    ):
        raise ValueError("Invalid original source SHA-256")
    if not re.fullmatch(r"^[0-9a-f]{64}$", report.get("candidate_sha256", "")):
        raise ValueError("Bad candidate SHA-256")
    if sha256(candidate) != report["candidate_sha256"]:
        raise ValueError("Candidate artifact hash mismatch")


def request_json(
    method: str, route: str, payload: dict | None = None, *, allow_missing: bool = False
) -> dict | None:
    if not route.startswith("/") or "://" in route:
        raise ValueError("Only repository-scoped REST routes allowed")
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        API_ROOT + route,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if payload is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
            if not raw:
                return {}  # GitHub DELETE returns HTTP 204 with no JSON body.
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("GitHub REST returned a non-object")
            return value
    except urllib.error.HTTPError as exc:
        if allow_missing and exc.code == 404:
            return None
        raise RuntimeError(f"GitHub {method} {route} returned HTTP {exc.code}") from exc


def main() -> None:
    if os.environ.get("GITHUB_EVENT_NAME") != "push" or (
        os.environ.get("GITHUB_REF") != "refs/heads/dev"
    ) or os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise RuntimeError("Publisher may only run on trusted dev pushes")
    sha = os.environ["GITHUB_SHA"]
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    candidate = CANDIDATE.read_bytes()
    validate_evidence(report, candidate, sha)

    # Re-fetch base ref before content and again before any write. A stale
    # worker result must not be published against a newly advanced dev.
    ref = request_json("GET", f"/git/ref/heads/{BASE}")
    if ref["object"]["sha"] != sha:
        raise RuntimeError("dev advanced since worker start: fail closed")
    encoded = request_json("GET", f"/contents/{TARGET}?ref={sha}")
    base_content = base64.b64decode("".join(encoded["content"].split()), validate=True)
    if sha256(base_content) != report["source_sha256"]:
        raise RuntimeError("Worker source digest does not match exact dev base")
    validate_patch(base_content, candidate)
    latest = request_json("GET", f"/git/ref/heads/{BASE}")
    if latest["object"]["sha"] != sha:
        raise RuntimeError("dev moved during publisher validation")
    branch = f"bot/ai-rank-repair-{sha[:12]}"
    if request_json("GET", f"/git/ref/heads/{branch}", allow_missing=True):
        print("Proposal branch already exists: idempotent no-op")
        return

    request_json("POST", "/git/refs", {
        "ref": f"refs/heads/{branch}", "sha": sha,
    })
    update = request_json("PUT", f"/contents/{TARGET}", {
        "message": "fix(observer): propose locally generated ranking correction",
        "content": base64.b64encode(candidate).decode("ascii"),
        "sha": encoded["sha"],
        "branch": branch,
    })
    created_commit = update.get("commit", {}).get("sha")
    if not created_commit or not COMMITTED.fullmatch(created_commit):
        raise RuntimeError("GitHub did not return the candidate commit identity")
    try:
        pr = request_json("POST", "/pulls", {
        "head": branch,
        "base": BASE,
        "draft": True,
        "title": "fix(observer): proposed bounded AI ranking repair",
        "body": (
            "Generated by Qwen3.5 9B on a GitHub-hosted CPU runner, no API credits. "
            "The unprivileged worker observed RED before the patch and GREEN after. "
            "The trusted separate publisher independently revalidated the exact "
            "source SHA-256 and one permitted ranking return-line correction. "
            "DRAFT ONLY. Exact-head CI and independent Safety review required; "
            "no automatic merge, installer/disk/boot authority or release promotion."
        ),
        })
    except Exception:
        # If GitHub disallows Actions-created PRs, do not leave an orphan
        # branch that would permanently block the next attempt. Delete only
        # when the ref still points to the exact commit created by this job.
        try:
            current = request_json("GET", f"/git/ref/heads/{branch}")
            if current["object"]["sha"] == created_commit:
                request_json("DELETE", f"/git/refs/heads/{branch}")
                print("Orphan proposal branch cleaned up after PR API failure")
            else:
                print("Proposal branch moved; manual inspection required")
        except Exception as cleanup_error:
            print("Could not safely clean proposal branch:", type(cleanup_error).__name__)
        raise
    print("Created Draft PR:", pr["html_url"])


if __name__ == "__main__":
    main()
