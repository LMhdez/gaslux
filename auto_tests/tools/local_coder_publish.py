#!/usr/bin/env python3
"""Strict GitHub draft-PR publisher for ONE reviewed-by-tests logging task.

Runs in a separate GitHub Actions job from the unprivileged repair worker.
It never executes candidate code. This proof of concept publishes ONLY the
exact reviewed deterministic missing-close fix after live identity checks.
The resulting PR stays Draft pending CI and independent safety review.
"""
from __future__ import annotations

import ast
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request


REPO = "LMhdez/gaslux"
TARGET = "auto_tests/app/logging_config.py"
BRANCH = "bot/local-coder-logging-fix"
BASE = "dev"
API = f"https://api.github.com/repos/{REPO}"


def request(method: str, url: str, payload: dict | None = None, allow_404: bool = False):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header("Authorization", "Bearer " + os.environ["GH_TOKEN"])
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if allow_404 and exc.code == 404:
            return None
        raise RuntimeError(f"GitHub API HTTP {exc.code} for {method} {url}") from exc


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def imports(source: str) -> list[str]:
    return [
        ast.unparse(n) for n in ast.parse(source).body
        if isinstance(n, (ast.Import, ast.ImportFrom))
    ]


def validate(old: str, new: str) -> None:
    if len(new) > 5000 or old == new or imports(old) != imports(new):
        raise ValueError("Candidate differs beyond allowed safe module scope")
    old_tree = ast.parse(old)
    new_tree = ast.parse(new)
    if [type(n) for n in old_tree.body] != [type(n) for n in new_tree.body]:
        raise ValueError("Top-level structure changed")
    changed = sum(
        line.startswith("+ ") or line.startswith("- ")
        for line in difflib.ndiff(old.splitlines(), new.splitlines())
    )
    if changed > 18:
        raise ValueError("Too many modified lines")
    if any(term in new and term not in old for term in
           ("eval(", "exec(", "__import__", "subprocess", "os.system", "shutil")):
        raise ValueError("New dangerous operation")
    if "configure_logging" not in new:
        raise ValueError("Missing API entrypoint")


def main() -> None:
    report = json.loads(Path("evidence/logging-repair.json").read_text())
    if not (report.get("passed") is True
            and report.get("baseline_red") is True
            and report.get("simulated") is False
            and report.get("status") == "proposable"
            and report.get("path") == TARGET
            and report.get("attempts") == []
            and report.get("repair_strategy") == "deterministic_missing_close"):
        raise ValueError("Unverified or out-of-scope agent evidence")
    candidate = Path("evidence/candidate-logging_config.py").read_bytes()
    if sha256(candidate) != report.get("candidate_sha256"):
        raise ValueError("Candidate artifact digest mismatch")
    encoded_branch = urllib.parse.quote(BRANCH, safe="/")
    if request("GET", f"{API}/git/ref/heads/{encoded_branch}", allow_404=True):
        print("Existing agent branch: duplicate attempt blocked")
        return
    original = request(
        "GET", f"{API}/contents/{TARGET}?ref={BASE}"
    )
    original_bytes = base64.b64decode(original["content"])
    if sha256(original_bytes) != report.get("original_sha256"):
        raise ValueError("dev file changed after generation: stale candidate rejected")
    old = original_bytes.decode("utf-8")
    anchor = "        root.removeHandler(handler)\n"
    if old.count(anchor) != 1 or "handler.close()" in old:
        raise ValueError("Unsupported source layout; no deterministic proposal")
    expected = old.replace(anchor, anchor + "        handler.close()\n", 1)
    if candidate.decode("utf-8") != expected:
        raise ValueError("Candidate is not the single permitted insertion")
    validate(old, expected)
    base_ref = request("GET", f"{API}/git/ref/heads/{BASE}")
    base_sha = base_ref["object"]["sha"]
    request("POST", f"{API}/git/refs", {"ref": f"refs/heads/{BRANCH}", "sha": base_sha})
    request("PUT", f"{API}/contents/{TARGET}", {
        "message": "fix(logging): tested deterministic missing-close recovery",
        "content": base64.b64encode(candidate).decode(),
        "sha": original["sha"],
        "branch": BRANCH,
    })
    pr = request("POST", f"{API}/pulls", {
        "title": "fix(logging): propose bounded deterministic missing-close repair",
        "body": (
            "Deterministic allowlisted repair of one missing handler.close() line, "
            "NOT a model-generated patch. The unprivileged worker reproduced "
            "RED and checked GREEN on a disposable runner. This publisher "
            "validated the exact insertion, target file and current dev digest. "
            "Independent review and exact-head CI still required; no auto-merge, "
            "release or installer authority."
        ),
        "head": BRANCH, "base": BASE, "draft": True,
    })
    print("Draft PR created:", pr["html_url"])


if __name__ == "__main__":
    main()
