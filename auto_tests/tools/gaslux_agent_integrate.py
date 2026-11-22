#!/usr/bin/env python3
"""Trusted default-branch dev integrator: exact one-line bot keyboard PRs only."""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

REPO = "LMhdez/gaslux"
API = "https://api.github.com/repos/" + REPO
SOURCE = "Installation/WindowsKeyboardLayout.cs"
SHA = re.compile(r"^[0-9a-f]{40}$")
BOT = re.compile(r"^bot/gaslux-(mint|zorin)-keyboard-([0-9a-f]{12})$")
TASKS = {
    "mint": ("MINT-PT-KEYBOARD-01", "00000809", "00000816", "pt"),
    "zorin": ("ZORIN-BR-KEYBOARD-01", "0000040C", "00000416", "br"),
}


def api(method: str, route: str, body: dict | None = None):
    if not route.startswith("/") or "://" in route or ".." in route:
        raise ValueError("Untrusted GitHub API route")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise RuntimeError("GitHub token absent")
    req = urllib.request.Request(
        API + route, method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub {method} failed: HTTP {exc.code}") from exc


def content_at(commit: str) -> str:
    if not SHA.fullmatch(commit):
        raise ValueError("Untrusted commit identity")
    blob = api("GET", f"/contents/{SOURCE}?ref={commit}")
    if blob.get("encoding") != "base64":
        raise ValueError("Unexpected source encoding")
    data = base64.b64decode("".join(blob["content"].split()), validate=True)
    if len(data) > 20000 or b"\r" in data:
        raise ValueError("Unexpected source length or line endings")
    return data.decode("utf-8")


def exact_insert(before: str, after: str, role: str) -> bool:
    if role not in TASKS or before == after:
        return False
    _, anchor, identifier, layout = TASKS[role]
    if before.count('"' + anchor + '"') != 1 or '"' + identifier + '"' in before:
        return False
    regex = re.compile(r'^([ \t]*\{\s*"' + anchor + r'"\s*,[^\r\n]*\n)', re.MULTILINE)
    found = list(regex.finditer(before))
    if len(found) != 1:
        return False
    indentation = re.match(r"^[ \t]*", found[0].group(1)).group(0)
    insertion = indentation + '{ "' + identifier + '", Mapping("' + layout + '") },\n'
    wanted = before[:found[0].end()] + insertion + before[found[0].end():]
    return after == wanted and len(after.splitlines()) == len(before.splitlines()) + 1


def inspect(number: int, expected: str | None = None) -> dict:
    if type(number) is not int or not 1 <= number <= 1000000:
        raise ValueError("Bad PR number")
    if expected is not None and not SHA.fullmatch(expected):
        raise ValueError("Bad expected HEAD")
    pr = api("GET", f"/pulls/{number}")
    head, base = pr.get("head", {}), pr.get("base", {})
    branch = head.get("ref", "")
    match = BOT.fullmatch(branch)
    commit, dev = head.get("sha", ""), base.get("sha", "")
    if (pr.get("number") != number or pr.get("state") != "open" or
        pr.get("draft") is not True or
        pr.get("user", {}).get("login") != "github-actions[bot]" or
        match is None or
        head.get("repo", {}).get("full_name") != REPO or
        base.get("repo", {}).get("full_name") != REPO or
        base.get("ref") != "dev" or
        not SHA.fullmatch(str(commit)) or not SHA.fullmatch(str(dev)) or
        match.group(2) != dev[:12] or
        (expected is not None and expected != commit)):
        raise ValueError("Not an approved exact-base GitHub bot Draft PR")
    if api("GET", "/git/ref/heads/dev")["object"]["sha"] != dev:
        raise RuntimeError("dev moved since proposal; deny")
    parents = api("GET", f"/git/commits/{commit}").get("parents", [])
    if len(parents) != 1 or parents[0].get("sha") != dev:
        raise ValueError("Proposal has unexpected ancestry")
    files = api("GET", f"/pulls/{number}/files?per_page=100")
    if (not isinstance(files, list) or len(files) != 1 or
        files[0].get("filename") != SOURCE or
        files[0].get("status") != "modified" or
        files[0].get("additions") != 1 or
        files[0].get("deletions") != 0 or
        files[0].get("changes") != 1):
        raise ValueError("Candidate diff exceeds one allowed line")
    if not exact_insert(content_at(dev), content_at(commit), match.group(1)):
        raise ValueError("Candidate source differs from approved exact code")
    reviews = api("GET", f"/pulls/{number}/reviews?per_page=100")
    if not isinstance(reviews, list) or any(
        v.get("state") == "CHANGES_REQUESTED" for v in reviews
    ):
        raise ValueError("An unresolved review objection exists")
    comments = api("GET", f"/issues/{number}/comments?per_page=100")
    if not isinstance(comments, list) or any(
        "SAFETY_DENIED" in str(v.get("body", "")).upper() or
        "BLOCKED_SAFETY" in str(v.get("body", "")).upper() or
        "DO_NOT_MERGE" in str(v.get("body", "")).upper()
        for v in comments
    ):
        raise ValueError("A technical Safety hold exists")
    checks = api("GET", f"/commits/{commit}/check-runs?per_page=100")
    if any(
        v.get("status") != "completed" or
        v.get("conclusion") not in ("success", "skipped", "neutral")
        for v in checks.get("check_runs", [])
    ):
        raise ValueError("An existing candidate-head check is not green")
    return {
        "number": number, "head": commit, "base": dev,
        "role": match.group(1), "task": TASKS[match.group(1)][0],
    }


def select() -> dict:
    prs = api("GET", "/pulls?state=open&per_page=100")
    if not isinstance(prs, list):
        raise ValueError("Unexpected PR list")
    queue = [
        pr for pr in prs if
        BOT.fullmatch(str(pr.get("head", {}).get("ref", ""))) and
        pr.get("user", {}).get("login") == "github-actions[bot]"
    ]
    if not queue:
        return {"status": "idle"}
    queue.sort(key=lambda pr: (pr.get("created_at", ""), pr["number"]))
    return {"status": "selected", **inspect(queue[0]["number"])}


def merge(number: int, expected: str) -> dict:
    if os.getenv("GITHUB_REPOSITORY") != REPO or os.getenv("GITHUB_REF") != "refs/heads/main":
        raise RuntimeError("Trusted default branch only")
    event_name = os.getenv("GITHUB_EVENT_NAME")
    if event_name not in ("schedule", "workflow_dispatch", "push", "workflow_run"):
        raise RuntimeError("Untrusted event")
    if event_name == "workflow_run":
        event_path = os.getenv("GITHUB_EVENT_PATH", "")
        if not event_path:
            raise RuntimeError("Missing workflow completion provenance")
        evt = json.loads(Path(event_path).read_text(encoding="utf-8"))
        runner = evt.get("workflow_run", {})
        if (runner.get("name") != "Gaslux autonomous GitHub agents"
            or runner.get("conclusion") != "success"
            or runner.get("head_branch") != "main"
            or runner.get("head_repository", {}).get("full_name") != REPO
            or runner.get("event") not in ("push", "schedule", "workflow_dispatch")):
            raise RuntimeError("Untrusted workflow completion provenance")
    if os.getenv("GASLUX_WINDOWS_ACCEPTANCE") != "success":
        raise RuntimeError("No exact-HEAD Windows build and tests in this run")
    checked = inspect(number, expected)
    if inspect(number, expected) != checked:
        raise RuntimeError("Proposal changed during validation")
    result = api("PUT", f"/pulls/{number}/merge", {
        "sha": expected,
        "merge_method": "squash",
        "commit_title": f"feat(keyboard): {checked['task']} Windows-validated",
        "commit_message": (
            f"Exactly one approved C# product mapping, {checked['task']}. "
            f"Windows build and tests executed on immutable {expected}. "
            "No physical disk, boot, recovery or release authority. "
            "Generated-by: GitHub Actions GASLUX-INTEGRATOR."
        ),
    })
    if result.get("merged") is not True or not SHA.fullmatch(str(result.get("sha", ""))):
        raise RuntimeError("GitHub did not confirm dev merge")
    return {"status": "merged", "pr": number, "sha": result["sha"], "task": checked["task"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("select", "verify", "merge"))
    parser.add_argument("--pr", type=int)
    parser.add_argument("--head")
    args = parser.parse_args()
    if args.operation == "select":
        out = select()
    elif args.pr is None or args.head is None:
        parser.error("PR and immutable HEAD required")
    else:
        out = inspect(args.pr, args.head) if args.operation == "verify" else merge(args.pr, args.head)
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()
