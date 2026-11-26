#!/usr/bin/env python3
"""Trusted default-branch dev integrator: exact one-line bot keyboard PRs only."""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import posixpath
import re
import sys
import urllib.error
import urllib.request

REPO = "LMhdez/gaslux"
API = "https://api.github.com/repos/" + REPO
SOURCE = "Installation/WindowsKeyboardLayout.cs"
SHA = re.compile(r"^[0-9a-f]{40}$")
BOT = re.compile(r"^bot/gaslux-(mint|zorin)-keyboard-([0-9a-f]{12})$")

class StaleProposal(RuntimeError):
    """Safe refusal when a relevant dev change needs a fresh model candidate."""


def harmless_drift_file(item: dict) -> bool:
    """Allow only non-build, non-product and non-agent-authority updates."""
    path = item.get("filename", "")
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        return False
    if posixpath.normpath(path) != path or path.startswith("../"):
        return False
    previous = item.get("previous_filename")
    if previous is not None and previous != path:
        return False
    if item.get("status") not in ("added", "modified"):
        return False
    if path.startswith("docs/") and path.endswith(".md"):
        return True
    if path.startswith("auto_tests/") and path.endswith(".py"):
        return not path.startswith("auto_tests/tools/gaslux_agent_")
    return path.startswith(".github/workflows/auth-dest-") and path.endswith(".yml")


def compatible_advance(original: str, live: str) -> bool:
    """Require complete, forward-only, path-disjoint dev ancestry."""
    if original == live:
        return True
    if not SHA.fullmatch(original) or not SHA.fullmatch(live):
        return False
    diff = api("GET", f"/compare/{original}...{live}")
    files = diff.get("files")
    return (
        diff.get("status") == "ahead"
        and diff.get("merge_base_commit", {}).get("sha") == original
        and type(diff.get("ahead_by")) is int and 0 < diff["ahead_by"] <= 100
        and type(diff.get("total_commits")) is int and 0 < diff["total_commits"] <= 100
        and isinstance(files, list) and 0 < len(files) < 300
        and all(isinstance(f, dict) and harmless_drift_file(f) for f in files)
    )
TASKS = {
    "mint": ("MINT-PT-KEYBOARD-01", "00000809", "00000816", "pt"),
    "zorin": ("ZORIN-BR-KEYBOARD-01", "0000040C", "00000416", "br"),
}


def api(method: str, route: str, body: dict | None = None):
    safe_compare = re.fullmatch(
        r"/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}", route
    ) is not None
    if not route.startswith("/") or "://" in route or (".." in route and not safe_compare):
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
    commit, declared_base = head.get("sha", ""), base.get("sha", "")
    if (pr.get("number") != number or pr.get("state") != "open" or
        type(pr.get("draft")) is not bool or
        pr.get("user", {}).get("login") != "github-actions[bot]" or
        match is None or
        head.get("repo", {}).get("full_name") != REPO or
        base.get("repo", {}).get("full_name") != REPO or
        base.get("ref") != "dev" or
        not SHA.fullmatch(str(commit)) or not SHA.fullmatch(str(declared_base)) or
        (expected is not None and expected != commit)):
        raise ValueError("Not an approved exact-base GitHub bot Draft PR")
    # GitHub PR metadata may retain an historical base.sha for a long-lived PR.
    # Only the live git ref is the integration target; never treat PR base.sha
    # as a fresh branch snapshot or as proof of the checked-out source.
    dev = api("GET", "/git/ref/heads/dev")["object"]["sha"]
    if not SHA.fullmatch(str(dev)):
        raise ValueError("Invalid current dev ref")
    parents = api("GET", f"/git/commits/{commit}").get("parents", [])
    if len(parents) != 1 or not SHA.fullmatch(str(parents[0].get("sha", ""))):
        raise ValueError("Proposal has unexpected ancestry")
    original = parents[0]["sha"]
    if match.group(2) != original[:12]:
        raise ValueError("Proposal original-base identity mismatch")
    if not compatible_advance(original, dev):
        raise StaleProposal("relevant dev changes require regenerated candidate")
    files = api("GET", f"/pulls/{number}/files?per_page=100")
    if (not isinstance(files, list) or len(files) != 1 or
        files[0].get("filename") != SOURCE or
        files[0].get("status") != "modified" or
        files[0].get("additions") != 1 or
        files[0].get("deletions") != 0 or
        files[0].get("changes") != 1):
        raise ValueError("Candidate diff exceeds one allowed line")
    original_code = content_at(original)
    if not exact_insert(original_code, content_at(commit), match.group(1)):
        raise ValueError("Candidate source differs from approved exact code")
    if content_at(dev) != original_code:
        raise StaleProposal("Windows product mapping source changed in dev")
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
    if api("GET", "/git/ref/heads/dev")["object"]["sha"] != dev:
        raise StaleProposal("dev changed during validation; retry")
    return {
        "number": number, "head": commit, "base": dev,
        "original_base": original,
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
    for candidate in queue:
        try:
            return {"status": "selected", **inspect(candidate["number"])}
        except StaleProposal:
            # Old proposals cannot starve newer compatible work.
            continue
    return {"status": "idle"}


def shared_admission():
    """Import only trusted siblings even when invoked with python -I."""
    directory = str(Path(__file__).resolve().parent)
    if not sys.path or sys.path[0] != directory:
        sys.path.insert(0, directory)
    import gaslux_supervised_admission as gate
    return gate


def strict_merge_policy(base: str) -> bool:
    gate = shared_admission()
    # The staged App publisher does not recognize legacy keyboard proposals.
    # Keep this route closed under production migration until it has its own
    # exact independently reviewed status adapter.
    return (os.getenv("GASLUX_APP_STATUS_GATES_ENABLED") != "true"
            and gate.strict_dev_protected(base) and gate.production_merge_policy(base))


def server_role_protection(checked: dict) -> bool:
    gate = shared_admission()
    reviewer, owners = gate.configured_reviewers()
    return gate.role_review_protected(checked["base"], reviewer, owners.get(checked["role"]),
                                      head=checked["head"])


def independent_merge_reviews(checked: dict) -> bool:
    """Require the actual Safety and owner identities, not just any two reviews."""
    gate = shared_admission()
    admission = gate.admission
    reviewer, owners = gate.configured_reviewers()
    role, head, base = checked["role"], checked["head"], checked["base"]
    owner = owners.get(role)
    pr = api("GET", f"/pulls/{checked['number']}")
    author = pr.get("user") or {}
    if (not admission.publisher_ok(author) or pr.get("state") != "open"
            or pr.get("head", {}).get("sha") != head
            or pr.get("base", {}).get("ref") != "dev"
            or reviewer in admission.BOTS.values() or owner in admission.BOTS.values()):
        return False
    reviews = admission.complete_page(api("GET", f"/pulls/{checked['number']}/reviews?per_page=100"))
    return (admission.review_ok(reviews, reviewer, author["id"], head, base)
            and admission.owner_review_ok(reviews, owner, reviewer, author["id"],
                                          None, role, head, base, supervised=True))


def require_merge_context():
    if os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true":
        raise RuntimeError("GASLUX_AUTONOMY_PAUSED: dev merge blocked")
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
        allowed = {
            ("Gaslux autonomous GitHub agents", "main"),
            ("GASLUX-CLOCK/auto", "main"),
            ("GASLUX-CLOCK/mint", "main"),
            ("GASLUX-CLOCK/zorin", "main"),
            ("Gaslux Goal Supervisor - read-only progress", "dev"),
        }
        if ((runner.get("name"), runner.get("head_branch")) not in allowed
            or runner.get("conclusion") != "success"
            or runner.get("head_repository", {}).get("full_name") != REPO
            or runner.get("event") not in ("push", "schedule", "workflow_dispatch")):
            raise RuntimeError("Untrusted workflow completion provenance")
    if os.getenv("GASLUX_WINDOWS_ACCEPTANCE") != "success":
        raise RuntimeError("No exact-HEAD Windows build and tests in this run")
    

def verify_before_ready(number: int, expected: str) -> dict:
    require_merge_context()
    checked = inspect(number, expected)
    if checked["original_base"] != checked["base"]:
        raise StaleProposal("Exact base required before readiness")
    if (not strict_merge_policy(checked["base"]) or not independent_merge_reviews(checked)
            or not server_role_protection(checked)):
        raise RuntimeError("Strict protection and independent exact reviews required before readiness")
    if inspect(number, expected) != checked:
        raise StaleProposal("Candidate changed before readiness")
    return checked


def merge(number: int, expected: str) -> dict:
    require_merge_context()
    try:
        checked = inspect(number, expected)
        if inspect(number, expected) != checked:
            raise StaleProposal("dev changed while confirming candidate")
    except StaleProposal:
        return {"status": "retry", "reason": "dev_updated", "pr": number}
    # A harmless historical advance is useful for inventory, not for merging
    # an out-of-date candidate under an exact-base Windows acceptance receipt.
    if checked["original_base"] != checked["base"]:
        return {"status": "retry", "reason": "exact_base_required", "pr": number}
    if not strict_merge_policy(checked["base"]):
        return {"status": "blocked", "reason": "strict_base_protection_required", "pr": number}
    if not independent_merge_reviews(checked):
        return {"status": "blocked", "reason": "independent_reviews_required", "pr": number}
    if not server_role_protection(checked):
        return {"status": "blocked", "reason": "server_role_review_protection_required", "pr": number}
    if api("GET", "/git/ref/heads/dev")["object"]["sha"] != checked["base"]:
        return {"status": "retry", "reason": "dev_updated", "pr": number}
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
    merged = result["sha"]
    actual = api("GET", f"/git/commits/{merged}")
    reviewed = api("GET", f"/git/commits/{expected}")
    tree = actual.get("tree", {}).get("sha")
    if ([p.get("sha") for p in actual.get("parents", [])] != [checked["base"]]
            or not isinstance(tree, str) or not SHA.fullmatch(tree)
            or tree != reviewed.get("tree", {}).get("sha")):
        raise RuntimeError("Merged tree or parent differs from reviewed candidate; investigate")
    closed = api("GET", f"/pulls/{number}")
    if (closed.get("state") != "closed" or closed.get("merged") is not True
            or closed.get("merge_commit_sha") != merged
            or closed.get("head", {}).get("sha") != expected
            or closed.get("base", {}).get("ref") != "dev"):
        raise RuntimeError("Post-merge PR closure not verified; investigate")
    live = api("GET", "/git/ref/heads/dev")["object"]["sha"]
    if not isinstance(live, str) or not SHA.fullmatch(live):
        raise RuntimeError("Invalid post-merge dev")
    if live != merged:
        relation = api("GET", f"/compare/{merged}...{live}")
        if (relation.get("status") != "ahead" or relation.get("behind_by") != 0
                or relation.get("merge_base_commit", {}).get("sha") != merged):
            raise RuntimeError("Merge not proven in live dev")
    return {"status": "merged", "pr": number, "sha": merged, "task": checked["task"],
            "reviewed_base": checked["base"], "reviewed_tree_verified": True,
            "independent_reviews_verified": True,
            "strict_base_protection_verified": True, "pr_closure_verified": True,
            "dev_ancestry_verified": True, "release_eligible": False}


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
        out = verify_before_ready(args.pr, args.head) if args.operation == "verify" else merge(args.pr, args.head)
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()
