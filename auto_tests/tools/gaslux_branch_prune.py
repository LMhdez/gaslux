#!/usr/bin/env python3
"""Safe branch-ref audit: only prune exact reachable old tips with a Git lease."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request, urlopen

REPO = "LMhdez/gaslux"
CONTROL = "automation/gaslux-branch-prune-20261119"
PREFIX = ("feature/", "fix/", "test/", "diag/", "debug/",
          "docs/", "security/", "integration/", "ci/")
IDLE = 6 * 3600

def git(*args, check=True):
    return subprocess.run(["git", *args], text=True, capture_output=True,
                          timeout=180, check=check)

def get_collection(path):
    token = os.environ["GH_TOKEN"]
    all_items = []
    for page in range(1, 16):
        sep = "&" if "?" in path else "?"
        req = Request(
            f"https://api.github.com/repos/{REPO}/{path}{sep}per_page=100&page={page}",
            headers={"Authorization": "Bearer " + token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        with urlopen(req, timeout=30) as response:
            raw = json.load(response)
        items = raw.get("workflow_runs") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            raise RuntimeError("unexpected GitHub API collection")
        all_items.extend(items)
        if len(items) < 100:
            return all_items
    raise RuntimeError("incomplete GitHub API pagination")

def protected_refs():
    protect = {"main", "dev", CONTROL}
    keep = {"main", "dev"}
    for pr in get_collection("pulls?state=open"):
        for side in ("head", "base"):
            ref = pr[side]
            if ref.get("repo") and ref["repo"]["full_name"] == REPO:
                protect.add(ref["ref"])
                if side == "head":
                    keep.add(ref["ref"])
    for status in ("in_progress", "queued", "waiting", "pending"):
        for run in get_collection("actions/runs?status=" + status):
            if run.get("head_branch"):
                protect.add(run["head_branch"])
    return protect, keep

def inventory():
    git("fetch", "--prune", "--no-tags", "origin",
        "+refs/heads/*:refs/remotes/origin/*")
    stdout = git(
        "for-each-ref", "--format=%(refname:strip=3) %(objectname)",
        "refs/remotes/origin").stdout
    refs = {}
    for line in stdout.splitlines():
        name, _, sha = line.partition(" ")
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            refs[name] = sha
    if len(refs) < 100 or "main" not in refs or "dev" not in refs:
        raise RuntimeError("incomplete branch inventory")
    return refs

def is_ancestor(older, newer):
    proc = git("merge-base", "--is-ancestor", older, newer, check=False)
    if proc.returncode not in (0, 1):
        raise RuntimeError("merge-base failed")
    return proc.returncode == 0

def audit(refs, protect, keep):
    if keep - refs.keys():
        raise RuntimeError("missing live PR head in checkout")
    candidates = []
    excludes = {}
    now = int(time.time())
    for branch, sha in sorted(refs.items()):
        reason = None
        if branch in protect or not branch.startswith(PREFIX):
            reason = "protected"
        else:
            timestamp = int(git("show", "-s", "--format=%ct", sha).stdout.strip())
            if now - timestamp < IDLE:
                reason = "active_recently"
            else:
                reachable = [x for x in sorted(keep)
                             if x != branch and is_ancestor(sha, refs[x])]
                if not reachable:
                    reason = "unique_unmerged_history"
                else:
                    candidates.append({
                        "branch": branch, "sha": sha,
                        "reachable_from": reachable,
                        "tip_date": datetime.fromtimestamp(
                            timestamp, timezone.utc).isoformat(),
                    })
        if reason:
            excludes[reason] = excludes.get(reason, 0) + 1
    candidates.sort(key=lambda x: (x["tip_date"], x["branch"]))
    return {"total": len(refs), "protected": len(protect & refs.keys()),
            "keeper_refs": sorted(keep), "candidate_count": len(candidates),
            "excluded": excludes, "candidates": candidates}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("audit", "prune"))
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if (os.getenv("GITHUB_ACTIONS") != "true"
        or os.getenv("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.getenv("GITHUB_REPOSITORY") != REPO
        or os.getenv("GITHUB_REF") != "refs/heads/" + CONTROL
        or os.getenv("GITHUB_EVENT_NAME") != "push"):
        raise RuntimeError("not the trusted standalone cleanup branch")
    protect, keep = protected_refs()
    refs = inventory()
    report = audit(refs, protect, keep)
    report.update(mode=args.mode, deleted=[], refused=[])
    print("AUDIT", json.dumps({k: v for k, v in report.items()
                              if k not in ("keeper_refs", "candidates")}),
          flush=True)
    for c in report["candidates"][:80]:
        print("CANDIDATE", c["branch"], c["sha"],
              ",".join(c["reachable_from"][:3]), flush=True)
    if args.mode == "prune":
        if os.getenv("GASLUX_PRUNE_APPROVED") != "LEASE_GUARDED_30":
            raise RuntimeError("no bounded user-authorized prune gate")
        new_protect, new_keep = protected_refs()
        fresh = inventory()
        if new_keep - fresh.keys():
            raise RuntimeError("new PR head missing after revalidation")
        for item in report["candidates"][:30]:
            name, sha = item["branch"], item["sha"]
            still_reachable = any(
                is_ancestor(sha, fresh[k]) for k in new_keep
                if k in fresh and k != name
            )
            tip_old = (int(time.time()) -
                       int(git("show", "-s", "--format=%ct", sha).stdout.strip())) >= IDLE
            if (name in new_protect or fresh.get(name) != sha
                    or not still_reachable or not tip_old):
                report["refused"].append({"branch": name, "reason": "recheck"})
                continue
            deletion = git(
                "push", "--porcelain",
                "--force-with-lease=refs/heads/" + name + ":" + sha,
                "origin", ":refs/heads/" + name, check=False)
            if deletion.returncode == 0 and "deleted" in deletion.stdout:
                report["deleted"].append({"branch": name, "sha": sha})
            else:
                report["refused"].append({
                    "branch": name, "reason": "lease or policy",
                    "code": deletion.returncode,
                    "stderr": deletion.stderr[-400:]})
            print("PRUNE", name, deletion.returncode, flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(f"## Branch {args.mode}: {report['total']} total, "
                    f"{report['candidate_count']} old reachable candidates, "
                    f"{len(report['deleted'])} deleted, "
                    f"{len(report['refused'])} refused\n")
    return 0 if not report["refused"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
