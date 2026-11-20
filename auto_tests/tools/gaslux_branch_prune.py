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
    protect = {"main", "dev", CONTROL, ARCHIVE}
    keep = {"main", "dev", ARCHIVE}
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

def inventory_matches_api(refs, branch_rows):
    """Reject truncated fetches or stale/mismatched GitHub REST branch tips."""
    if (not isinstance(refs, dict) or len(refs) < 20
            or "main" not in refs or "dev" not in refs
            or not isinstance(branch_rows, list)):
        return False
    expected = {}
    for record in branch_rows:
        if not isinstance(record, dict):
            return False
        name = record.get("name")
        commit = record.get("commit")
        sha = commit.get("sha") if isinstance(commit, dict) else None
        if (not isinstance(name, str) or not name
                or not isinstance(sha, str)
                or not re.fullmatch("[0-9a-f]{40}", sha)
                or name in expected):
            return False
        expected[name] = sha
    return refs == expected

def inventory():
    # Cross-check both the complete ref names and all exact commit SHAs
    # against a separate paginated GitHub API inventory. A hard-coded
    # minimum of 100 was wrong after successfully pruning below 100.
    for _attempt in range(3):
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
        if inventory_matches_api(refs, get_collection("branches")):
            return refs
        time.sleep(1)
    raise RuntimeError("incomplete or conflicting Git/API branch inventories")

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


ARCHIVE = "archive/gaslux-experiments-preserved-20261119"
ARCHIVE_MIN_IDLE = 12 * 3600
ARCHIVE_MAX_BATCH = 25

def archive_candidates(refs, protect, keep):
    """Only old, non-PR, non-running, uniquely reachable experimental tips."""
    if ARCHIVE not in refs or ARCHIVE not in keep:
        raise RuntimeError("missing trusted permanent archive branch")
    marker = git("show", refs[ARCHIVE] + ":docs/ARCHIVED_EXPERIMENT_HISTORY.md",
                 check=False)
    if marker.returncode != 0 or "não integra código no instalador" not in marker.stdout:
        raise RuntimeError("archive marker is absent or differs")
    now = int(time.time())
    result = []
    for name, sha in sorted(refs.items()):
        if name in protect or not name.startswith(PREFIX):
            continue
        stamp = int(git("show", "-s", "--format=%ct", sha).stdout.strip())
        if now - stamp < ARCHIVE_MIN_IDLE:
            continue
        # Do not archive material already retained by a protected keeper;
        # that material can be handled by the previous proven prune gate.
        if any(name != k and is_ancestor(sha, refs[k]) for k in keep):
            continue
        result.append({"branch": name, "sha": sha,
                       "tip_date": datetime.fromtimestamp(
                           stamp, timezone.utc).isoformat()})
    result.sort(key=lambda entry: (entry["tip_date"], entry["branch"]))
    return result

def remote_ref(name):
    raw = git("ls-remote", "--heads", "origin",
              "refs/heads/" + name).stdout.strip()
    if not raw:
        return None
    lines = raw.splitlines()
    if len(lines) != 1:
        raise RuntimeError("ambiguous remote reference " + name)
    sha, sep, ref = lines[0].partition("\t")
    if not sep or ref != "refs/heads/" + name or not re.fullmatch("[0-9a-f]{40}", sha):
        raise RuntimeError("unexpected remote reference response " + name)
    return sha

def archive_history_and_delete(report, candidates, refs):
    """Create real two-parent archive commits; delete refs only after proof."""
    if os.getenv("GASLUX_ARCHIVE_APPROVED") != "PRESERVE_HISTORY_LEASE_25":
        raise RuntimeError("explicit bounded archive authorization missing")
    archive_tip = refs[ARCHIVE]
    if remote_ref(ARCHIVE) != archive_tip:
        raise RuntimeError("archive tip changed before authorization")
    for candidate in candidates[:ARCHIVE_MAX_BATCH]:
        name, sha = candidate["branch"], candidate["sha"]
        # API snapshot is refreshed for every deletion; a newly opened
        # PR or running workflow must stop the deletion.
        current_protect, current_keep = protected_refs()
        if (name in current_protect or ARCHIVE not in current_keep
                or remote_ref(name) != sha
                or int(time.time()) - int(
                    git("show", "-s", "--format=%ct", sha).stdout.strip()
                ) < ARCHIVE_MIN_IDLE):
            report["refused"].append({"branch": name, "reason": "changed or protected"})
            continue
        if remote_ref(ARCHIVE) != archive_tip:
            raise RuntimeError("concurrent archive writer detected")
        # Archive only: keep the exact existing tree, adding the original
        # history as the second parent. This is not a source-code merge.
        archive_tree = git("rev-parse", archive_tip + "^{tree}").stdout.strip()
        message = (
            "archive(gaslux): preserve independent experimental Git history\n\n"
            "Source-ref: refs/heads/" + name + "\n"
            "Source-sha: " + sha + "\n"
            "Archive-only: no experimental code included in working tree\n"
            "Production-merge: false\n"
            "Generated-by: GPT-6"
        )
        new_tip = git(
            "commit-tree", archive_tree, "-p", archive_tip,
            "-p", sha, "-m", message).stdout.strip()
        if (not re.fullmatch("[0-9a-f]{40}", new_tip)
                or not is_ancestor(sha, new_tip)
                or git("rev-parse", new_tip + "^{tree}").stdout.strip() != archive_tree):
            raise RuntimeError("archive did not retain exact original history and tree")
        pushed = git(
            "push", "--porcelain",
            "--force-with-lease=refs/heads/" + ARCHIVE + ":" + archive_tip,
            "origin", new_tip + ":refs/heads/" + ARCHIVE, check=False)
        if pushed.returncode != 0 or remote_ref(ARCHIVE) != new_tip:
            raise RuntimeError("archive promotion failed, source not deleted: "
                               + pushed.stderr[-350:])
        archive_tip = new_tip
        report["archived"].append({"branch": name, "source_sha": sha,
                                   "archive_commit": new_tip})
        # Verify remote archive after successful push and block all mutations
        # if either the old source tip or PR/Actions protection changed.
        current_protect, _ = protected_refs()
        if name in current_protect or remote_ref(name) != sha:
            report["refused"].append({"branch": name, "reason": "protected after archive"})
            continue
        if not is_ancestor(sha, archive_tip) or remote_ref(ARCHIVE) != archive_tip:
            raise RuntimeError("archive proof disappeared; source retained")
        deleted = git(
            "push", "--porcelain",
            "--force-with-lease=refs/heads/" + name + ":" + sha,
            "origin", ":refs/heads/" + name, check=False)
        if deleted.returncode == 0 and "deleted" in deleted.stdout and remote_ref(name) is None:
            report["deleted"].append({"branch": name, "sha": sha,
                                      "archive_commit": archive_tip})
        else:
            report["refused"].append({"branch": name, "reason": "lease or policy",
                                      "code": deleted.returncode,
                                      "stderr": deleted.stderr[-300:]})
        print("ARCHIVE", name, sha, new_tip,
              "DELETED" if report["deleted"] and report["deleted"][-1]["branch"] == name
              else "PRESERVED", flush=True)

def exact_prune_candidates(report, approval):
    """Fail closed unless every named SHA is already in its specified PR head."""
    if not isinstance(approval, dict) or not 1 <= len(approval) <= 3:
        raise RuntimeError("invalid exact prune authorization")
    found = {item["branch"]: item for item in report["candidates"]}
    selected = []
    for branch, spec in sorted(approval.items()):
        if (not isinstance(branch, str) or not branch.startswith(PREFIX)
                or not isinstance(spec, dict)
                or set(spec) != {"sha", "preserved_in"}
                or not isinstance(spec["sha"], str)
                or not re.fullmatch("[0-9a-f]{40}", spec["sha"])
                or not isinstance(spec["preserved_in"], str)):
            raise RuntimeError("malformed exact prune authorization")
        item = found.get(branch)
        if (not item or item["sha"] != spec["sha"]
                or spec["preserved_in"] not in report["keeper_refs"]
                or spec["preserved_in"] not in item["reachable_from"]):
            raise RuntimeError("unproven exact ancestry for " + branch)
        selected.append((item, spec["preserved_in"]))
    return selected


def exact_archive_candidates(candidates, approval):
    """Allow only the explicitly named and immutable independent histories."""
    if not isinstance(approval, dict) or not 1 <= len(approval) <= 6:
        raise RuntimeError("invalid exact archive authorization")
    known = {item["branch"]: item for item in candidates}
    selected = []
    for name, sha in sorted(approval.items()):
        if (not isinstance(name, str) or not name.startswith(PREFIX)
                or not isinstance(sha, str)
                or not re.fullmatch("[0-9a-f]{40}", sha)):
            raise RuntimeError("malformed exact archive authorization")
        item = known.get(name)
        if item is None or item["sha"] != sha:
            raise RuntimeError("unverified archived history " + name)
        selected.append(item)
    return selected


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("audit", "prune", "archive"))
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
    report.update(mode=args.mode, deleted=[], refused=[], archived=[])
    archiveable = archive_candidates(refs, protect, keep)
    report["archive_candidate_count"] = len(archiveable)
    print("ARCHIVE_AUDIT", len(archiveable), flush=True)
    for item in archiveable[:60]:
        print("ARCHIVE_CANDIDATE", item["branch"], item["sha"], item["tip_date"], flush=True)
    print("AUDIT", json.dumps({k: v for k, v in report.items()
                              if k not in ("keeper_refs", "candidates")}),
          flush=True)
    for c in report["candidates"][:80]:
        print("CANDIDATE", c["branch"], c["sha"],
              ",".join(c["reachable_from"][:3]), flush=True)
    if args.mode == "archive":
        exact_archive = json.loads(os.environ.get("GASLUX_ARCHIVE_EXACT", "null"))
        selected_archive = exact_archive_candidates(archiveable, exact_archive)
        archive_history_and_delete(report, selected_archive, refs)
    if args.mode == "prune":
        if os.getenv("GASLUX_PRUNE_APPROVED") != "LEASE_GUARDED_30":
            raise RuntimeError("no bounded user-authorized prune gate")
        exact = json.loads(os.environ.get("GASLUX_PRUNE_EXACT", "null"))
        selected = exact_prune_candidates(report, exact)
        new_protect, new_keep = protected_refs()
        fresh = inventory()
        if new_keep - fresh.keys():
            raise RuntimeError("new PR head missing after revalidation")
        for item, keeper in selected:
            name, sha = item["branch"], item["sha"]
            still_reachable = (
                keeper in new_keep and keeper in fresh
                and is_ancestor(sha, fresh[keeper])
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
