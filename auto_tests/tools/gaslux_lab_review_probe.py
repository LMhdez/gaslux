#!/usr/bin/env python3
"""One frozen inert laboratory PR; approval-only credential tests, no merge."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gaslux_supervised_admission as gate

A = gate.admission
NUMBER = 431
BASE_REF = "lab/gaslux-review-probe-v1-base"
HEAD_REF = "lab/gaslux-review-probe-v1-candidate"
BASE = "87b14e62f59da27d1a859741a9d149973414920f"
HEAD = "afdf58873cd862c6a8bf359824d6b6fb11b168f0"
TREE = "095fd1925b2cef0d7afae50ec7bdf782077fda0c"
BLOB = "3ab13c6904cb4ed4034506919ff6f926295e20ff"
FILE = "docs/gaslux-review-probe-v1.txt"
AUTHOR = 156089838
ROUTE = f"/pulls/{NUMBER}"


def api(method, route, body=None):
    """No ref, PR-target, merge, dismissal or other write operation is exposed."""
    if method == "GET" and body is None:
        return A.api(method, route)
    if (method == "POST" and route == ROUTE + "/reviews"
            and isinstance(body, dict) and set(body) == {"commit_id", "event", "body"}
            and body["commit_id"] == HEAD and body["event"] == "APPROVE"
            and body["body"] in (marker("safety"), marker("owner"))):
        return A.api(method, route, body)
    raise ValueError("Laboratory write prohibited")


def context():
    sha = os.getenv("GITHUB_SHA")
    if (os.getenv("GITHUB_REPOSITORY") != A.REPO
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GITHUB_EVENT_NAME") not in ("push", "workflow_dispatch")
            or os.getenv("GASLUX_AUTONOMY_PAUSED") != "true"
            or not A.valid_sha(sha)
            or not os.getenv("GH_TOKEN")
            or api("GET", "/git/ref/heads/main")["object"]["sha"] != sha):
        raise ValueError("Current trusted paused main required")


def actors():
    safety, owners = gate.configured_reviewers()
    ids = set(owners.values())
    if (type(safety) is not int or safety <= 0 or len(ids) != 1
            or set(owners) != set(gate.factory.TASKS)):
        raise ValueError("Independent complete lab actor mapping required")
    owner = next(iter(ids))
    if (type(owner) is not int or owner <= 0 or safety == owner
            or {safety, owner} & ({AUTHOR} | set(A.BOTS.values()))):
        raise ValueError("Non-author, non-publisher reviewer identities required")
    return {"safety": safety, "owner": owner}


def ref(name):
    return api("GET", "/git/ref/heads/" + name)["object"]["sha"]


def candidate():
    pr = api("GET", ROUTE)
    if (pr.get("number") != NUMBER or pr.get("user", {}).get("id") != AUTHOR
            or pr.get("head", {}).get("ref") != HEAD_REF
            or pr.get("head", {}).get("sha") != HEAD
            or pr.get("base", {}).get("ref") != BASE_REF
            or any((pr.get(k, {}).get("repo") or {}).get("full_name") != A.REPO
                   for k in ("head", "base"))):
        raise ValueError("Lab PR identity drift")
    if pr.get("state") == "closed":
        return pr
    if (pr.get("state") != "open" or pr.get("draft") is not False
            or pr.get("merged") is not False or pr.get("base", {}).get("sha") != BASE
            or pr.get("changed_files") != 1 or pr.get("commits") != 1
            or pr.get("additions") != 2 or pr.get("deletions") != 0
            or ref(BASE_REF) != BASE or ref(HEAD_REF) != HEAD):
        raise ValueError("Lab PR state or ref drift")
    commit = api("GET", f"/git/commits/{HEAD}")
    if (commit.get("sha") != HEAD or commit.get("tree", {}).get("sha") != TREE
            or [p.get("sha") for p in commit.get("parents", [])] != [BASE]):
        raise ValueError("Lab commit ancestry or tree drift")
    files = A.complete_page(api("GET", ROUTE + "/files?per_page=100"))
    if (len(files) != 1 or any(files[0].get(k) != v for k, v in {
            "filename": FILE, "sha": BLOB, "status": "added",
            "additions": 2, "deletions": 0, "changes": 2}.items())):
        raise ValueError("Lab inert scope not verified")
    return pr


def marker(kind):
    return (f"GASLUX-LAB-REVIEW-V1 kind={kind} head={HEAD} base={BASE}\n"
            "Inert laboratory fixture only. No installer or production approval.")


def verified_reviews(ids):
    rows = A.complete_page(api("GET", ROUTE + "/reviews?per_page=100"))
    found = {}
    for row in rows:
        if row.get("state") == "COMMENTED":
            continue
        role = next((kind for kind, uid in ids.items()
                     if uid == row.get("user", {}).get("id")), None)
        if (role is None or role in found or row.get("state") != "APPROVED"
                or row.get("commit_id") != HEAD or row.get("body") != marker(role)
                or type(row.get("id")) is not int or row["id"] <= 0
                or row.get("user", {}).get("type") != "Bot"):
            raise ValueError("Unexpected, stale, dismissed or adverse review")
        found[role] = row["id"]
    return found


def approve(kind):
    context()
    ids = actors()
    if gate.review_app_actor(kind) != ids[kind]:
        raise ValueError("Lab reviewer credential mismatch")
    pr = candidate()
    if pr["state"] == "closed":
        return {"status": "lab_closed_no_new_review", "pr": NUMBER,
                "merge_authorized": False}
    previous = verified_reviews(ids)
    if kind not in previous:
        if candidate()["state"] != "open":
            raise ValueError("Lab closed before review")
        context()
        if candidate()["state"] != "open" or kind in verified_reviews(ids):
            raise ValueError("Lab changed before review")
        result = api("POST", ROUTE + "/reviews", {
            "commit_id": HEAD, "event": "APPROVE", "body": marker(kind)})
        if (result.get("user", {}).get("id") != ids[kind]
                or result.get("state") != "APPROVED" or result.get("commit_id") != HEAD
                or result.get("body") != marker(kind)
                or type(result.get("id")) is not int):
            raise ValueError("Independent review receipt rejected")
        expected = result["id"]
    else:
        expected = previous[kind]
    if candidate()["state"] != "open" or verified_reviews(ids).get(kind) != expected:
        raise ValueError("Independent review no longer current")
    return {"status": "lab_review_verified", "pr": NUMBER, "kind": kind,
            "head": HEAD, "reviewer": ids[kind], "review_id": expected,
            "review_capability_verified": True, "merge_authorized": False}


def protected():
    """Require an actual isolated exact-ref ruleset; never infer protection."""
    active = A.complete_page(api("GET", f"/rules/branches/lab%2Fgaslux-review-probe-v1-base?per_page=100"))
    for rid in {r.get("ruleset_id") for r in active}:
        if type(rid) is not int or rid <= 0:
            continue
        rows = [r for r in active if r.get("ruleset_id") == rid]
        if any(r.get("ruleset_source") != A.REPO or r.get("ruleset_source_type") != "Repository"
               for r in rows):
            continue
        detail = api("GET", f"/rulesets/{rid}?includes_parents=false")
        if (detail.get("id") != rid or detail.get("source") != A.REPO
                or detail.get("source_type") != "Repository" or detail.get("target") != "branch"
                or detail.get("enforcement") != "active" or detail.get("conditions") !=
                {"ref_name": {"include": ["refs/heads/" + BASE_REF], "exclude": []}}):
            continue
        declared = A.complete_page(detail["rules"])
        by_type = {r["type"]: r.get("parameters", {}) for r in declared}
        effective = {r["type"]: r.get("parameters", {}) for r in rows}
        if (len(by_type) != len(declared) or len(effective) != len(rows)
                or by_type != effective or not {"deletion", "non_fast_forward", "pull_request", "required_status_checks"} <= set(by_type)
                or "update" in by_type):
            continue
        checks = by_type["required_status_checks"]
        if (checks.get("strict_required_status_checks_policy") is not True
                or checks.get("do_not_enforce_on_create") is True
                or not checks.get("required_status_checks")):
            continue
        review = by_type["pull_request"]
        if (type(review.get("required_approving_review_count")) is not int
                or review["required_approving_review_count"] != 2
                or any(review.get(k) is not True for k in ("dismiss_stale_reviews_on_push",
                   "require_last_push_approval", "required_review_thread_resolution"))
                or "merge" not in review.get("allowed_merge_methods", [])
                or gate.ruleset_bypass_evidence(detail) not in ("rest_empty", "graphql_empty")):
            continue
        return rid
    return None


def decision():
    raw = subprocess.run(["gh", "pr", "view", str(NUMBER), "--repo", A.REPO,
                          "--json", "headRefName,baseRefName,headRefOid,baseRefOid,reviewDecision,mergeStateStatus,mergeable"],
                         capture_output=True, check=True, timeout=30).stdout
    data = json.loads(raw)
    if (data.get("headRefOid") != HEAD or data.get("baseRefOid") != BASE
            or data.get("headRefName") != HEAD_REF or data.get("baseRefName") != BASE_REF):
        raise ValueError("GitHub review decision refers to different commits")
    return data


def merged_receipt(pr):
    sha = pr.get("merge_commit_sha")
    if (pr.get("state") != "closed" or pr.get("merged") is not True
            or not A.valid_sha(sha) or ref(BASE_REF) != sha):
        raise ValueError("No exact closed lab merge")
    obj = api("GET", f"/git/commits/{sha}")
    if ([p.get("sha") for p in obj.get("parents", [])] != [BASE, HEAD]
            or obj.get("tree", {}).get("sha") != TREE):
        raise ValueError("Lab merge parent or tree mismatch")
    return sha


def audit():
    context()
    ids = actors()
    pr = candidate()
    reviews = verified_reviews(ids)
    if set(reviews) != set(ids):
        raise ValueError("Two distinct exact lab approvals required")
    report = {"pr": NUMBER, "head": HEAD, "base": BASE, "review_ids": reviews,
              "independent_reviews_verified": True,
              "production_merge_authorized": False,
              "server_named_role_enforcement_verified": False,
              "lab_merge_verified": False,
              "lab_merge_authorized": False,
              "write_isolation_verified": False,
              "merge_blocker": "ATOMIC_TARGET_AND_BASE_CONFINEMENT_UNAVAILABLE"}
    if pr["state"] == "closed":
        # A closed PR and exact tree alone cannot attribute a past merge to this job.
        return {**report, "status": "lab_merge_observed", "merge_sha": merged_receipt(pr)}
    rid = protected()
    if rid is None:
        return {**report, "status": "lab_rule_missing_no_merge"}
    state = decision()
    if (state.get("reviewDecision") != "APPROVED" or state.get("mergeable") != "MERGEABLE"
            or state.get("mergeStateStatus") != "CLEAN"):
        return {**report, "status": "server_merge_not_ready", "lab_ruleset": rid,
                "review_decision": state.get("reviewDecision"),
                "merge_state": state.get("mergeStateStatus")}
    # Even a CLEAN server decision and exact-ref ruleset do not bind the
    # merge API to the target ref or base SHA. Never enable a write here.
    # The production repository cannot be a disposable merge laboratory.
    if (candidate()["state"] != "open" or protected() != rid
            or verified_reviews(ids) != reviews or decision() != state):
        raise ValueError("Lab observation changed during audit")
    return {**report, "status": "server_approved_merge_disabled", "lab_ruleset": rid}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("safety", "owner", "audit"))
    args = p.parse_args()
    report = audit() if args.mode == "audit" else approve(args.mode)
    print("GASLUX_LAB_REVIEW_PROBE " + json.dumps(report, sort_keys=True))
