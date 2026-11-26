#!/usr/bin/env python3
"""Bounded duplicate Draft reconciliation; never merge or delete refs."""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import sys
import time

# Trusted script directory only, including when invoked with python -I.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gaslux_distro_admission as admission
from gaslux_agent_feature_factory import TASKS

HOLD = ("SAFETY_DENIED", "BLOCKED_SAFETY", "DO_NOT_MERGE",
        "DO_NOT_CLOSE", "DO NOT CLOSE", "SAFETY HOLD", "SECURITY HOLD")


def unobstructed(number):
    comments = admission.complete_page(admission.api(
        "GET", f"/issues/{number}/comments?per_page=100"))
    return not any(marker in str(item.get("body", "")).upper()
                   for item in comments for marker in HOLD)


def equivalent(old, new, role, base):
    """Verify both histories independently and compare actual bytes/semantics."""
    path, test, _ = TASKS[role]
    old_pr = admission.api("GET", f"/pulls/{old['pr']}")
    new_pr = admission.api("GET", f"/pulls/{new['pr']}")
    if (old_pr["head"]["sha"] != old["head"] or new_pr["head"]["sha"] != new["head"]
            or not all(p.get("state") == "open" and p.get("draft") is True
                       and admission.publisher_ok(p.get("user") or {})
                       for p in (old_pr, new_pr))):
        return False
    original, _ = admission.candidate_append(old_pr, role, old["head"], path)
    current, _ = admission.candidate_append(new_pr, role, new["head"], path)
    if current != base or original == base:
        return False
    diff = admission.api("GET", f"/compare/{original}...{base}")
    if (diff.get("status") != "ahead"
            or diff.get("merge_base_commit", {}).get("sha") != original):
        return False
    before = admission.source_at(path, original)
    if before != admission.source_at(path, base):
        return False
    test_path = "auto_tests/tests/" + test
    if admission.source_at(test_path, original) != admission.source_at(test_path, base):
        return False
    def normalized(head):
        raw = admission.source_at(path, head)
        formatted = raw.startswith(before.rstrip(b"\n") + b"\n\n\n")
        addition = admission.exact_append(before, raw, role, formatted=formatted)
        admission.require_fixed_lifecycle(role, addition)
        tree = ast.parse(addition)
        # The existing fixed contract admits exactly these two local names.
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "missingGates":
                node.id = "missing"
        return ast.dump(tree, include_attributes=False)
    return (normalized(old["head"]) == normalized(new["head"])
            and unobstructed(old["pr"]) and unobstructed(new["pr"]))


def plan():
    base = admission.api("GET", "/git/ref/heads/dev")["object"]["sha"]
    if not admission.valid_sha(base):
        raise ValueError("Invalid live base")
    candidates = admission.discover_candidates()
    by_role = {}
    for number, (role, head) in candidates.items():
        by_role.setdefault(role, []).append((number, head))
    for role, items in by_role.items():
        if len(items) != 2:
            continue
        # Count all matching same-repo proposals, including non-bot/non-Draft,
        # rather than ignoring a third candidate during deduplication.
        inventory = admission.complete_page(admission.api(
            "GET", "/pulls?state=open&base=dev&per_page=100"))
        observed = set()
        for pr in inventory:
            head = pr["head"]
            match = admission.BRANCH.fullmatch(head.get("ref", ""))
            if (match and match[1] == role
                    and (head.get("repo") or {}).get("full_name") == admission.REPO):
                observed.add(pr["number"])
        if observed != {number for number, _ in items}:
            continue
        rows = [admission.inspect(number, role, None, expected_head=head)
                for number, head in items]
        if not all(row["base"] == base and row["technical_objection"] is False
                   and row["exact_scope_verified"] is True
                   and row["ci_verified"] is True
                   and row["ci_workflow_provenance_verified"] is True
                   and row["merge_authorized"] is False
                   and row["release_eligible"] is False for row in rows):
            continue
        stale = [r for r in rows if r["current_base_verified"] is False]
        live = [r for r in rows if r["current_base_verified"] is True]
        if len(stale) != 1 or len(live) != 1:
            continue
        old, new = stale[0], live[0]
        if not equivalent(old, new, role, base):
            continue
        if admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != base:
            return None
        return {"old": old["pr"], "old_head": old["head"], "keep": new["pr"],
                "keep_head": new["head"], "role": role, "base": base}
    return None


def reconcile(*, execute=False):
    if execute and (os.getenv("GITHUB_REPOSITORY") != admission.REPO
                    or os.getenv("GITHUB_REF") != "refs/heads/main"
                    or os.getenv("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch", "push")
                    or os.getenv("GASLUX_AUTONOMY_PAUSED", "").lower().strip() != "false"):
        raise RuntimeError("Untrusted or paused duplicate reconciliation")
    picked = plan()
    if not picked:
        return {"status": "idle", "merge_authorized": False}
    if not execute:
        return {"status": "eligible_duplicate", **picked, "merge_authorized": False}
    old, keep = picked["old"], picked["keep"]
    marker = (f"<!-- GASLUX-DUPLICATE-V1:{old}:{picked['old_head']}:"
              f"{keep}:{picked['keep_head']}:{picked['base']} -->")
    comments = admission.complete_page(admission.api(
        "GET", f"/issues/{old}/comments?per_page=100"))
    if not any((c.get("user") or {}).get("id") == 41898282
               and str(c.get("body", "")).splitlines()[:1] == [marker]
               for c in comments):
        admission.api("POST", f"/issues/{old}/comments", {
            "body": marker + "\n\n"
            f"Exact-scope redundant Draft superseded by current-base #{keep}. "
            "Both exact HEADs and normal CI were checked. The source prefix, "
            "regression suite and fixed helper semantics match. Preserve all "
            "commits, branch and evidence. No approval transfer, merge or release."
        })
    if plan() != picked:
        return {"status": "drift_before_close", **picked, "merge_authorized": False}
    # GitHub has no atomic expected-head condition on the close endpoint.
    # Only a reversible PR metadata change is permitted; never delete a ref.
    result = admission.api("PATCH", f"/pulls/{old}", {"state": "closed"})
    retained = admission.api("GET", f"/pulls/{keep}")
    if (result.get("state") != "closed" or result.get("merged") is not False
            or result["head"]["sha"] != picked["old_head"]
            or retained.get("state") != "open"
            or retained["head"]["sha"] != picked["keep_head"]
            or admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != picked["base"]):
        raise RuntimeError("Concurrent metadata drift: reconcile closure manually; no ref deleted")
    return {"status": "duplicate_closed", **picked, "merge_authorized": False}


def historical_dependency(prs, number, refs):
    """Resolve an exact same-repository PR stack, without granting write authority."""
    repo = admission.REPO
    visited = set()
    chain = []
    current = number
    while True:
        if current in visited:
            return {"dependency_state": "CYCLE", "dependency_chain": chain}
        visited.add(current)
        pr = prs[current]
        head, base = pr["head"], pr["base"]
        if ((head.get("repo") or {}).get("full_name") != repo
                or (base.get("repo") or {}).get("full_name") != repo
                or not admission.valid_sha(head.get("sha"))):
            return {"dependency_state": "FOREIGN_OR_INVALID", "dependency_chain": chain}
        target = base.get("ref")
        if target in refs:
            return {"dependency_state": "ROOTED", "dependency_chain": chain,
                    "root_target": target, "root_sha": refs[target]}
        parents = [(n, row) for n, row in prs.items()
                   if (row["head"].get("repo") or {}).get("full_name") == repo
                   and row["head"].get("ref") == target]
        if len(parents) != 1:
            return {"dependency_state": "AMBIGUOUS_PARENT" if parents else "ORPHAN_BRANCH",
                    "dependency_chain": chain}
        n, parent = parents[0]
        if (not admission.valid_sha(base.get("sha"))
                or base["sha"] != parent["head"].get("sha")):
            return {"dependency_state": "PARENT_HEAD_DRIFT", "dependency_chain": chain}
        chain.append({"pr": n, "head": parent["head"]["sha"], "branch": target})
        current = n


def historical_inventory(*, slot=None):
    """Inspect a rotating bounded batch of historical PRs, never mutate."""
    api = admission.api
    refs = {name: api("GET", f"/git/ref/heads/{name}")["object"]["sha"]
            for name in ("main", "dev")}
    if not all(admission.valid_sha(sha) for sha in refs.values()):
        raise ValueError("Invalid target refs")
    prs = {}
    for page in range(1, 6):
        rows = api("GET", f"/pulls?state=open&sort=created&direction=asc&per_page=100&page={page}")
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError("Invalid historical inventory page")
        for pr in rows:
            n = pr["number"]
            if type(n) is not int or n <= 0 or n in prs or pr.get("state") != "open":
                raise ValueError("Malformed or changing historical inventory")
            prs[n] = pr
        if len(rows) < 100:
            break
    else:
        raise ValueError("Historical inventory exceeds bounded pagination")
    batch_size = 10
    ordered = sorted(prs)
    batches = max(1, (len(ordered) + batch_size - 1) // batch_size)
    index = (int(time.time()) // 900 if slot is None else slot) % batches
    findings = []
    for n in ordered[index * batch_size:(index + 1) * batch_size]:
        pr = prs[n]
        head, base = pr["head"], pr["base"]
        target, sha = base.get("ref"), head.get("sha")
        result = {"pr": n, "head": sha, "target": target, "draft": pr.get("draft"),
                  "status": "UNSUPPORTED_OR_FOREIGN", "close_authorized": False}
        if (target in refs and admission.valid_sha(sha)
                and (head.get("repo") or {}).get("full_name") == admission.REPO
                and (base.get("repo") or {}).get("full_name") == admission.REPO):
            pinned = refs[target]
            result["base"] = pinned
            diff = api("GET", f"/compare/{sha}...{pinned}")
            behind, ahead = diff.get("behind_by"), diff.get("ahead_by")
            ancestor = diff.get("merge_base_commit", {}).get("sha")
            if (diff.get("base_commit", {}).get("sha") != sha
                    or not admission.valid_sha(ancestor)
                    or type(behind) is not int or type(ahead) is not int
                    or min(behind, ahead) < 0):
                raise ValueError("Unverified historical compare")
            result["unique_head_commits"] = behind
            if (diff.get("status") in ("ahead", "identical") and behind == 0
                    and ancestor == sha):
                result["status"] = "ANCESTRY_PRESENT_REVIEW_CLOSURE"
            elif behind > 0:
                result["status"] = "UNIQUE_COMMITS_REQUIRE_RECONCILIATION"
            else:
                result["status"] = "UNVERIFIED_RELATION"
        dependency = historical_dependency(prs, n, refs)
        result.update(dependency)
        if (result["status"] == "UNSUPPORTED_OR_FOREIGN"
                and dependency["dependency_state"] == "ROOTED"
                and dependency["dependency_chain"]):
            result["status"] = "STACKED_PR_REQUIRES_PARENT_RECONCILIATION"
        findings.append(result)
    if any(api("GET", f"/git/ref/heads/{name}")["object"]["sha"] != sha
           for name, sha in refs.items()):
        raise ValueError("Target drift during historical inventory")
    return {"schema": "gaslux-historical-reconciliation-v1", "read_only": True,
            "merge_authorized": False, "close_authorized": False,
            "total_open": len(ordered), "batch": index, "batches": batches,
            "refs": refs, "findings": findings}


def historical_close_candidate(row):
    """Proven integrated ancestry or identical complete tree; no unresolved discussion."""
    unique = row.get("unique_head_commits")
    ancestry = row.get("status") == "ANCESTRY_PRESENT_REVIEW_CLOSURE" and unique == 0
    squash = (row.get("status") == "UNIQUE_COMMITS_REQUIRE_RECONCILIATION"
              and type(unique) is int and unique > 0)
    if (not (ancestry or squash) or row.get("target") not in ("dev", "main")
            or row.get("draft") is not True):
        return False
    n, head, base, target = row["pr"], row["head"], row["base"], row["target"]
    if type(n) is not int or not 1 <= n <= 1000000 or not all(
            admission.valid_sha(s) for s in (head, base)):
        return False
    api = admission.api
    pr = api("GET", f"/pulls/{n}")
    if (pr.get("state") != "open" or pr.get("draft") is not True
            or pr.get("merged") is not False or pr.get("requested_reviewers")
            or pr.get("requested_teams")
            or not admission.publisher_ok(pr.get("user") or {})
            or pr["head"]["sha"] != head or pr["base"]["ref"] != target
            or pr["head"]["repo"]["full_name"] != admission.REPO
            or pr["base"]["repo"]["full_name"] != admission.REPO
            or api("GET", f"/git/ref/heads/{target}")["object"]["sha"] != base):
        return False
    relation = api("GET", f"/compare/{head}...{base}")
    if ancestry:
        if (relation.get("status") not in ("ahead", "identical")
                or relation.get("behind_by") != 0
                or relation.get("merge_base_commit", {}).get("sha") != head):
            return False
    elif (relation.get("status") not in ("behind", "diverged")
          or relation.get("behind_by") != unique
          or not admission.valid_sha(relation.get("merge_base_commit", {}).get("sha"))):
        return False
    a = api("GET", f"/git/commits/{head}")["tree"]["sha"]
    b = api("GET", f"/git/commits/{base}")["tree"]["sha"]
    if not admission.valid_sha(a) or not admission.valid_sha(b):
        return False
    if a != b:
        # With distinct history, exact complete tree equality is mandatory.
        # Squash-equivalent commits are not proof that differing trees are redundant.
        if squash:
            return False
        # Later legitimate dev changes need not reproduce the entire old tree.
        # Require GitHub to report zero remaining PR files as well as ancestry.
        if type(pr.get("changed_files")) is not int or pr["changed_files"] != 0:
            return False
        if admission.complete_page(api("GET", f"/pulls/{n}/files?per_page=100")):
            return False
    # Unresolved historical findings may live in discussion rather than code.
    # Any existing review, inline comment or issue comment defers closure.
    for endpoint in (f"/pulls/{n}/reviews?per_page=100",
                     f"/pulls/{n}/comments?per_page=100",
                     f"/issues/{n}/comments?per_page=100"):
        if admission.complete_page(api("GET", endpoint)):
            return False
    return True


def close_integrated_history(*, execute=False):
    if execute and (os.getenv("GITHUB_REPOSITORY") != admission.REPO
                    or os.getenv("GITHUB_REF") != "refs/heads/main"
                    or os.getenv("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch", "push")
                    or os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() != "false"):
        raise RuntimeError("Untrusted or paused historical reconciliation")
    report = historical_inventory()
    for row in report["findings"]:
        if not historical_close_candidate(row):
            continue
        n, head, base, target = row["pr"], row["head"], row["base"], row["target"]
        receipt = {"pr": n, "head": head, "base": base, "target": target,
                   "merge_authorized": False, "refs_deleted": False,
                   "equivalence": ("identical_full_tree_distinct_history" if
                                   row["status"] == "UNIQUE_COMMITS_REQUIRE_RECONCILIATION"
                                   else "integrated_ancestry")}
        if not execute:
            return {"status": "eligible_exact_history", **receipt}
        if not historical_close_candidate(row):
            return {"status": "history_drift_before_close", **receipt}
        # REST close has no atomic expected-head argument. Never delete refs;
        # verify metadata and report concurrency drift rather than conceal it.
        api = admission.api
        closed = api("PATCH", f"/pulls/{n}", {"state": "closed"})
        if (closed.get("state") != "closed" or closed.get("merged") is not False
                or closed.get("head", {}).get("sha") != head
                or api("GET", f"/git/ref/heads/{target}")["object"]["sha"] != base):
            raise RuntimeError("Historical closure drift; manual reconciliation required")
        return {"status": "exact_history_closed", **receipt}
    return {"status": "no_exact_history_closure", "merge_authorized": False,
            "pending_reconciliation": [r for r in report["findings"]
                                       if r["status"] == "UNIQUE_COMMITS_REQUIRE_RECONCILIATION"]}


def main():
    cli = argparse.ArgumentParser()
    modes = cli.add_mutually_exclusive_group()
    modes.add_argument("--execute", action="store_true")
    modes.add_argument("--historical-inventory", action="store_true")
    modes.add_argument("--close-integrated-history", action="store_true")
    args = cli.parse_args()
    report = (close_integrated_history(execute=True) if args.close_integrated_history else
              historical_inventory() if args.historical_inventory else reconcile(execute=args.execute))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
