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
from urllib.parse import quote

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


def historical_ancestor(ancestor, descendant):
    """Prove commit containment without trusting branch names or diff summaries."""
    if not all(admission.valid_sha(s) for s in (ancestor, descendant)):
        return False
    relation = admission.api("GET", f"/compare/{ancestor}...{descendant}")
    return (relation.get("base_commit", {}).get("sha") == ancestor
            and relation.get("merge_base_commit", {}).get("sha") == ancestor
            and relation.get("status") in ("ahead", "identical")
            and type(relation.get("behind_by")) is int
            and relation["behind_by"] == 0)


def historical_merged_parent(branch, head, refs):
    """Follow bounded, proven merged-parent chains to a pinned production root.

    The first parent requires exact head identity. Each subsequent parent
    must contain the previous merge commit in its own reviewed head history.
    Squash/rebase at a later step is acceptable only with a fresh proof of
    the resulting merge commit's ancestry. This is a replay hint, not authority.
    """
    if (not isinstance(branch, str) or not 1 <= len(branch) <= 255
            or not admission.valid_sha(head)):
        return {"dependency_state": "INVALID_CLOSED_PARENT_QUERY"}
    owner = admission.REPO.split("/", 1)[0]
    chain, visited = [], set()
    first = True
    required = head
    for _ in range(8):
        if branch in visited:
            return {"dependency_state": "CLOSED_PARENT_CYCLE", "closed_chain": chain}
        visited.add(branch)
        query = quote(owner + ":" + branch, safe="")
        rows = admission.complete_page(admission.api(
            "GET", f"/pulls?state=closed&head={query}&per_page=100"))
        matches = []
        for row in rows:
            h, b = row.get("head") or {}, row.get("base") or {}
            if (h.get("ref") == branch and admission.valid_sha(h.get("sha"))
                    and (h.get("repo") or {}).get("full_name") == admission.REPO
                    and (b.get("repo") or {}).get("full_name") == admission.REPO):
                matches.append(row)
        if first:
            matches = [row for row in matches if row["head"]["sha"] == required]
        else:
            if len(matches) > 8:
                return {"dependency_state": "CLOSED_PARENT_LOOKUP_LIMIT", "closed_chain": chain}
            matches = [row for row in matches
                       if historical_ancestor(required, row["head"]["sha"])]
        if not matches:
            return {"dependency_state": "ORPHAN_BRANCH" if first else "CLOSED_PARENT_ROOT_UNVERIFIED",
                    "closed_chain": chain}
        if len(matches) != 1:
            return {"dependency_state": "AMBIGUOUS_CLOSED_PARENT", "closed_chain": chain}
        number, expected_head = matches[0].get("number"), matches[0]["head"]["sha"]
        if type(number) is not int or not 1 <= number <= 1000000:
            return {"dependency_state": "INVALID_CLOSED_PARENT", "closed_chain": chain}
        parent = admission.api("GET", f"/pulls/{number}")
        h, b = parent.get("head") or {}, parent.get("base") or {}
        target, merge = b.get("ref"), parent.get("merge_commit_sha")
        if (parent.get("number") != number or parent.get("state") != "closed"
                or h.get("ref") != branch or h.get("sha") != expected_head
                or (h.get("repo") or {}).get("full_name") != admission.REPO
                or (b.get("repo") or {}).get("full_name") != admission.REPO):
            return {"dependency_state": "CLOSED_PARENT_DRIFT", "closed_chain": chain}
        if parent.get("merged") is not True:
            return {"dependency_state": "CLOSED_PARENT_NOT_MERGED", "closed_parent": number,
                    "closed_chain": chain}
        if not admission.valid_sha(merge) or not isinstance(target, str) or not 1 <= len(target) <= 255:
            return {"dependency_state": "CLOSED_PARENT_ROOT_UNVERIFIED", "closed_parent": number,
                    "closed_chain": chain}
        chain.append({"pr": number, "head": expected_head, "branch": branch,
                      "merge": merge, "target": target})
        if target in refs:
            root = refs[target]
            if not historical_ancestor(merge, root):
                return {"dependency_state": "CLOSED_PARENT_ROOT_UNVERIFIED", "closed_parent": number,
                        "closed_chain": chain}
            return {"dependency_state": "MERGED_PARENT_REPLAY_REQUIRED",
                    "closed_parent": chain[0]["pr"], "closed_parent_head": head,
                    "parent_merge_commit": chain[0]["merge"], "closed_chain": chain,
                    "root_target": target, "root_sha": root}
        branch, required, first = target, merge, False
    return {"dependency_state": "CLOSED_PARENT_DEPTH_LIMIT", "closed_chain": chain}


def historical_dependency(prs, number, refs, *, closed_lookup=None):
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
        if not parents and closed_lookup is not None:
            return {**closed_lookup(target, base.get("sha"), refs), "dependency_chain": chain}
        if len(parents) != 1:
            return {"dependency_state": "AMBIGUOUS_PARENT" if parents else "ORPHAN_BRANCH",
                    "dependency_chain": chain}
        n, parent = parents[0]
        if (not admission.valid_sha(base.get("sha"))
                or base["sha"] != parent["head"].get("sha")):
            return {"dependency_state": "PARENT_HEAD_DRIFT", "dependency_chain": chain}
        chain.append({"pr": n, "head": parent["head"]["sha"], "branch": target})
        current = n


def historical_replay_hint(row):
    """Pin the source diff range and destination for isolated replay, never execute it.

    A closed stack may be replayed only after its immediate predecessor and
    all closed ancestors are proven integrated. Open predecessors must be
    resolved first. The resulting range is evidence, not a merge permission.
    """
    direct = row.get("status") == "UNIQUE_COMMITS_REQUIRE_RECONCILIATION"
    stacked = (row.get("status") == "STACKED_PR_REPLAY_ON_ROOT_REQUIRED"
               and row.get("dependency_state") == "MERGED_PARENT_REPLAY_REQUIRED"
               and row.get("dependency_chain") == [])
    if not (direct or stacked):
        return None
    denied = {"status": "REPLAY_RANGE_UNVERIFIED", "merge_authorized": False,
              "close_authorized": False}
    n, head = row.get("pr"), row.get("head")
    target = row.get("root_target")
    root = row.get("root_sha")
    if (type(n) is not int or not 1 <= n <= 1000000
            or target not in ("main", "dev")
            or not all(admission.valid_sha(s) for s in (head, root))):
        return denied
    if direct:
        expected_base = root
        if row.get("target") != target or row.get("base") != root:
            return denied
    else:
        chain = row.get("closed_chain")
        if not isinstance(chain, list) or not chain or not isinstance(chain[0], dict):
            return denied
        parent = chain[0]
        expected_base = parent.get("head")
        if (parent.get("branch") != row.get("target")
                or expected_base != row.get("closed_parent_head")
                or not admission.valid_sha(expected_base)):
            return denied
    api = admission.api
    pr = api("GET", f"/pulls/{n}")
    h, b = pr.get("head") or {}, pr.get("base") or {}
    if (pr.get("number") != n or pr.get("state") != "open"
            or h.get("sha") != head or b.get("ref") != row.get("target")
            or b.get("sha") != expected_base
            or any((x.get("repo") or {}).get("full_name") != admission.REPO
                   for x in (h, b))):
        return denied
    relation = api("GET", f"/compare/{expected_base}...{head}")
    start = (relation.get("merge_base_commit") or {}).get("sha")
    ahead, behind = relation.get("ahead_by"), relation.get("behind_by")
    if ((relation.get("base_commit") or {}).get("sha") != expected_base
            or not admission.valid_sha(start)
            or relation.get("status") not in ("ahead", "diverged")
            or type(ahead) is not int or ahead <= 0
            or type(behind) is not int or behind < 0
            or (relation["status"] == "ahead" and (start != expected_base or behind != 0))
            or (relation["status"] == "diverged" and (start == expected_base or behind == 0))
            or (direct and (type(row.get("unique_head_commits")) is not int
                            or row["unique_head_commits"] != ahead))
            or (stacked and (start != expected_base or behind != 0))):
        return denied
    # Bind actual immutable Git tree objects, rather than a potentially
    # truncated GitHub file/commit listing or an untrusted PR description.
    trees = {}
    for sha in dict.fromkeys((start, head, root)):
        commit = api("GET", f"/git/commits/{sha}")
        tree = (commit.get("tree") or {}).get("sha")
        if commit.get("sha") != sha or not admission.valid_sha(tree):
            return denied
        trees[sha] = tree
    if trees[start] == trees[head]:
        return {**denied, "status": "EMPTY_SOURCE_DIFF_REQUIRES_REVIEW"}
    # A second exact observation detects drift during evidence collection.
    observed = api("GET", f"/pulls/{n}")
    oh, ob = observed.get("head") or {}, observed.get("base") or {}
    if (observed.get("number") != n or observed.get("state") != "open"
            or oh.get("sha") != head or ob.get("sha") != expected_base
            or ob.get("ref") != row.get("target")
            or any((x.get("repo") or {}).get("full_name") != admission.REPO
                   for x in (oh, ob))
            or api("GET", f"/git/ref/heads/{target}")["object"]["sha"] != root):
        return denied
    return {**denied, "status": "ISOLATED_REPLAY_REQUIRED", "pr": n,
            "source_base": start, "source_head": head, "source_base_tree": trees[start],
            "source_head_tree": trees[head], "target": target, "target_head": root,
            "target_tree": trees[root], "unique_source_commits": ahead,
            "fresh_ci_and_safety_required": True}


def historical_inventory(*, slot=None, include_replay=False):
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
    closed_cache = {}

    def closed_lookup(branch, head, targets):
        key = (branch, head)
        if key not in closed_cache:
            closed_cache[key] = historical_merged_parent(branch, head, targets)
        return closed_cache[key]

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
        dependency = historical_dependency(prs, n, refs, closed_lookup=closed_lookup)
        result.update(dependency)
        if (result["status"] == "UNSUPPORTED_OR_FOREIGN"
                and dependency["dependency_state"] == "ROOTED"
                and dependency["dependency_chain"]):
            result["status"] = "STACKED_PR_REQUIRES_PARENT_RECONCILIATION"
        if (result["status"] == "UNSUPPORTED_OR_FOREIGN"
                and dependency["dependency_state"] == "MERGED_PARENT_REPLAY_REQUIRED"):
            result["status"] = "STACKED_PR_REPLAY_ON_ROOT_REQUIRED"
        if include_replay:
            hint = historical_replay_hint(result)
            if hint is not None:
                result["replay"] = hint
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
              historical_inventory(include_replay=True) if args.historical_inventory else reconcile(execute=args.execute))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
