#!/usr/bin/env python3
"""Inspect generated supervised scopes without executing candidate files."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gaslux_agent_feature_factory as factory
import gaslux_distro_admission as admission

BRANCH = re.compile(r"bot/gaslux-(test|pins)-(mint|zorin|cachyos|popos|q4os|bazzite)-[0-9a-f]{12}")


def discover():
    rows = admission.complete_page(admission.api(
        "GET", "/pulls?state=open&base=dev&per_page=100"))
    result = {}
    for pr in rows:
        head, base = pr["head"], pr["base"]
        branch = head.get("ref")
        match = BRANCH.fullmatch(branch) if isinstance(branch, str) else None
        if not match or (head.get("repo") or {}).get("full_name") != admission.REPO:
            continue
        kind, role = match.groups()
        scope = factory.SUPERVISED_TEST_SCOPE if kind == "test" else factory.SUPERVISED_MEDIA_SCOPE
        number = pr.get("number")
        if (type(number) is not int or not 1 <= number <= 1000000 or number in result
                or (base.get("repo") or {}).get("full_name") != admission.REPO
                or base.get("ref") != "dev" or not admission.valid_sha(head.get("sha"))):
            raise ValueError("Malformed supervised inventory")
        result[number] = (role, scope, head["sha"])
    if len(result) > 16:
        raise ValueError("Supervised candidate inventory exceeds bound")
    return result


def canonical_scope(pr, role, scope, head):
    if pr.get("commits") != 1:
        raise ValueError("Supervised proposal is not a single append")
    parent = admission.single_parent(head)
    if pr["head"]["ref"] != factory.supervised_branch(role, parent, scope):
        raise ValueError("Supervised branch mismatch")
    path = factory.scope_target(role, scope)
    admission.one_path_commit(parent, head, path)
    # Materialize only fixed, bounded files as data; never import any candidate
    # or source module into this token-bearing admission process.
    source, suite, _ = factory.TASKS[role]
    paths = {source, "auto_tests/tests/" + suite}
    if scope == factory.SUPERVISED_MEDIA_SCOPE:
        paths.add("release-config.json")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in paths:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(admission.source_at(name, parent))
        addition = factory.supervised_addition(role, scope)
        before, expected = factory.expected_source(root, role, addition, scope=scope)
        if admission.source_at(path, head) != expected or not before:
            raise ValueError("Candidate differs from exact canonical scoped append")
    return parent


def inspect(number, role, scope, head, reviewer=None, owner=None, *, allow_ready=False):
    row = {"pr": number, "role": role, "scope": scope, "head": head,
           "base": None, "exact_scope_verified": False, "current_base_verified": False,
           "ci_workflow_provenance_verified": False, "ci_verified": False,
           "technical_objection": None, "safety_review_verified": False,
           "backend_owner_verified": False, "merge_authorized": False,
           "release_eligible": False, "next_action": "VERIFY_SUPERVISED_SCOPE"}
    try:
        if not admission.valid_sha(head) or role not in factory.TASKS or scope not in factory.SUPERVISED_SCOPES:
            raise ValueError("Unknown supervised scope")
        pr = admission.api("GET", f"/pulls/{number}")
        base = admission.api("GET", "/git/ref/heads/dev")["object"]["sha"]
        row["base"] = base
        if (not admission.valid_sha(base) or pr.get("number") != number
                or pr.get("state") != "open"
                or (pr.get("draft") is not True and not (allow_ready and pr.get("draft") is False))
                or not admission.publisher_ok(pr.get("user") or {})
                or pr["head"]["sha"] != head or pr["base"]["ref"] != "dev"
                or pr["head"]["repo"]["full_name"] != admission.REPO
                or pr["base"]["repo"]["full_name"] != admission.REPO):
            raise ValueError("Supervised candidate identity mismatch")
        parent = canonical_scope(pr, role, scope, head)
        row["exact_scope_verified"] = True
        row["current_base_verified"] = parent == base
        row["ci_workflow_provenance_verified"] = admission.ci_workflow_provenance(
            head, role, supervised=True)
        row["ci_verified"] = row["ci_workflow_provenance_verified"] and admission.checks_ok(
            admission.api("GET", f"/commits/{head}/check-runs?per_page=100"), head, role)
        reviews = admission.complete_page(admission.api(
            "GET", f"/pulls/{number}/reviews?per_page=100"))
        comments = admission.complete_page(admission.api(
            "GET", f"/issues/{number}/comments?per_page=100"))
        hold = ("SAFETY_DENIED", "BLOCKED_SAFETY", "DO_NOT_MERGE", "SAFETY HOLD", "SECURITY HOLD")
        row["technical_objection"] = (any(r.get("state") == "CHANGES_REQUESTED" for r in reviews)
                                      or any(m in str(c.get("body", "")).upper()
                                             for m in hold for c in comments))
        if not row["technical_objection"]:
            author = pr["user"]["id"]
            row["safety_review_verified"] = admission.review_ok(reviews, reviewer, author, head, base)
            row["backend_owner_verified"] = admission.owner_review_ok(
                reviews, owner, reviewer, author, None, role, head, base, supervised=True)
        if (admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != base
                or admission.api("GET", f"/pulls/{number}")["head"]["sha"] != head):
            raise ValueError("Candidate drift during inspection")
        row["next_action"] = (
            "RESOLVE_TECHNICAL_OBJECTION" if row["technical_objection"] else
            "REFRESH_SUPERVISED_SCOPE" if not row["current_base_verified"] else
            "WAIT_OR_REPAIR_SCOPE_CI" if not row["ci_verified"] else
            "INDEPENDENT_SAFETY_REVIEW" if not row["safety_review_verified"] else
            "BACKEND_OWNER_REVIEW" if not row["backend_owner_verified"] else
            "COLLECT_VM_EVIDENCE" if scope == factory.SUPERVISED_MEDIA_SCOPE else
            "TEST_ONLY_INTEGRATION_ELIGIBLE"
        )
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError, SyntaxError):
        for key in row:
            if key.endswith("_verified"):
                row[key] = False
        row["technical_objection"] = None
        row["next_action"] = "VERIFY_SUPERVISED_SCOPE"
    return row


def configured_reviewers():
    raw = os.getenv("GASLUX_SAFETY_REVIEWER_ID", "")
    reviewer = int(raw) if re.fullmatch(r"[1-9][0-9]{0,18}", raw) else None
    owners = admission.parse_owner_ids(
        os.getenv("GASLUX_SUPERVISED_OWNER_IDS") or os.getenv("GASLUX_BACKEND_OWNER_IDS", ""),
        allowed_roles=factory.TASKS)
    return reviewer, owners


def inventory():
    reviewer, owners = configured_reviewers()
    try:
        candidates = discover()
        return {"schema": "gaslux-supervised-admission-v1", "inventory_verified": True,
                "merge_authorized": False, "release_eligible": False,
                "candidates": [inspect(n, role, scope, head, reviewer, owners.get(role))
                               for n, (role, scope, head) in candidates.items()]}
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError):
        return {"schema": "gaslux-supervised-admission-v1", "inventory_verified": False,
                "merge_authorized": False, "release_eligible": False, "candidates": []}


def eligible_test(row):
    """A read-only receipt is never merge authority on its own."""
    return (
        row.get("scope") == factory.SUPERVISED_TEST_SCOPE
        and row.get("next_action") == "TEST_ONLY_INTEGRATION_ELIGIBLE"
        and all(row.get(key) is True for key in (
            "exact_scope_verified", "current_base_verified",
            "ci_workflow_provenance_verified", "ci_verified",
            "safety_review_verified", "backend_owner_verified"))
        and row.get("technical_objection") is False
        and admission.valid_sha(row.get("head"))
        and admission.valid_sha(row.get("base"))
    )


# REST merge only pins the PR head. Require GitHub to enforce strict
# up-to-date checks on dev itself; a client-side GET is not a base lock.
STRICT_DEV_QUERY = """
query {
  repository(owner: "LMhdez", name: "gaslux") {
    nameWithOwner
    ref(qualifiedName: "refs/heads/dev") {
      name
      prefix
      target { oid }
      branchProtectionRule {
        isAdminEnforced
        requiresStatusChecks
        requiresStrictStatusChecks
        requiredStatusCheckContexts
        allowsForcePushes
        allowsDeletions
        bypassPullRequestAllowances(first: 1) { totalCount }
        bypassForcePushAllowances(first: 1) { totalCount }
      }
      refUpdateRule {
        requiredStatusCheckContexts
        allowsForcePushes
        allowsDeletions
      }
    }
  }
}
"""


def strict_dev_protected(base):
    """Read effective server policy with the same token used to merge.

    Unknown, missing, unreadable or bypassable policy is not merge authority.
    The safety argument assumes trusted admins do not disable the rules during
    integration; the server rejects concurrent ordinary updates to dev.
    """
    try:
        if not admission.valid_sha(base):
            return False
        raw = subprocess.run(
            ["gh", "api", "graphql", "-f", "query=" + STRICT_DEV_QUERY],
            check=True, timeout=30, capture_output=True,
        ).stdout
        if len(raw) > 65536:
            return False
        data = json.loads(raw)
        if data.get("errors"):
            return False
        repo = data["data"]["repository"]
        ref = repo["ref"]
        rule, effective = ref["branchProtectionRule"], ref["refUpdateRule"]
        checks = rule["requiredStatusCheckContexts"]
        enforced = effective["requiredStatusCheckContexts"]
        return (
            repo["nameWithOwner"] == admission.REPO
            and ref["name"] == "dev" and ref["prefix"] == "refs/heads/"
            and ref["target"]["oid"] == base
            and all(rule[k] is True for k in (
                "isAdminEnforced", "requiresStatusChecks", "requiresStrictStatusChecks"))
            and all(rule[k] is False and effective[k] is False for k in (
                "allowsForcePushes", "allowsDeletions"))
            and all(type(rule[k]["totalCount"]) is int and rule[k]["totalCount"] == 0
                    for k in ("bypassPullRequestAllowances", "bypassForcePushAllowances"))
            and type(checks) is list and 0 < len(checks) <= 100
            and all(type(x) is str and x.strip() for x in checks)
            and type(enforced) is list and set(checks) <= set(enforced)
        )
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError):
        return False


def integrate_one():
    """Trusted-main-only bounded integration, never executes candidate code."""
    if (os.getenv("GITHUB_REPOSITORY") != admission.REPO
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch", "push")
            or os.getenv("GASLUX_AUTONOMY_PAUSED", "").lower() == "true"):
        raise ValueError("Untrusted integration context")
    reviewer, owners = configured_reviewers()
    for number, (role, scope, head) in sorted(discover().items()):
        if scope != factory.SUPERVISED_TEST_SCOPE:
            continue
        row = inspect(number, role, scope, head, reviewer, owners.get(role), allow_ready=True)
        if not eligible_test(row):
            continue
        base = row["base"]
        if not strict_dev_protected(base):
            return {"status": "strict_base_protection_required", "pr": number, "head": head}
        pr = admission.api("GET", f"/pulls/{number}")
        if pr["head"]["sha"] != head or pr["base"]["sha"] != base:
            raise ValueError("Candidate drift before ready")
        if pr.get("draft") is True:
            # No candidate code, no shell interpolation, fixed repository.
            subprocess.run(["gh", "pr", "ready", str(number), "--repo", admission.REPO],
                           check=True, timeout=60)
        checked = inspect(number, role, scope, head, reviewer, owners.get(role), allow_ready=True)
        if not eligible_test(checked) or checked["base"] != base:
            return {"status": "drift_before_merge", "pr": number, "head": head}
        pr = admission.api("GET", f"/pulls/{number}")
        if (pr.get("draft") is not False or pr.get("mergeable_state") != "clean"
                or pr["head"]["sha"] != head or pr["base"]["sha"] != base
                or admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != base):
            return {"status": "waiting_for_github", "pr": number, "head": head}
        if not strict_dev_protected(base):
            return {"status": "strict_base_protection_required", "pr": number, "head": head}
        # Do not retry with an updated base or bypass protection. A concurrent
        # dev advance makes the exact single-parent head out of date; GitHub's
        # strict rule must reject this request at merge time.
        result = admission.api("PUT", f"/pulls/{number}/merge",
                               {"sha": head, "merge_method": "squash"})
        if result.get("merged") is not True or not admission.valid_sha(result.get("sha")):
            raise RuntimeError("GitHub did not confirm merge")
        if admission.single_parent(result["sha"]) != base:
            raise RuntimeError("Merged commit parent differs from reviewed base; investigate")
        merged_tree = admission.api("GET", f"/git/commits/{result['sha']}")["tree"]["sha"]
        reviewed_tree = admission.api("GET", f"/git/commits/{head}")["tree"]["sha"]
        if not admission.valid_sha(merged_tree) or merged_tree != reviewed_tree:
            raise RuntimeError("Merged tree differs from reviewed tree; investigate")
        return {"status": "merged", "pr": number, "head": head,
                "reviewed_base": base, "merge_sha": result["sha"],
                "strict_base_protection_verified": True, "reviewed_tree_verified": True}
    return {"status": "idle"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--integrate-test", action="store_true")
    args = parser.parse_args()
    print(json.dumps(integrate_one() if args.integrate_test else inventory(),
                     indent=2, sort_keys=True))
