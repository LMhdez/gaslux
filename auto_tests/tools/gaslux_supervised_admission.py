#!/usr/bin/env python3
"""Inspect generated supervised scopes without executing candidate files."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
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


def inspect(number, role, scope, head, reviewer=None, owner=None):
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
                or pr.get("state") != "open" or pr.get("draft") is not True
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
            "TEST_ONLY_INTEGRATION_POLICY_REQUIRED"
        )
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError, SyntaxError):
        for key in row:
            if key.endswith("_verified"):
                row[key] = False
        row["technical_objection"] = None
        row["next_action"] = "VERIFY_SUPERVISED_SCOPE"
    return row


def inventory():
    raw = os.getenv("GASLUX_SAFETY_REVIEWER_ID", "")
    reviewer = int(raw) if re.fullmatch(r"[1-9][0-9]{0,18}", raw) else None
    owners = admission.parse_owner_ids(os.getenv("GASLUX_BACKEND_OWNER_IDS", ""),
                                      allowed_roles=factory.TASKS)
    try:
        candidates = discover()
        return {"schema": "gaslux-supervised-admission-v1", "inventory_verified": True,
                "merge_authorized": False, "release_eligible": False,
                "candidates": [inspect(n, role, scope, head, reviewer, owners.get(role))
                               for n, (role, scope, head) in candidates.items()]}
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError):
        return {"schema": "gaslux-supervised-admission-v1", "inventory_verified": False,
                "merge_authorized": False, "release_eligible": False, "candidates": []}


if __name__ == "__main__":
    print(json.dumps(inventory(), indent=2, sort_keys=True))
