#!/usr/bin/env python3
"""Read-only candidate admission evidence. Never authorizes a distro merge."""
from __future__ import annotations

import base64
import json
import os
import re

from gaslux_agent_feature_factory import TASKS, validate_addition
from gaslux_agent_integrate import REPO, SHA, api

QUEUE = {395: "zorin", 400: "bazzite", 411: "cachyos", 412: "popos", 413: "q4os"}
BOTS = {"github-actions[bot]", "gaslux-autonomous-publisher[bot]"}
COMMON_CHECKS = {
    "evidence-python", "evidence-powershell",
    "Windows recovery evidence rules (fixtures only)",
}


def complete_page(value):
    # A full first page may conceal objections or additional changes.
    if not isinstance(value, list) or len(value) >= 100:
        raise ValueError("Incomplete or invalid GitHub page")
    return value


def valid_sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def source_at(path, ref):
    if not valid_sha(ref):
        raise ValueError("Invalid source ref")
    obj = api("GET", f"/contents/{path}?ref={ref}")
    if obj.get("type") != "file" or obj.get("encoding") != "base64":
        raise ValueError("Unexpected source object")
    raw = base64.b64decode("".join(obj["content"].split()), validate=True)
    if len(raw) > 32000 or b"\r" in raw or b"\x00" in raw:
        raise ValueError("Unexpected source bytes")
    return raw


def exact_append(before, after, role):
    prefix = before.rstrip(b"\n") + b"\n\n"
    signature = f"def assess_{role}_lifecycle(".encode()
    if len(before) > 25000 or signature in before or not after.startswith(prefix):
        raise ValueError("Not a single new append")
    addition = after[len(prefix):].decode("utf-8")
    if after != prefix + addition.rstrip().encode("utf-8") + b"\n":
        raise ValueError("Noncanonical append")
    validate_addition(role, addition.rstrip(), execute=False)


def checks_ok(response, head, role):
    rows = complete_page(response.get("check_runs"))
    required = COMMON_CHECKS | (
        {"python-contracts", "windows-contracts"} if role == "cachyos"
        else {"read-only-contracts"}
    )
    if type(response.get("total_count")) is not int or response["total_count"] != len(rows):
        return False
    if any(row.get("head_sha") != head
           or row.get("status") != "completed"
           or row.get("conclusion") != "success"
           for row in rows):
        return False
    names = {row.get("name") for row in rows
             if row.get("app", {}).get("slug") == "github-actions"}
    return required <= names


def review_ok(reviews, reviewer_id, author_id, head, dev):
    if (type(reviewer_id) is not int or reviewer_id <= 0
            or type(author_id) is not int or reviewer_id == author_id):
        return False
    rows = complete_page(reviews)
    if any(row.get("state") == "CHANGES_REQUESTED" for row in rows):
        return False
    own = [row for row in rows if row.get("user", {}).get("id") == reviewer_id
           and row.get("state") != "COMMENTED"]
    if not own:
        return False
    # Require all approval-bearing records to match the exact current tuple.
    # Stale or dismissed reviews fail closed and require explicit reconciliation.
    marker = f"GASLUX-SAFETY-V1 head={head} base={dev}"
    return all(row.get("state") == "APPROVED"
               and row.get("commit_id") == head
               and marker in str(row.get("body", "")).splitlines()
               for row in own)


def inspect(number, role, reviewer_id):
    out = {"pr": number, "role": role, "head": None, "base": None,
           "exact_scope_verified": False, "current_base_verified": False,
           "ci_verified": False, "safety_review_verified": False,
           "backend_owner_verified": False, "full_vm_acceptance_verified": False,
           "merge_authorized": False, "release_eligible": False}
    try:
        pr = api("GET", f"/pulls/{number}")
        head, base = pr["head"], pr["base"]
        sha = head["sha"]
        dev = api("GET", "/git/ref/heads/dev")["object"]["sha"]
        if not valid_sha(sha) or not valid_sha(dev):
            raise ValueError("Malformed SHA")
        out.update(head=sha, base=dev)
        if (pr.get("number") != number or pr.get("state") != "open"
                or pr.get("draft") is not True or pr.get("user", {}).get("login") not in BOTS
                or head["repo"]["full_name"] != REPO or base["repo"]["full_name"] != REPO
                or base["ref"] != "dev"):
            raise ValueError("Candidate identity mismatch")
        parents = api("GET", f"/git/commits/{sha}")["parents"]
        if len(parents) != 1 or not valid_sha(parents[0].get("sha")):
            raise ValueError("Unexpected ancestry")
        original = parents[0]["sha"]
        if head["ref"] != f"bot/gaslux-feature-{role}-{original[:12]}":
            raise ValueError("Branch identity mismatch")
        out["current_base_verified"] = original == dev
        files = complete_page(api("GET", f"/pulls/{number}/files?per_page=100"))
        path = TASKS[role][0]
        if (len(files) != 1 or files[0].get("filename") != path
                or files[0].get("status") != "modified"
                or files[0].get("previous_filename") is not None
                or files[0].get("deletions") != 0
                or type(files[0].get("additions")) is not int
                or not 1 <= files[0]["additions"] <= 101):
            raise ValueError("Candidate exceeds append-only scope")
        exact_append(source_at(path, original), source_at(path, sha), role)
        out["exact_scope_verified"] = True
        out["ci_verified"] = checks_ok(
            api("GET", f"/commits/{sha}/check-runs?per_page=100"), sha, role)
        reviews = api("GET", f"/pulls/{number}/reviews?per_page=100")
        out["safety_review_verified"] = review_ok(reviews, reviewer_id, pr["user"]["id"], sha, dev)
        comments = complete_page(api("GET", f"/issues/{number}/comments?per_page=100"))
        if any(marker in str(row.get("body", "")).upper()
               for row in comments for marker in ("SAFETY_DENIED", "BLOCKED_SAFETY", "DO_NOT_MERGE")):
            out["safety_review_verified"] = False
        if (api("GET", "/git/ref/heads/dev")["object"]["sha"] != dev
                or api("GET", f"/pulls/{number}")["head"]["sha"] != sha):
            raise ValueError("Candidate changed during inspection")
        out["status"] = "blocked"
        out["reason"] = "Backend-owner and full-VM evidence not authenticated; merge disabled"
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError, SyntaxError):
        for key in out:
            if key.endswith("_verified"):
                out[key] = False
        out["status"] = "blocked"
        out["reason"] = "Identity, scope or API validation failed"
    return out


def main():
    raw = os.getenv("GASLUX_SAFETY_REVIEWER_ID", "")
    reviewer = int(raw) if re.fullmatch(r"[1-9][0-9]{0,18}", raw) else None
    report = {"schema": "gaslux-distro-admission-v1", "read_only": True,
              "reviewer_configured": reviewer is not None,
              "candidates": [inspect(n, role, reviewer) for n, role in QUEUE.items()]}
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
