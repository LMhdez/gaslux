#!/usr/bin/env python3
"""Read-only candidate admission evidence. Never authorizes a distro merge."""
from __future__ import annotations

import ast
import base64
import json
import os
import re

from gaslux_agent_feature_factory import TASKS, validate_addition
from gaslux_agent_integrate import REPO, SHA, api

QUEUE = {395: "zorin", 400: "bazzite", 411: "cachyos", 412: "popos", 413: "q4os"}
BOTS = {"github-actions[bot]": 41898282,
        "gaslux-autonomous-publisher[bot]": 360620437}
ROLES = frozenset(QUEUE.values())
MAX_CANDIDATES = 10
BRANCH = re.compile(r"bot/gaslux-feature-([a-z0-9]+)-([0-9a-f]{12})")
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


def publisher_ok(user):
    login, actor = user.get("login"), user.get("id")
    return (isinstance(login, str) and login in BOTS
            and type(actor) is int and actor == BOTS[login])


def discover_candidates():
    """Find new bot proposals without trusting PR text or expanding the scope."""
    rows = complete_page(api("GET", "/pulls?state=open&base=dev&per_page=100"))
    selected = {}
    for pr in rows:
        if not isinstance(pr, dict):
            raise ValueError("Malformed candidate inventory")
        head, base = pr.get("head") or {}, pr.get("base") or {}
        branch = head.get("ref")
        match = BRANCH.fullmatch(branch) if isinstance(branch, str) else None
        if match is None or match.group(1) not in ROLES:
            continue
        role, number = match.group(1), pr.get("number")
        if (pr.get("state") != "open" or pr.get("draft") is not True
                or not publisher_ok(pr.get("user") or {})
                or (head.get("repo") or {}).get("full_name") != REPO
                or (base.get("repo") or {}).get("full_name") != REPO
                or base.get("ref") != "dev" or not valid_sha(head.get("sha"))
                or type(number) is not int or not 1 <= number <= 1000000):
            continue
        if number in selected:
            raise ValueError("Duplicate candidate inventory")
        selected[number] = (role, head["sha"])
    if len(selected) > MAX_CANDIDATES:
        raise ValueError("Candidate inventory exceeds bounded admission budget")
    return dict(sorted(selected.items()))


def classify(row):
    """Machine-readable next step; never grants review or merge authority."""
    blockers = []
    for key, label in (
        ("exact_scope_verified", "VERIFY_IDENTITY_AND_SCOPE"),
        ("current_base_verified", "REFRESH_CANDIDATE_BASE"),
        ("ci_workflow_provenance_verified", "VERIFY_CI_PROVENANCE"),
        ("ci_verified", "WAIT_OR_REPAIR_CI"),
        ("safety_review_verified", "INDEPENDENT_SAFETY_REVIEW"),
        ("backend_owner_verified", "BACKEND_OWNER_REVIEW"),
        ("full_vm_acceptance_verified", "COLLECT_VM_EVIDENCE"),
    ):
        if row.get(key) is not True:
            blockers.append(label)
    if row.get("technical_objection") is True:
        blockers.insert(0, "RESOLVE_TECHNICAL_OBJECTION")
    row["automatic_technical_safety_passed"] = (
        all(row.get(key) is True for key in
            ("exact_scope_verified", "current_base_verified", "ci_verified",
             "ci_workflow_provenance_verified"))
        and row.get("technical_objection") is False
    )
    row["blockers"] = blockers + ["MERGE_AUTHORITY_DISABLED"]
    row["next_action"] = row["blockers"][0]
    return row


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


def exact_append(before, after, role, *, formatted=False):
    prefix = before.rstrip(b"\n") + (b"\n\n\n" if formatted else b"\n\n")
    signature = f"def assess_{role}_lifecycle(".encode()
    if (len(before) > 25000 or signature in before
            or not after.startswith(prefix + signature)):
        raise ValueError("Not a single new append")
    addition = after[len(prefix):].decode("utf-8")
    if after != prefix + addition.rstrip().encode("utf-8") + b"\n":
        raise ValueError("Noncanonical append")
    validate_addition(role, addition.rstrip(), execute=False)
    return addition.rstrip()


# Fixed, deliberately narrow semantic contract for the five queued helpers.
# Independent of the more general Factory AST allowlist.
LIFECYCLE_GATES = (
    "source-authenticity", "windows-preflight", "install", "linux-first-boot",
    "windows-return", "linux-update-reboot", "uninstall-windows-integrity",
    "fault-injection-rollback",
)


def require_fixed_lifecycle(role, addition):
    if role not in ROLES:
        raise ValueError("Unreviewed lifecycle role")
    actual = ast.dump(ast.parse(addition), include_attributes=False)
    # Only the two observed local names are admitted. No normalization of
    # arbitrary identifiers, control flow, calls, constants or dict keys.
    for local in ("missing", "missingGates"):
        expected = (
            f"def assess_{role}_lifecycle(evidence: dict) -> dict:\n"
            f"    gates = {LIFECYCLE_GATES!r}\n"
            f"    {local} = sorted([name for name in gates if evidence.get(name) is not True])\n"
            f"    return {{'backend': {role!r}, 'missingGates': {local}, "
            "'installationAuthorized': False, 'releaseEligible': False}\n"
        )
        if actual == ast.dump(ast.parse(expected), include_attributes=False):
            return
    raise ValueError("Helper violates fixed non-writer lifecycle semantics")


def single_parent(sha):
    parents = api("GET", f"/git/commits/{sha}")["parents"]
    if len(parents) != 1 or not valid_sha(parents[0].get("sha")):
        raise ValueError("Unexpected ancestry")
    return parents[0]["sha"]


def one_path_commit(parent, head, path):
    comparison = api("GET", f"/compare/{parent}...{head}")
    files = complete_page(comparison["files"])
    if (comparison.get("status") != "ahead" or comparison.get("ahead_by") != 1
            or comparison.get("behind_by") != 0 or comparison.get("total_commits") != 1
            or comparison.get("merge_base_commit", {}).get("sha") != parent
            or len(files) != 1 or files[0].get("filename") != path
            or files[0].get("status") != "modified"
            or files[0].get("previous_filename") is not None):
        raise ValueError("Unexpected intermediate commit scope")


def candidate_append(pr, role, sha, path):
    """Accept one bot append, or that append plus one semantic-neutral Ruff repair."""
    count = pr.get("commits")
    if type(count) is not int or count not in (1, 2):
        raise ValueError("Unsupported candidate history")
    generated = single_parent(sha) if count == 2 else sha
    original = single_parent(generated)
    if pr["head"]["ref"] != f"bot/gaslux-feature-{role}-{original[:12]}":
        raise ValueError("Branch identity mismatch")
    one_path_commit(original, generated, path)
    before = source_at(path, original)
    generated_source = source_at(path, generated)
    # New deterministic successors already use canonical Ruff spacing. The
    # alternate separator is admitted only for a one-commit fixed helper.
    formatted_single = count == 1 and generated_source.startswith(
        before.rstrip(b"\n") + b"\n\n\n" + f"def assess_{role}_lifecycle(".encode())
    first = exact_append(before, generated_source, role, formatted=formatted_single)
    require_fixed_lifecycle(role, first)
    repair_actor = None
    if count == 2:
        one_path_commit(generated, sha, path)
        final = exact_append(before, source_at(path, sha), role, formatted=True)
        if ast.dump(ast.parse(first)) != ast.dump(ast.parse(final)):
            raise ValueError("Repair changed generated semantics")
        repair = api("GET", f"/commits/{sha}")
        repair_actor = (repair.get("author") or {}).get("id")
        if type(repair_actor) is not int or repair_actor <= 0:
            raise ValueError("Repair author not authenticated")
    return original, repair_actor


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


# Immutable repository/workflow IDs observed on the five candidate CI runs.
# Names alone are not a provenance boundary; do not accept a lookalike workflow.
REPOSITORY_ID = 1460159259
WORKFLOW_JOBS = {
    420402269: {"Windows recovery evidence rules (fixtures only)"},
    420417743: {"evidence-python", "evidence-powershell"},
    420471368: {"read-only-contracts"},
    420371034: {"python-contracts", "windows-contracts"},
}


def ci_workflow_provenance(head, role):
    if not valid_sha(head) or role not in ROLES:
        return False
    required = {420402269, 420417743,
                420371034 if role == "cachyos" else 420471368}
    data = api("GET", f"/actions/runs?head_sha={head}&event=pull_request&per_page=100")
    rows = complete_page(data["workflow_runs"])
    if type(data.get("total_count")) is not int or data["total_count"] != len(rows):
        return False
    found = set()
    for run in rows:
        workflow = run.get("workflow_id")
        if workflow not in required:
            continue
        run_id, attempt = run.get("id"), run.get("run_attempt")
        if (type(run_id) is not int or run_id <= 0
                or type(attempt) is not int or attempt <= 0
                or run.get("head_sha") != head
                or run.get("event") != "pull_request"
                or run.get("repository", {}).get("id") != REPOSITORY_ID
                or run.get("head_repository", {}).get("id") != REPOSITORY_ID
                or run.get("status") != "completed" or run.get("conclusion") != "success"):
            return False
        jobs = api("GET", f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
        items = complete_page(jobs["jobs"])
        if type(jobs.get("total_count")) is not int or jobs["total_count"] != len(items):
            return False
        names = set()
        for job in items:
            if (job.get("run_id") != run_id or job.get("run_attempt") != attempt
                    or job.get("head_sha") != head or job.get("status") != "completed"
                    or job.get("conclusion") != "success"):
                return False
            name = job.get("name")
            if not isinstance(name, str) or name in names:
                return False
            names.add(name)
        if not WORKFLOW_JOBS[workflow] <= names:
            return False
        found.add(workflow)
    return found == required


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


def parse_owner_ids(raw):
    """Strict, administrator-provided configuration; no default identities."""
    if not isinstance(raw, str) or not raw or len(raw) > 1024:
        return {}

    def unique_pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("Duplicate owner role")
            out[key] = value
        return out

    try:
        data = json.loads(raw, object_pairs_hook=unique_pairs)
        if (type(data) is not dict
                or not set(data) <= ROLES
                or any(type(value) is not int or not 1 <= value < 10**19
                       for value in data.values())):
            return {}
        return data
    except (ValueError, TypeError, RecursionError):
        return {}


def owner_review_ok(reviews, owner_id, safety_id, author_id, repair_id, role, head, dev):
    # A shared account cannot attest two roles. Unknown Safety identity also
    # blocks this gate; no inferred role from PR text or model output.
    if (role not in ROLES or not valid_sha(head) or not valid_sha(dev)
            or any(type(value) is not int or value <= 0
                   for value in (owner_id, safety_id, author_id))
            or owner_id in (safety_id, author_id, repair_id)
            or safety_id in (author_id, repair_id)):
        return False
    rows = complete_page(reviews)
    if any(row.get("state") == "CHANGES_REQUESTED" for row in rows):
        return False
    own = [row for row in rows if row.get("user", {}).get("id") == owner_id
           and row.get("state") != "COMMENTED"]
    marker = f"GASLUX-BACKEND-OWNER-V1 role={role} head={head} base={dev}"
    return bool(own) and all(
        row.get("state") == "APPROVED" and row.get("commit_id") == head
        and marker in str(row.get("body", "")).splitlines()
        for row in own
    )


def inspect(number, role, reviewer_id, owner_id=None, expected_head=None):
    out = {"pr": number, "role": role, "head": None, "base": None,
           "exact_scope_verified": False, "current_base_verified": False,
           "ci_verified": False, "ci_workflow_provenance_verified": False,
           "safety_review_verified": False,
           "backend_owner_verified": False, "full_vm_acceptance_verified": False,
           "technical_objection": None,
           "merge_authorized": False, "release_eligible": False}
    try:
        pr = api("GET", f"/pulls/{number}")
        head, base = pr["head"], pr["base"]
        sha = head["sha"]
        dev = api("GET", "/git/ref/heads/dev")["object"]["sha"]
        if (not valid_sha(sha) or not valid_sha(dev)
                or (expected_head is not None and sha != expected_head)):
            raise ValueError("Malformed SHA")
        out.update(head=sha, base=dev)
        if (pr.get("number") != number or pr.get("state") != "open"
                or pr.get("draft") is not True or not publisher_ok(pr.get("user") or {})
                or head["repo"]["full_name"] != REPO or base["repo"]["full_name"] != REPO
                or base["ref"] != "dev"):
            raise ValueError("Candidate identity mismatch")
        files = complete_page(api("GET", f"/pulls/{number}/files?per_page=100"))
        path = TASKS[role][0]
        if (len(files) != 1 or files[0].get("filename") != path
                or files[0].get("status") != "modified"
                or files[0].get("previous_filename") is not None
                or files[0].get("deletions") != 0
                or type(files[0].get("additions")) is not int
                or not 1 <= files[0]["additions"] <= 101):
            raise ValueError("Candidate exceeds append-only scope")
        original, repair_actor = candidate_append(pr, role, sha, path)
        out["current_base_verified"] = original == dev
        out["exact_scope_verified"] = True
        out["ci_workflow_provenance_verified"] = ci_workflow_provenance(sha, role)
        out["ci_verified"] = (
            out["ci_workflow_provenance_verified"] and checks_ok(
                api("GET", f"/commits/{sha}/check-runs?per_page=100"), sha, role)
        )
        reviews = complete_page(api("GET", f"/pulls/{number}/reviews?per_page=100"))
        out["technical_objection"] = any(row.get("state") == "CHANGES_REQUESTED" for row in reviews)
        out["safety_review_verified"] = (
            reviewer_id != repair_actor
            and review_ok(reviews, reviewer_id, pr["user"]["id"], sha, dev)
        )
        out["backend_owner_verified"] = (
            out["current_base_verified"] and owner_review_ok(
                reviews, owner_id, reviewer_id, pr["user"]["id"], repair_actor, role, sha, dev)
        )
        comments = complete_page(api("GET", f"/issues/{number}/comments?per_page=100"))
        if any(marker in str(row.get("body", "")).upper()
               for row in comments for marker in ("SAFETY_DENIED", "BLOCKED_SAFETY", "DO_NOT_MERGE")):
            out["technical_objection"] = True
            out["safety_review_verified"] = False
            out["backend_owner_verified"] = False
        if (api("GET", "/git/ref/heads/dev")["object"]["sha"] != dev
                or api("GET", f"/pulls/{number}")["head"]["sha"] != sha):
            raise ValueError("Candidate changed during inspection")
        out["status"] = "blocked"
        out["reason"] = "Full-VM acceptance and merge authority unavailable; merge disabled"
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError, SyntaxError):
        out["technical_objection"] = None
        for key in out:
            if key.endswith("_verified"):
                out[key] = False
        out["status"] = "blocked"
        out["reason"] = "Identity, scope or API validation failed"
    return classify(out)


def main():
    raw = os.getenv("GASLUX_SAFETY_REVIEWER_ID", "")
    reviewer = int(raw) if re.fullmatch(r"[1-9][0-9]{0,18}", raw) else None
    owners = parse_owner_ids(os.getenv("GASLUX_BACKEND_OWNER_IDS", ""))
    report = {"schema": "gaslux-distro-admission-v3", "read_only": True,
              "reviewer_configured": reviewer is not None,
              "owner_roles_configured": sorted(owners),
              "inventory_verified": False, "merge_authorized": False,
              "candidates": []}
    try:
        candidates = discover_candidates()
        report["inventory_verified"] = True
        report["candidates"] = [
            inspect(n, role, reviewer, owners.get(role), head)
            for n, (role, head) in candidates.items()
        ]
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError):
        report["inventory_verified"] = False
        report["candidates"] = []
        report["next_action"] = "RECONCILE_CANDIDATE_INVENTORY"
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
