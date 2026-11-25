#!/usr/bin/env python3
"""Inspect generated supervised scopes without executing candidate files."""
from __future__ import annotations

import argparse
import ast
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
import gaslux_dynamic_development as dynamic

DYNAMIC_SCOPE = "dynamic-test-demanded-api-v1"
PRODUCT_SCOPES = (factory.SUPERVISED_MEDIA_SCOPE, DYNAMIC_SCOPE)
DYNAMIC_BRANCH = re.compile(r"bot/gaslux-dynamic-(mint|zorin|cachyos|popos|q4os|bazzite)-[0-9a-f]{12}-[0-9a-f]{12}")

BRANCH = re.compile(r"bot/gaslux-(test|pins)-(mint|zorin|cachyos|popos|q4os|bazzite)-[0-9a-f]{12}")


def discover():
    rows = admission.complete_page(admission.api(
        "GET", "/pulls?state=open&base=dev&per_page=100"))
    result = {}
    for pr in rows:
        head, base = pr["head"], pr["base"]
        branch = head.get("ref")
        match = BRANCH.fullmatch(branch) if isinstance(branch, str) else None
        dynamic_match = DYNAMIC_BRANCH.fullmatch(branch) if isinstance(branch, str) else None
        if not (match or dynamic_match) or (head.get("repo") or {}).get("full_name") != admission.REPO:
            continue
        if dynamic_match:
            role, scope = dynamic_match.group(1), DYNAMIC_SCOPE
        else:
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


def dynamic_scope(pr, role, head):
    """Recover the task from immutable source/test bytes, not PR prose."""
    if pr.get("commits") != 1:
        raise ValueError("Dynamic proposal is not a single append")
    parent = admission.single_parent(head)
    source, suite, _ = factory.TASKS[role]
    admission.one_path_commit(parent, head, source)
    before, after = admission.source_at(source, parent), admission.source_at(source, head)
    prefix = before.rstrip(b"\n") + b"\n\n\n"
    if not after.startswith(prefix):
        raise ValueError("Dynamic source prefix changed")
    generated = after[len(prefix):].decode("utf-8")
    nodes = ast.parse(generated).body
    if len(nodes) != 1 or not isinstance(nodes[0], ast.FunctionDef):
        raise ValueError("Dynamic append is not one function")
    symbol = nodes[0].name
    key = factory.sha256(f"{source}:{symbol}".encode())
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in (source, "auto_tests/tests/" + suite):
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(admission.source_at(name, parent))
        task = dynamic.select_task(root, key)
        if (task["role"] != role or pr["head"]["ref"] != dynamic.branch_for(task, parent)
                or dynamic.candidate_bytes(before, symbol, generated) != after):
            raise ValueError("Dynamic task/branch or exact bytes mismatch")
    return parent


def canonical_scope(pr, role, scope, head):
    if scope == DYNAMIC_SCOPE:
        return dynamic_scope(pr, role, head)
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


VM_PLATFORMS = ("windows10-bios-mbr", "windows10-uefi-gpt", "windows11-uefi-gpt")
VM_MARKER = re.compile(
    r"GASLUX-VM-V1 role=([a-z0-9]+) platform=([a-z0-9-]+) "
    r"head=([0-9a-f]{40}) base=([0-9a-f]{40}) "
    r"run=([1-9][0-9]{0,18}) artifact=([1-9][0-9]{0,18}) "
    r"sha256=([0-9a-f]{64})"
)


def vm_acceptance_verified(reviews, role, head, base, author, safety, owner):
    """Authenticate independent installed-lifecycle evidence, not live ISO proof.

    The reviewer is an externally controlled observer who independently checks
    the archived, exact candidate's complete install/boot/update/uninstall/
    rollback evidence. GitHub metadata binds that review to immutable runs and
    artifact digests. The producer workflow must be separately provisioned and
    reviewed; a missing producer or observer is never treated as success.
    """
    try:
        observer_raw = os.getenv("GASLUX_VM_OBSERVER_ID", "")
        workflow_raw = os.getenv("GASLUX_VM_ACCEPTANCE_WORKFLOW_ID", "")
        if not all(re.fullmatch(r"[1-9][0-9]{0,18}", x)
                   for x in (observer_raw, workflow_raw)):
            return False
        observer, workflow = int(observer_raw), int(workflow_raw)
        if (role not in factory.TASKS or not all(admission.valid_sha(x) for x in (head, base))
                or any(type(x) is not int or x <= 0 for x in (author, safety, owner))
                or observer in (author, safety, owner, *admission.BOTS.values())):
            return False
        rows = admission.complete_page(reviews)
        if any(x.get("state") == "CHANGES_REQUESTED" for x in rows):
            return False
        own = [x for x in rows if x.get("user", {}).get("id") == observer
               and x.get("state") != "COMMENTED"]
        if len(own) != 1 or own[0].get("state") != "APPROVED" or own[0].get("commit_id") != head:
            return False
        platforms = VM_PLATFORMS[1:] if role == "bazzite" else VM_PLATFORMS
        receipts = {}
        for line in str(own[0].get("body", "")).splitlines():
            if not line.startswith("GASLUX-VM-V1"):
                continue
            m = VM_MARKER.fullmatch(line)
            if not m:
                return False
            distro, platform, observed_head, observed_base, run, artifact, digest = m.groups()
            if (distro != role or platform not in platforms or platform in receipts
                    or observed_head != head or observed_base != base):
                return False
            receipts[platform] = (int(run), int(artifact), digest)
        if set(receipts) != set(platforms) or len({v[1] for v in receipts.values()}) != len(platforms):
            return False
        # Extend the existing Lifecycle workflow, but only a separately
        # reviewed installed-guest job can satisfy the acceptance contract.
        definition = admission.api("GET", f"/actions/workflows/{workflow}")
        path = definition.get("path")
        if (definition.get("id") != workflow or definition.get("state") != "active"
                or path != ".github/workflows/gaslux-agent-lifecycle-research.yml"):
            return False
        # Refuse a candidate with a different lab workflow than trusted main.
        trusted = admission.api("GET", "/git/ref/heads/main")["object"]["sha"]
        if not admission.valid_sha(trusted) or admission.source_at(path, head) != admission.source_at(path, trusted):
            return False
        for platform, (run_id, artifact_id, digest) in receipts.items():
            run = admission.api("GET", f"/actions/runs/{run_id}")
            attempt = run.get("run_attempt")
            if (run.get("id") != run_id or run.get("workflow_id") != workflow
                    or run.get("head_sha") != head or run.get("event") != "pull_request"
                    or run.get("repository", {}).get("id") != admission.REPOSITORY_ID
                    or run.get("head_repository", {}).get("id") != admission.REPOSITORY_ID
                    or run.get("status") != "completed" or run.get("conclusion") != "success"
                    or type(attempt) is not int or attempt <= 0):
                return False
            job_data = admission.api("GET", f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
            jobs = admission.complete_page(job_data.get("jobs"))
            if job_data.get("total_count") != len(jobs):
                return False
            required = f"full-installed-lifecycle ({role}, {platform})"
            matching = [j for j in jobs if j.get("name") == required]
            if (len(matching) != 1 or any(j.get("head_sha") != head
                    or j.get("run_id") != run_id or j.get("run_attempt") != attempt
                    or j.get("status") != "completed" or j.get("conclusion") != "success"
                    for j in matching)):
                return False
            data = admission.api("GET", f"/actions/runs/{run_id}/artifacts?per_page=100")
            artifacts = admission.complete_page(data.get("artifacts"))
            if data.get("total_count") != len(artifacts):
                return False
            matching = [a for a in artifacts if a.get("id") == artifact_id]
            if len(matching) != 1:
                return False
            artifact = matching[0]
            if (artifact.get("name") != f"gaslux-full-vm-{role}-{platform}"
                    or artifact.get("expired") is not False
                    or artifact.get("digest") != "sha256:" + digest
                    or type(artifact.get("size_in_bytes")) is not int
                    or not 0 < artifact["size_in_bytes"] <= 64 * 1024 * 1024):
                return False
        return True
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError):
        return False


def inspect(number, role, scope, head, reviewer=None, owner=None, *, allow_ready=False):
    row = {"pr": number, "role": role, "scope": scope, "head": head,
           "base": None, "exact_scope_verified": False, "current_base_verified": False,
           "ci_workflow_provenance_verified": False, "ci_verified": False,
           "technical_objection": None, "safety_review_verified": False,
           "backend_owner_verified": False, "full_vm_acceptance_verified": False,
           "merge_authorized": False,
           "release_eligible": False, "next_action": "VERIFY_SUPERVISED_SCOPE"}
    try:
        if not admission.valid_sha(head) or role not in factory.TASKS or scope not in (*factory.SUPERVISED_SCOPES, DYNAMIC_SCOPE):
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
            if (scope in PRODUCT_SCOPES
                    and row["safety_review_verified"] and row["backend_owner_verified"]):
                row["full_vm_acceptance_verified"] = vm_acceptance_verified(
                    reviews, role, head, base, author, reviewer, owner)
        if (admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != base
                or admission.api("GET", f"/pulls/{number}")["head"]["sha"] != head):
            raise ValueError("Candidate drift during inspection")
        row["next_action"] = (
            "RESOLVE_TECHNICAL_OBJECTION" if row["technical_objection"] else
            "REFRESH_SUPERVISED_SCOPE" if not row["current_base_verified"] else
            "WAIT_OR_REPAIR_SCOPE_CI" if not row["ci_verified"] else
            "INDEPENDENT_SAFETY_REVIEW" if not row["safety_review_verified"] else
            "BACKEND_OWNER_REVIEW" if not row["backend_owner_verified"] else
            ("PRODUCT_INTEGRATION_ELIGIBLE" if row["full_vm_acceptance_verified"] else
             "COLLECT_VM_EVIDENCE") if scope in PRODUCT_SCOPES else
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


def eligible_product(row):
    return (
        row.get("scope") in PRODUCT_SCOPES
        and row.get("next_action") == "PRODUCT_INTEGRATION_ELIGIBLE"
        and all(row.get(key) is True for key in (
            "exact_scope_verified", "current_base_verified",
            "ci_workflow_provenance_verified", "ci_verified",
            "safety_review_verified", "backend_owner_verified",
            "full_vm_acceptance_verified"))
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
        requiredApprovingReviewCount
        dismissesStaleReviews
        requireLastPushApproval
        requiresConversationResolution
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


def strict_ruleset_protected(base):
    """Accept only an active exact-dev repository ruleset with visible no-bypass policy.

    Effective rule listing alone does not expose bypass actors. Never infer
    that a missing bypass_actors field means an empty list, and never acquire
    administrative credentials to make this check succeed.
    """
    try:
        if not admission.valid_sha(base):
            return False
        if admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != base:
            return False
        rows = admission.complete_page(admission.api(
            "GET", "/rules/branches/dev?per_page=100"))
        groups = {}
        for row in rows:
            if (row.get("ruleset_source_type") != "Repository"
                    or row.get("ruleset_source") != admission.REPO):
                continue
            rid = row.get("ruleset_id")
            if type(rid) is not int or rid <= 0:
                return False
            groups.setdefault(rid, []).append(row)
        if len(groups) > 16:
            return False
        for rid, active in sorted(groups.items()):
            kinds = {row.get("type") for row in active}
            if not {"deletion", "non_fast_forward", "pull_request",
                    "required_status_checks"} <= kinds:
                continue
            detail = admission.api("GET", f"/rulesets/{rid}?includes_parents=false")
            if (detail.get("id") != rid or detail.get("source_type") != "Repository"
                    or detail.get("source") != admission.REPO
                    or detail.get("target") != "branch" or detail.get("enforcement") != "active"
                    or detail.get("bypass_actors") != []
                    or detail.get("conditions") != {
                        "ref_name": {"include": ["refs/heads/dev"], "exclude": []}}):
                continue
            declared = admission.complete_page(detail["rules"])
            by_type = {row["type"]: row for row in declared}
            active_by_type = {row["type"]: row for row in active}
            if (len(by_type) != len(declared) or len(active_by_type) != len(active)
                    or set(by_type) != set(active_by_type)
                    or any(row.get("parameters", {}) != active_by_type[kind].get("parameters", {})
                           for kind, row in by_type.items())):
                continue
            # Do not accept a ruleset that restricts all updates, even PR merges.
            if "update" in by_type:
                continue
            reviews = by_type["pull_request"].get("parameters", {})
            if (type(reviews.get("required_approving_review_count")) is not int
                    or reviews["required_approving_review_count"] < 2
                    or any(reviews.get(key) is not True for key in (
                        "dismiss_stale_reviews_on_push", "require_last_push_approval",
                        "required_review_thread_resolution"))):
                continue
            params = by_type["required_status_checks"]["parameters"]
            checks = params["required_status_checks"]
            if (params.get("strict_required_status_checks_policy") is not True
                    or params.get("do_not_enforce_on_create") is True
                    or not isinstance(checks, list) or not 0 < len(checks) < 100
                    or not all(isinstance(x, dict) and isinstance(x.get("context"), str)
                               and x["context"].strip() for x in checks)
                    or not admission.COMMON_CHECKS <= {x["context"] for x in checks}
                    or any(x.get("integration_id") != 15368 for x in checks)):
                continue
            # Recheck the exact base, not an inferred merge base. The GitHub
            # server enforces the strict rule at merge time.
            return admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] == base
        return False
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError):
        return False


def strict_dev_protected(base):
    """Read effective server policy with the same token used to merge.

    Unknown, missing, unreadable or bypassable policy is not merge authority.
    The safety argument assumes trusted admins do not disable the rules during
    integration; the server rejects concurrent ordinary updates to dev and
    enforces independent review count, stale dismissal and conversation resolution.
    Exact role/HEAD review checks remain separate application gates.
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
        if (repo["nameWithOwner"] != admission.REPO
                or ref["name"] != "dev" or ref["prefix"] != "refs/heads/"
                or ref["target"]["oid"] != base):
            return False
        rule, effective = ref["branchProtectionRule"], ref["refUpdateRule"]
        if rule is None:
            return strict_ruleset_protected(base)
        checks = rule["requiredStatusCheckContexts"]
        enforced = effective["requiredStatusCheckContexts"]
        return (
            repo["nameWithOwner"] == admission.REPO
            and ref["name"] == "dev" and ref["prefix"] == "refs/heads/"
            and ref["target"]["oid"] == base
            and all(rule[k] is True for k in (
                "isAdminEnforced", "requiresStatusChecks", "requiresStrictStatusChecks",
                "dismissesStaleReviews", "requireLastPushApproval", "requiresConversationResolution"))
            and type(rule["requiredApprovingReviewCount"]) is int
            and rule["requiredApprovingReviewCount"] >= 2
            and all(rule[k] is False and effective[k] is False for k in (
                "allowsForcePushes", "allowsDeletions"))
            and all(type(rule[k]["totalCount"]) is int and rule[k]["totalCount"] == 0
                    for k in ("bypassPullRequestAllowances", "bypassForcePushAllowances"))
            and type(checks) is list and 0 < len(checks) <= 100
            and all(type(x) is str and x.strip() for x in checks)
            and admission.COMMON_CHECKS <= set(checks)
            and type(enforced) is list and set(checks) <= set(enforced)
        )
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError):
        return False


def integrate_one(*, product=False):
    """Trusted-main-only bounded integration, never executes candidate code."""
    if (os.getenv("GITHUB_REPOSITORY") != admission.REPO
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch", "push")
            or os.getenv("GASLUX_AUTONOMY_PAUSED", "").lower() == "true"):
        raise ValueError("Untrusted integration context")
    reviewer, owners = configured_reviewers()
    expected_scopes = PRODUCT_SCOPES if product else (factory.SUPERVISED_TEST_SCOPE,)
    eligible = eligible_product if product else eligible_test
    for number, (role, scope, head) in sorted(discover().items()):
        if scope not in expected_scopes:
            continue
        row = inspect(number, role, scope, head, reviewer, owners.get(role), allow_ready=True)
        if not eligible(row):
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
        if not eligible(checked) or checked["base"] != base:
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
        closed = admission.api("GET", f"/pulls/{number}")
        if (closed.get("state") != "closed" or closed.get("merged") is not True
                or closed.get("merge_commit_sha") != result["sha"]
                or closed.get("head", {}).get("sha") != head
                or closed.get("base", {}).get("ref") != "dev"):
            raise RuntimeError("Post-merge PR closure not verified; investigate")
        live = admission.api("GET", "/git/ref/heads/dev")["object"]["sha"]
        if not admission.valid_sha(live):
            raise RuntimeError("Post-merge dev ref invalid")
        if live != result["sha"]:
            relation = admission.api("GET", f"/compare/{result['sha']}...{live}")
            if (relation.get("status") != "ahead"
                    or relation.get("behind_by") != 0
                    or relation.get("merge_base_commit", {}).get("sha") != result["sha"]):
                raise RuntimeError("Merged commit not proven in live dev")
        return {"status": "merged", "pr": number, "head": head,
                "reviewed_base": base, "merge_sha": result["sha"], "live_dev": live,
                "strict_base_protection_verified": True, "reviewed_tree_verified": True,
                "pr_closure_verified": True, "dev_ancestry_verified": True,
                "scope": scope, "role": role, "release_eligible": False}
    return {"status": "idle"}


def dynamic_safety_findings(number, role, head):
    """Recompute structural Safety facts from the live exact candidate.

    No candidate code is executed. Test success or a restricted AST is not
    a semantic proof that a new API can safely control installation.
    """
    pr = admission.api("GET", f"/pulls/{number}")
    base = admission.api("GET", "/git/ref/heads/dev")["object"]["sha"]
    author = pr.get("user") or {}
    if (pr.get("state") != "open" or pr.get("number") != number
            or not admission.publisher_ok(author)
            or pr["head"]["sha"] != head or pr["base"]["sha"] != base
            or pr["base"]["ref"] != "dev"
            or pr["head"]["repo"]["full_name"] != admission.REPO
            or pr["base"]["repo"]["full_name"] != admission.REPO
            or not admission.valid_sha(base)):
        raise ValueError("Dynamic Safety identity mismatch")
    parent = dynamic_scope(pr, role, head)
    if parent != base:
        raise ValueError("Dynamic Safety stale parent")
    source = factory.TASKS[role][0]
    before, after = admission.source_at(source, base), admission.source_at(source, head)
    prefix = before.rstrip(b"\n") + b"\n\n\n"
    addition = after[len(prefix):].decode("utf-8")
    fn = ast.parse(addition).body[0]
    dynamic.validate_function(fn.name, addition)
    # Report safety-sensitive names as review leads, not evidence of an exploit.
    sensitive = re.compile(r"authoriz|permission|allow|release|install|disk|partition|boot|recover|rollback|write|sign|verify|trust", re.I)
    signals = set()
    for node in ast.walk(fn):
        value = (node.id if isinstance(node, ast.Name) else
                 node.arg if isinstance(node, ast.arg) else
                 node.value if isinstance(node, ast.Constant) and isinstance(node.value, str)
                 else None)
        if value and sensitive.search(value):
            signals.add(str(value)[:80])
    if sensitive.search(fn.name):
        signals.add(fn.name)
    return {"schema": "gaslux-dynamic-safety-v1", "pr": number, "head": head,
            "base": base, "role": role, "symbol": fn.name,
            "candidate_sha256": factory.sha256(after),
            "source_prefix_preserved": True, "restricted_ast_verified": True,
            "safety_sensitive_names": sorted(signals)[:20],
            "semantic_approval": False, "merge_authorized": False,
            "status": "SEMANTIC_AND_VM_REVIEW_REQUIRED"}


def independent_dynamic_assessment(reviewer, owners):
    """Publish a bounded technical finding with the independent Safety actor."""
    for number, (role, scope, head) in sorted(discover().items()):
        if scope != DYNAMIC_SCOPE:
            continue
        row = inspect(number, role, scope, head, reviewer, owners.get(role), allow_ready=True)
        if (row.get("technical_objection") is not False
                or row.get("safety_review_verified") is True
                or not all(row.get(k) is True for k in (
                    "exact_scope_verified", "current_base_verified",
                    "ci_workflow_provenance_verified", "ci_verified"))):
            continue
        base = row["base"]
        pr = admission.api("GET", f"/pulls/{number}")
        if pr["user"]["id"] == reviewer:
            continue
        marker = f"GASLUX-DYNAMIC-SAFETY-V1 head={head} base={base}"
        reviews = admission.complete_page(admission.api("GET", f"/pulls/{number}/reviews?per_page=100"))
        if any((r.get("user") or {}).get("id") == reviewer and
               (r.get("state") != "COMMENTED" or
                str(r.get("body", "")).splitlines()[:1] == [marker])
               for r in reviews):
            continue
        findings = dynamic_safety_findings(number, role, head)
        if (findings["base"] != base or
                inspect(number, role, scope, head, reviewer, owners.get(role), allow_ready=True) != row):
            return {"status": "dynamic_assessment_drift", "pr": number}
        # COMMENT is intentionally not APPROVE. A test-demanded helper can
        # affect a safety-sensitive caller even when its AST is side-effect free.
        result = admission.api("POST", f"/pulls/{number}/reviews", {
            "commit_id": head, "event": "COMMENT",
            "body": marker + "\n\n" + json.dumps(findings, sort_keys=True)})
        if (result.get("user", {}).get("id") != reviewer
                or result.get("commit_id") != head or result.get("state") != "COMMENTED"):
            raise RuntimeError("GitHub did not confirm dynamic Safety finding")
        return {"status": "dynamic_assessed", "pr": number, "head": head,
                "base": base, "review_id": result.get("id"), "semantic_approval": False}
    return {"status": "idle"}


def independent_safety_review():
    """Separate credential and exact canonical review; never approve product writers."""
    if (os.getenv("GITHUB_REPOSITORY") != admission.REPO
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch", "push")
            or os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true"):
        raise ValueError("Untrusted Safety execution context")
    reviewer, owners = configured_reviewers()
    if reviewer is None or reviewer in admission.BOTS.values() or reviewer in owners.values():
        return {"status": "independent_identity_required"}
    if not os.getenv("GH_TOKEN"):
        return {"status": "independent_credential_required"}
    # The token must authenticate as the configured independent service account.
    # Never fall back to github.token or to the publisher credential.
    actor = json.loads(subprocess.run(
        ["gh", "api", "user"], check=True, timeout=30, capture_output=True).stdout)
    if type(actor.get("id")) is not int or actor["id"] != reviewer:
        raise ValueError("Safety credential identity mismatch")
    for number, (role, scope, head) in sorted(discover().items()):
        if scope not in factory.SUPERVISED_SCOPES:
            continue
        row = inspect(number, role, scope, head, reviewer, owners.get(role), allow_ready=True)
        if (row.get("next_action") != "INDEPENDENT_SAFETY_REVIEW"
                or row.get("technical_objection") is not False
                or not all(row.get(k) is True for k in (
                    "exact_scope_verified", "current_base_verified",
                    "ci_workflow_provenance_verified", "ci_verified"))):
            continue
        base = row["base"]
        pr = admission.api("GET", f"/pulls/{number}")
        if (pr["user"]["id"] == reviewer or pr["head"]["sha"] != head
                or pr["base"]["sha"] != base or pr.get("state") != "open"):
            raise ValueError("Safety candidate identity drift")
        # Prior stale or adverse reviews are not overwritten by automation.
        reviews = admission.complete_page(admission.api(
            "GET", f"/pulls/{number}/reviews?per_page=100"))
        if any(item.get("user", {}).get("id") == reviewer
               and item.get("state") != "COMMENTED" for item in reviews):
            continue
        if scope == factory.SUPERVISED_MEDIA_SCOPE and (
                not row.get("backend_owner_verified")
                or not vm_acceptance_verified(reviews, role, head, base,
                                              pr["user"]["id"], reviewer, owners.get(role))):
            continue
        if inspect(number, role, scope, head, reviewer, owners.get(role),
                   allow_ready=True) != row:
            return {"status": "review_drift", "pr": number}
        if admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != base:
            return {"status": "review_drift", "pr": number}
        result = admission.api("POST", f"/pulls/{number}/reviews", {
            "commit_id": head, "event": "APPROVE",
            "body": (f"GASLUX-SAFETY-V1 head={head} base={base}\n"
                     "Automated independent exact-byte canonical scope review: "
                     "scope, current parent, trusted CI provenance and required checks verified. "
                     "No product writer, installation or release authority.")})
        if (result.get("user", {}).get("id") != reviewer
                or result.get("commit_id") != head or result.get("state") != "APPROVED"):
            raise RuntimeError("GitHub did not confirm independent review")
        return {"status": "reviewed", "pr": number, "head": head, "base": base,
                "reviewer": reviewer, "review_id": result.get("id")}
    return independent_dynamic_assessment(reviewer, owners)


def independent_owner_review():
    """One separately authenticated backend owner; only canonical scopes."""
    if (os.getenv("GITHUB_REPOSITORY") != admission.REPO
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch", "push")
            or os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true"):
        raise ValueError("Untrusted backend review context")
    safety, owners = configured_reviewers()
    if safety is None or not os.getenv("GH_TOKEN"):
        return {"status": "owner_identity_or_credential_required"}
    actor = json.loads(subprocess.run(
        ["gh", "api", "user"], check=True, timeout=30, capture_output=True).stdout)
    owner = actor.get("id")
    if (type(owner) is not int or owner <= 0 or owner == safety
            or owner in admission.BOTS.values() or owner not in owners.values()):
        raise ValueError("Independent backend owner credential mismatch")
    for number, (role, scope, head) in sorted(discover().items()):
        if owners.get(role) != owner or scope not in factory.SUPERVISED_SCOPES:
            continue
        row = inspect(number, role, scope, head, safety, owner, allow_ready=True)
        if (row.get("backend_owner_verified") or row.get("technical_objection") is not False
                or not all(row.get(k) is True for k in (
                    "exact_scope_verified", "current_base_verified",
                    "ci_workflow_provenance_verified", "ci_verified"))):
            continue
        base = row["base"]
        pr = admission.api("GET", f"/pulls/{number}")
        author = pr["user"]["id"]
        if (author == owner or author == safety or pr["head"]["sha"] != head
                or pr["base"]["sha"] != base or pr.get("state") != "open"):
            raise ValueError("Backend candidate drift")
        reviews = admission.complete_page(admission.api(
            "GET", f"/pulls/{number}/reviews?per_page=100"))
        if any(item.get("user", {}).get("id") == owner
               and item.get("state") != "COMMENTED" for item in reviews):
            continue
        if scope == factory.SUPERVISED_MEDIA_SCOPE and not vm_acceptance_verified(
                reviews, role, head, base, author, safety, owner):
            continue
        if inspect(number, role, scope, head, safety, owner, allow_ready=True) != row:
            return {"status": "owner_review_drift", "pr": number}
        if admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != base:
            return {"status": "owner_review_drift", "pr": number}
        receipt = admission.api("POST", f"/pulls/{number}/reviews", {
            "commit_id": head, "event": "APPROVE",
            "body": (f"GASLUX-BACKEND-OWNER-V1 role={role} head={head} base={base}\n"
                     "Automated canonical backend scope and independent required CI review. "
                     "No installation or release authority.")})
        if (receipt.get("user", {}).get("id") != owner
                or receipt.get("commit_id") != head or receipt.get("state") != "APPROVED"):
            raise RuntimeError("GitHub did not confirm backend review")
        return {"status": "owner_reviewed", "pr": number, "role": role, "head": head,
                "base": base, "owner": owner, "review_id": receipt.get("id")}
    return {"status": "idle"}


def audit_completed_integrations():
    """Read-only reconstruction of actual merged candidate receipts.

    A green fixture, draft, missing approval, or successful workflow alone
    cannot be reported as a completed engineering integration.
    """
    live = admission.api("GET", "/git/ref/heads/dev")["object"]["sha"]
    if not admission.valid_sha(live):
        raise ValueError("Invalid audit dev ref")
    reviewer, owners = configured_reviewers()
    prs = admission.api("GET", "/pulls?state=closed&base=dev&sort=updated&direction=desc&per_page=50")
    if not isinstance(prs, list) or len(prs) > 50:
        raise ValueError("Invalid closed PR audit page")
    findings = []
    for summary in prs:
        ref = summary.get("head", {}).get("ref", "")
        match = BRANCH.fullmatch(ref) if isinstance(ref, str) else None
        dm = DYNAMIC_BRANCH.fullmatch(ref) if isinstance(ref, str) else None
        if not (match or dm) or not admission.publisher_ok(summary.get("user") or {}):
            continue
        n = summary["number"]
        if type(n) is not int or not 1 <= n <= 1000000:
            raise ValueError("Invalid closed PR number")
        if dm:
            role, scope = dm.group(1), DYNAMIC_SCOPE
        else:
            kind, role = match.groups()
            scope = factory.SUPERVISED_TEST_SCOPE if kind == "test" else factory.SUPERVISED_MEDIA_SCOPE
        pr = admission.api("GET", f"/pulls/{n}")
        head, merged = pr["head"]["sha"], pr.get("merge_commit_sha")
        row = {"pr": n, "role": role, "scope": scope, "head": head,
               "status": "CLOSED_WITHOUT_VERIFIED_MERGE", "integration_verified": False,
               "release_eligible": False}
        findings.append(row)
        if (pr.get("merged") is not True or pr.get("state") != "closed"
                or pr.get("number") != n or pr["base"]["ref"] != "dev"
                or pr["head"]["repo"]["full_name"] != admission.REPO
                or pr["base"]["repo"]["full_name"] != admission.REPO
                or not admission.publisher_ok(pr.get("user") or {})
                or not all(admission.valid_sha(x) for x in (head, merged))):
            continue
        try:
            base = canonical_scope(pr, role, scope, head)
            if admission.single_parent(merged) != base:
                raise ValueError("Wrong integrated parent")
            a = admission.api("GET", f"/git/commits/{head}")["tree"]["sha"]
            b = admission.api("GET", f"/git/commits/{merged}")["tree"]["sha"]
            if not admission.valid_sha(a) or a != b:
                raise ValueError("Wrong integrated tree")
            if live != merged:
                relation = admission.api("GET", f"/compare/{merged}...{live}")
                if (relation.get("status") != "ahead" or relation.get("behind_by") != 0
                        or relation.get("merge_base_commit", {}).get("sha") != merged):
                    raise ValueError("Integrated commit not in live dev")
            reviews = admission.complete_page(admission.api("GET", f"/pulls/{n}/reviews?per_page=100"))
            author = pr["user"]["id"]
            owner = owners.get(role)
            if not (admission.review_ok(reviews, reviewer, author, head, base)
                    and admission.owner_review_ok(reviews, owner, reviewer, author, None,
                                                  role, head, base, supervised=True)
                    and admission.ci_workflow_provenance(head, role, supervised=True)
                    and admission.checks_ok(admission.api("GET", f"/commits/{head}/check-runs?per_page=100"),
                                             head, role)):
                raise ValueError("Exact review or CI no longer verifiable")
            if scope in PRODUCT_SCOPES and not vm_acceptance_verified(
                    reviews, role, head, base, author, reviewer, owner):
                raise ValueError("Independent VM evidence not verified")
            comments = admission.complete_page(admission.api("GET", f"/issues/{n}/comments?per_page=100"))
            if any(marker in str(c.get("body", "")).upper() for c in comments for marker in
                   ("SAFETY_DENIED", "BLOCKED_SAFETY", "DO_NOT_MERGE", "SAFETY HOLD", "SECURITY HOLD")):
                raise ValueError("Unresolved technical objection")
            row.update(status="EXACT_INTEGRATION_VERIFIED", integration_verified=True,
                       reviewed_base=base, merge_sha=merged, tree_sha=a,
                       independent_reviews_verified=True, exact_ci_verified=True,
                       vm_acceptance_verified=scope in PRODUCT_SCOPES)
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError, SyntaxError):
            row["status"] = "MERGED_BUT_EVIDENCE_INCOMPLETE"
    if admission.api("GET", "/git/ref/heads/dev")["object"]["sha"] != live:
        raise ValueError("Audit base changed; retry")
    return {"schema": "gaslux-operational-integration-audit-v1", "read_only": True,
            "live_dev": live, "bounded_recent_closed_prs": len(prs),
            "findings": findings,
            "verified_integrations": sum(r["integration_verified"] for r in findings),
            "verified_product_integrations": sum(r["integration_verified"] and
                                                r["scope"] in PRODUCT_SCOPES for r in findings),
            "release_eligible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--integrate-test", action="store_true")
    modes.add_argument("--integrate-product", action="store_true")
    modes.add_argument("--independent-safety", action="store_true")
    modes.add_argument("--independent-owner", action="store_true")
    modes.add_argument("--audit-completed-integrations", action="store_true")
    args = parser.parse_args()
    result = (audit_completed_integrations() if args.audit_completed_integrations else
              independent_owner_review() if args.independent_owner else
              independent_safety_review() if args.independent_safety else
              integrate_one(product=True) if args.integrate_product else
              integrate_one() if args.integrate_test else inventory())
    print(json.dumps(result, indent=2, sort_keys=True))
