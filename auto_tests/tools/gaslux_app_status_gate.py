#!/usr/bin/env python3
"""Staged App-status gate migration. Never grants merge or release authority."""
from __future__ import annotations
import argparse
import json
import os
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gaslux_supervised_admission as gate
import gaslux_lab_review_probe as lab

a = gate.admission
ROLES = ("safety", "owner")
CONTEXTS = {k: "gaslux-dev/" + k + "-v1" for k in ROLES}
ACTORS = {"safety": 361554749, "owner": 361556198}
MAX_CANDIDATES = 10
PILOT_CONTEXTS = {k: "gaslux-inert-probe/" + k + "-v1" for k in ROLES}
PILOT_DESCRIPTION = "INERT credential proof; no approval"

def require(value, message):
    if not value:
        raise ValueError(message)

def context(*, publish=False):
    require(os.getenv("GITHUB_REPOSITORY") == a.REPO
            and os.getenv("GITHUB_REF") == "refs/heads/main"
            and os.getenv("GITHUB_EVENT_NAME") in ("push", "schedule", "workflow_dispatch"),
            "Trusted main only")
    if publish:
        require(os.getenv("GASLUX_APP_STATUS_GATES_ENABLED") == "true"
                and os.getenv("GASLUX_AUTONOMY_PAUSED") == "false",
                "Explicit migration flag and explicit unpause required")
    require(a.api("GET", "/git/ref/heads/main")["object"]["sha"] == os.getenv("GITHUB_SHA"),
            "Trusted main checkout stale")

def marker(number, role, base):
    require(type(number) is int and 0 < number <= 1000000
            and role in gate.factory.TASKS and a.valid_sha(base), "Invalid tuple")
    return f"GASLUX dev PR={number} role={role} base={base}"

def status_receipts(head, *, contexts=None):
    """Resolve effective status IDs against the detailed endpoint, fail closed on drift."""
    require(a.valid_sha(head), "Invalid status head")
    contexts = CONTEXTS if contexts is None else contexts
    route = "/commits/" + head
    summary = a.api("GET", route + "/status?per_page=100")
    history = a.api("GET", route + "/statuses?per_page=100")
    again = a.api("GET", route + "/status?per_page=100")
    def snapshot(data):
        require(data["sha"] == head and data["repository"]["id"] == a.REPOSITORY_ID
                and type(data["total_count"]) is int and 0 <= data["total_count"] < 100
                and isinstance(data["statuses"], list)
                and len(data["statuses"]) == data["total_count"], "Incomplete status aggregate")
        return data["statuses"]
    rows = snapshot(summary)
    require(rows == snapshot(again), "Concurrent status change")
    details = a.complete_page(history)
    by_id = {}
    for item in details:
        require(type(item.get("id")) is int and item["id"] not in by_id, "Invalid status ID")
        by_id[item["id"]] = item
    found = {}
    for row in rows:
        kind = next((k for k, v in contexts.items() if v == row["context"]), None)
        if kind is None:
            continue
        detail = by_id.get(row.get("id"))
        require(kind not in found and isinstance(detail, dict)
                and all(row.get(k) == detail.get(k) for k in
                        ("id", "context", "state", "description", "created_at", "updated_at")),
                "Status detail mismatch")
        creator = detail.get("creator")
        require(isinstance(creator, dict) and type(creator.get("id")) is int
                and creator["id"] > 0, "Missing authenticated status creator")
        found[kind] = {"id": row["id"], "state": row["state"],
                       "description": row["description"], "actor": creator["id"],
                       "login": creator.get("login"), "type": creator.get("type")}
    return found

def receipt_ok(receipt, kind, number, role, base):
    return isinstance(receipt, dict) and receipt.get("actor") == ACTORS[kind] and (
        receipt.get("type") == "Bot"
        and receipt.get("login") == "gaslux-independent-" + kind + "[bot]"
        and receipt.get("state") == "success"
        and receipt.get("description") == marker(number, role, base))

def identities():
    safety, owners = gate.configured_reviewers()
    require(safety == ACTORS["safety"] and set(owners) == set(gate.factory.TASKS)
            and set(owners.values()) == {ACTORS["owner"]}, "Unverified production role configuration")
    return safety, owners

def decision(row, kind):
    """No new semantic authority: require existing independent exact reviews.
    Product scopes additionally require existing full VM acceptance.
    """
    if row.get("technical_objection") is True:
        return "failure"
    common = ("exact_scope_verified", "current_base_verified",
              "ci_workflow_provenance_verified", "ci_verified",
              "safety_review_verified", "backend_owner_verified")
    if row.get("technical_objection") is not False or not all(row.get(k) is True for k in common):
        return "pending"
    if gate.eligible_test(row):
        return "success"
    if gate.eligible_product(row):
        return "success"
    return "pending"

def frozen(number, head, base):
    pr = a.api("GET", f"/pulls/{number}")
    require(pr["number"] == number and pr["state"] == "open"
            and pr.get("merged") is False and a.publisher_ok(pr["user"])
            and pr["base"]["ref"] == "dev" and pr["base"]["sha"] == base
            and pr["head"]["sha"] == head
            and pr["base"]["repo"]["id"] == a.REPOSITORY_ID
            and pr["head"]["repo"]["id"] == a.REPOSITORY_ID
            and a.api("GET", "/git/ref/heads/dev")["object"]["sha"] == base,
            "Candidate identity, target or base changed")
    return pr

def plan():
    safety, owners = identities()
    base = a.api("GET", "/git/ref/heads/dev")["object"]["sha"]
    require(a.valid_sha(base), "Invalid dev")
    candidates = gate.discover()
    require(len(candidates) <= MAX_CANDIDATES, "Candidate inventory exceeds bounded review batch")
    findings = []
    for number, (role, scope, head) in sorted(candidates.items()):
        frozen(number, head, base)
        row = gate.inspect(number, role, scope, head, safety, owners[role], allow_ready=True)
        require(row["base"] == base, "Inspection base drift")
        receipts = status_receipts(head)
        findings.append({"pr": number, "role": role, "scope": scope, "head": head, "base": base,
                         "assessment": row, "decisions": {k: decision(row, k) for k in ROLES},
                         "receipts": receipts,
                         "both_statuses_verified": all(receipt_ok(receipts.get(k), k, number, role, base)
                                                       for k in ROLES),
                         "merge_authorized": False})
        frozen(number, head, base)
    require(a.api("GET", "/git/ref/heads/dev")["object"]["sha"] == base, "Inventory drift")
    return {"schema": "gaslux-app-status-plan-v1", "base": base, "candidates": findings,
            "merge_authorized": False, "release_eligible": False}

def publish(kind):
    context(publish=True)
    registration = app_registration(kind)
    require(gate.configured_status_sources().get(CONTEXTS[kind]) == registration["app_id"],
            "Production App registration ID mismatch")
    safety, owners = identities()
    report = plan()
    receipts = []
    for item in report["candidates"]:
        n, role, scope, head, base = (item[k] for k in ("pr", "role", "scope", "head", "base"))
        frozen(n, head, base)
        checked = gate.inspect(n, role, scope, head, safety, owners[role], allow_ready=True)
        require(checked == item["assessment"], "Assessment changed")
        state = decision(checked, kind)
        description = marker(n, role, base) if state == "success" else "GASLUX dev " + state
        old = status_receipts(head).get(kind)
        if old and old.get("actor") == ACTORS[kind] and old.get("type") == "Bot" and (
                old.get("login") == "gaslux-independent-" + kind + "[bot]"
                and old.get("state") == state and old.get("description") == description):
            continue
        context(publish=True)
        frozen(n, head, base)
        result = a.api("POST", "/statuses/" + head,
                       {"context": CONTEXTS[kind], "state": state, "description": description})
        require(result.get("creator", {}).get("id") == ACTORS[kind]
                and result.get("context") == CONTEXTS[kind]
                and result.get("state") == state and result.get("description") == description,
                "Status publication receipt mismatch")
        live = status_receipts(head).get(kind)
        require(live and live["id"] == result["id"] and live["actor"] == ACTORS[kind],
                "Effective status changed")
        frozen(n, head, base)
        receipts.append({"pr": n, "head": head, "base": base, "kind": kind,
                         "decision": state, "status_id": result["id"]})
    return {"schema": "gaslux-app-status-publication-v1", "kind": kind, "receipts": receipts,
            "merge_authorized": False, "release_eligible": False}

def existing_success(kind, row, number):
    """Only invalidate this App's previously issued production approval."""
    if (not isinstance(row, dict) or row.get("actor") != ACTORS[kind]
            or row.get("type") != "Bot" or row.get("state") != "success"
            or row.get("login") != "gaslux-independent-" + kind + "[bot]"):
        return None
    m = re.fullmatch(r"GASLUX dev PR=([1-9][0-9]{0,6}) role=([a-z0-9]+) base=([a-f0-9]{40})",
                     row.get("description") or "")
    if not m or int(m[1]) != number or m[2] not in gate.factory.TASKS:
        return None
    return m[2], m[3]


def revocation_scan(kind):
    """Invalidate known stale production approvals on current open same-repo heads.

    This is a defensive reconciliation pass, not atomic native review
    revocation. Never issue success, never approve/merge, never write on
    arbitrary heads or touch the inert pilot contexts. A missing/incomplete
    scan fails the workflow and blocks the same-cycle Integrator.
    """
    context()
    require(os.getenv("GASLUX_APP_STATUS_GATES_ENABLED") == "true",
            "Production status migration not explicitly configured")
    paused = os.getenv("GASLUX_AUTONOMY_PAUSED")
    require(paused in ("true", "false"), "Explicit pause state required")
    reg = app_registration(kind)
    require(gate.configured_status_sources().get(CONTEXTS[kind]) == reg["app_id"],
            "Unverified revocation identity")
    safety, owners = identities()
    base = a.api("GET", "/git/ref/heads/dev")["object"]["sha"]
    require(a.valid_sha(base), "Invalid revocation base")
    rows = a.complete_page(a.api("GET", "/pulls?state=open&per_page=100"))
    require(len(rows) < 100, "Incomplete revocation inventory")
    discovered = gate.discover() if paused == "false" else {}
    seen = set()
    invalidated = []
    for pr in rows:
        n = pr.get("number")
        require(type(n) is int and 0 < n <= 1000000 and n not in seen,
                "Malformed revocation inventory")
        seen.add(n)
        if ((pr.get("head", {}).get("repo") or {}).get("id") != a.REPOSITORY_ID
                or (pr.get("base", {}).get("repo") or {}).get("id") != a.REPOSITORY_ID
                or not a.publisher_ok(pr.get("user") or {})):
            continue
        head = pr["head"]["sha"]
        require(a.valid_sha(head), "Malformed publisher head")
        old = status_receipts(head).get(kind)
        issued = existing_success(kind, old, n)
        if issued is None:
            continue
        role, issued_base = issued
        found = discovered.get(n)
        keep = False
        if (paused == "false" and pr["base"]["ref"] == "dev"
                and pr["base"]["sha"] == base == issued_base
                and found is not None and found[0] == role and found[2] == head):
            row = gate.inspect(n, role, found[1], head, safety, owners[role], allow_ready=True)
            keep = row["base"] == base and decision(row, kind) == "success"
        if keep:
            continue
        context()
        fresh = a.api("GET", f"/pulls/{n}")
        require(fresh.get("state") == "open" and fresh["head"]["sha"] == head
                and fresh["head"]["repo"]["id"] == a.REPOSITORY_ID
                and fresh["base"]["repo"]["id"] == a.REPOSITORY_ID
                and a.publisher_ok(fresh["user"])
                and status_receipts(head).get(kind) == old,
                "Revocation candidate or receipt changed")
        description = "GASLUX dev authorization revoked"
        result = a.api("POST", "/statuses/" + head, {
            "context": CONTEXTS[kind], "state": "failure", "description": description})
        live = status_receipts(head).get(kind)
        require(result.get("creator", {}).get("id") == ACTORS[kind]
                and result.get("context") == CONTEXTS[kind]
                and result.get("state") == "failure"
                and result.get("description") == description
                and live and live["id"] == result["id"]
                and live["actor"] == ACTORS[kind] and live["state"] == "failure",
                "Revocation receipt unverified")
        invalidated.append({"pr": n, "head": head, "status_id": result["id"]})
    require(a.api("GET", "/git/ref/heads/dev")["object"]["sha"] == base,
            "Revocation base changed")
    return {"schema": "gaslux-status-revocation-scan-v1", "kind": kind,
            "base": base, "paused": paused == "true", "scanned": len(rows),
            "invalidated": invalidated, "atomic_native_revocation_verified": False,
            "merge_authorized": False}


def activation_audit():
    """Read-only preflight even during pause. Never emits merge authority."""
    context()
    base = a.api("GET", "/git/ref/heads/dev")["object"]["sha"]
    require(a.valid_sha(base), "Invalid dev")
    report = {
        "schema": "gaslux-production-activation-audit-v1", "base": base,
        "main_and_target_policy_observed": gate.production_policy_observed(base),
        "source_pinned_dev_policy_observed": gate.strict_ruleset_protected(
            base, require_app_statuses=True),
        "native_named_role_gate_retained": True,
        "native_named_role_enforcement_verified": False,
        "atomic_native_revocation_verified": False,
        "production_merge_authorized": False, "release_eligible": False,
    }
    require(a.api("GET", "/git/ref/heads/dev")["object"]["sha"] == base, "Audit base changed")
    return report


def pilot_context():
    lab.context()
    require(os.getenv("GASLUX_STATUS_PILOT_ENABLED") == "true"
            and os.getenv("GASLUX_APP_STATUS_GATES_ENABLED") != "true",
            "Explicit isolated pilot opt-in; production status migration disabled")
    require(lab.actors() == ACTORS, "Unexpected pilot actor configuration")
    require(lab.candidate()["state"] == "open", "Frozen inert fixture not open")
    require(set(lab.verified_reviews(ACTORS)) == set(ROLES), "Exact independent fixture reviews absent")


def pilot_ok(row, kind):
    return isinstance(row, dict) and row.get("actor") == ACTORS[kind] and (
        row.get("type") == "Bot" and row.get("login") == "gaslux-independent-" + kind + "[bot]"
        and row.get("state") == "success" and row.get("description") == PILOT_DESCRIPTION)


def app_registration(kind):
    require(kind in ROLES, "Invalid App role")
    reg = gate.review_app_actor(kind, status_permission=True, registration=True)
    require(isinstance(reg, dict) and reg.get("actor") == ACTORS[kind]
            and reg.get("slug") == "gaslux-independent-" + kind
            and type(reg.get("app_id")) is int and reg["app_id"] > 0
            and reg["app_id"] not in (15368, 5938492, 5938509, *ACTORS.values()),
            "Wrong independent production App registration")
    return reg


def pilot_publish(kind):
    require(kind in ROLES, "Invalid pilot role")
    pilot_context()
    registration = app_registration(kind)
    old = status_receipts(lab.HEAD, contexts=PILOT_CONTEXTS).get(kind)
    if not pilot_ok(old, kind):
        pilot_context()
        # Sole permitted pilot write: exclusive context, exact inert HEAD.
        result = a.api("POST", "/statuses/" + lab.HEAD,
                       {"context": PILOT_CONTEXTS[kind], "state": "success",
                        "description": PILOT_DESCRIPTION})
        require(result.get("creator", {}).get("id") == ACTORS[kind]
                and result.get("context") == PILOT_CONTEXTS[kind]
                and result.get("state") == "success"
                and result.get("description") == PILOT_DESCRIPTION,
                "Pilot publication receipt mismatch")
        expected = result["id"]
    else:
        expected = old["id"]
    live = status_receipts(lab.HEAD, contexts=PILOT_CONTEXTS).get(kind)
    require(pilot_ok(live, kind) and live["id"] == expected, "Pilot receipt changed")
    pilot_context()
    return {"schema": "gaslux-inert-status-pilot-v1", "pr": lab.NUMBER,
            "head": lab.HEAD, "base": lab.BASE, "kind": kind, "status_id": expected,
            "app_registration_id": registration["app_id"],
            "credential_verified": True, "merge_authorized": False,
            "production_gate_verified": False, "release_eligible": False}


def pilot_audit():
    pilot_context()
    rows = status_receipts(lab.HEAD, contexts=PILOT_CONTEXTS)
    require(all(pilot_ok(rows.get(k), k) for k in ROLES), "Both genuine pilot receipts required")
    pilot_context()
    return {"schema": "gaslux-inert-status-pilot-audit-v1", "pr": lab.NUMBER,
            "head": lab.HEAD, "base": lab.BASE, "receipts": rows,
            "credential_verified": True, "merge_authorized": False,
            "production_gate_verified": False, "release_eligible": False}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--publish", choices=ROLES)
    modes.add_argument("--pilot-publish", choices=ROLES)
    modes.add_argument("--pilot-audit", action="store_true")
    modes.add_argument("--activation-audit", action="store_true")
    modes.add_argument("--revoke-stale", choices=ROLES)
    args = p.parse_args()
    if args.pilot_publish:
        report = pilot_publish(args.pilot_publish)
    elif args.pilot_audit:
        report = pilot_audit()
    elif args.activation_audit:
        report = activation_audit()
    elif args.revoke_stale:
        report = revocation_scan(args.revoke_stale)
    else:
        context(publish=bool(args.publish))
        report = publish(args.publish) if args.publish else plan()
    print(json.dumps(report, sort_keys=True))
