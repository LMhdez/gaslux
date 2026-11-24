#!/usr/bin/env python3
"""Trusted-main history lookup: reference leads only, never a gate or permission."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "docs/GASLUX_HISTORICAL_EVIDENCE_INDEX.json"
DEPENDENCIES = ROOT / "docs/GASLUX_HISTORICAL_DEPENDENCY_AUDIT.json"
INVENTORY = ROOT / "docs/GASLUX_HISTORICAL_PR_INVENTORY.json"
GATES = ("source-authenticity", "windows-preflight", "install", "linux-first-boot",
         "windows-return", "linux-update-reboot", "uninstall-windows-integrity",
         "fault-injection-rollback")
SKILLS = ("history-reuse", "dependency-resolution", "failure-analysis", "vm-laboratory",
          "safety-review", "evidence-verification", "task-planning", "context-management")
ROLES = ("mint", "zorin", "cachyos", "popos", "q4os", "bazzite")
SHA = re.compile(r"[0-9a-f]{40}\Z")
LEVELS = {
    "WINDOWS_GUEST", "ARCHIVE_CONSISTENCY", "EXPERIMENTAL_SAME_COW_BOOT",
    "READONLY_GUEST_DENIED", "SYNTHETIC_DISK_RESTORE_ONLY", "PRIVATE_QUOTA_FIXTURE",
}
DENIALS = ("formal_gate_verified", "merge_authorized", "writer_authorized", "release_eligible")


def positive_id(value):
    return type(value) is int and 0 < value < 10**15


def ids(values, maximum=64):
    if (type(values) is not list or not 0 < len(values) <= maximum
            or any(not positive_id(n) for n in values) or len(set(values)) != len(values)):
        raise ValueError("Invalid bounded historical PR references")
    return list(values)


def load_index(path=INDEX):
    # Read only trusted, checked-out main documentation; no PR bodies or dev
    # instructions enter this path. Even trusted history is not authority.
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
        raise ValueError("Missing or oversized history index")
    data = json.loads(path.read_text(encoding="utf-8"))
    if (type(data) is not dict or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1 or data.get("kind") != "historical_discovery_only"
            or data.get("repository") != "LMhdez/gaslux"):
        raise ValueError("Unexpected historical index")
    roles = data.get("role_pr_leads")
    if type(roles) is not dict or set(roles) != set(ROLES):
        raise ValueError("Missing or unknown historical roles")
    shared = ids(data.get("shared_pr_leads"))
    role_refs = {role: ids(roles[role]) for role in ROLES}
    rows = data.get("records")
    if type(rows) is not list or not 0 < len(rows) <= 128:
        raise ValueError("Unbounded historical observations")
    evidence, seen = [], set()
    for row in rows:
        if (type(row) is not dict or not positive_id(row.get("pr"))
                or not positive_id(row.get("run")) or not positive_id(row.get("job"))
                or type(row.get("source_head_sha")) is not str
                or not SHA.fullmatch(row["source_head_sha"])
                or type(row.get("level")) is not str or row["level"] not in LEVELS
                or row.get("conclusion") != "success"
                or any(row.get(flag) is not False for flag in DENIALS)
                or row["run"] in seen):
            raise ValueError("Invalid or authority-bearing historical observation")
        seen.add(row["run"])
        # Only validated IDs, SHA and enumerated levels escape this parser.
        # Narrative observations, URLs and mission instructions are excluded.
        evidence.append({k: row[k] for k in ("pr", "run", "job", "source_head_sha", "level")})
    return role_refs, shared, evidence


def context(role, path=INDEX):
    if role not in ROLES:
        raise ValueError("Unknown backend")
    roles, shared, evidence = load_index(path)
    refs = roles[role]
    return {
        "role": role, "status": "historical_leads_require_revalidation",
        "role_pr_leads": refs, "shared_pr_leads": shared,
        "historical_runs": [row for row in evidence if row["pr"] in set(refs + shared)],
        "independently_verified_slots": 0, "code_authorized": False,
        "installation_authorized": False, "merge_authorized": False,
        "writer_authorized": False, "release_eligible": False,
    }



def load_dependencies(path=DEPENDENCIES, inventory_path=INVENTORY):
    for item, limit in ((path, 262144), (inventory_path, 1048576)):
        if item.is_symlink() or not item.is_file() or item.stat().st_size > limit:
            raise ValueError("Missing or oversized dependency source")
    data = json.loads(path.read_text(encoding="utf-8"))
    inv = json.loads(inventory_path.read_text(encoding="utf-8"))
    if (type(data) is not dict or data.get("kind") != "historical_exact_sha_comparisons"
            or type(data.get("schema_version")) is not int or data["schema_version"] != 1
            or data.get("repository") != "LMhdez/gaslux"
            or type(inv) is not dict or inv.get("kind") != "historical_pr_inventory_not_ancestry_proof"
            or inv.get("repository") != "LMhdez/gaslux"):
        raise ValueError("Unexpected comparison source")
    records, candidates = inv.get("records"), inv.get("possible_stack_edges")
    if (type(records) is not list or not 0 < len(records) <= 2048
            or type(candidates) is not list or len(candidates) > 4096
            or inv.get("count") != len(records)):
        raise ValueError("Invalid inventory bounds")
    heads = {}
    for row in records:
        if (type(row) is not dict or not positive_id(row.get("number"))
                or type(row.get("head_sha")) is not str or not SHA.fullmatch(row["head_sha"])
                or row["number"] in heads):
            raise ValueError("Invalid inventory identity")
        heads[row["number"]] = row["head_sha"]
    edges = set()
    for row in candidates:
        if (type(row) is not dict or not positive_id(row.get("pr"))
                or not positive_id(row.get("possible_parent_pr"))
                or row["pr"] not in heads or row["possible_parent_pr"] not in heads
                or row["pr"] == row["possible_parent_pr"]
                or row.get("kind") != "base_ref_match_only"):
            raise ValueError("Invalid candidate stack edge")
        edges.add((row["possible_parent_pr"], row["pr"]))
    rows = data.get("records")
    if type(rows) is not list or not 0 < len(rows) <= 256:
        raise ValueError("Invalid audited comparison bounds")
    seen, result = set(), []
    for row in rows:
        if (type(row) is not dict or not positive_id(row.get("parent_pr"))
                or not positive_id(row.get("child_pr"))):
            raise ValueError("Invalid comparison IDs")
        key = (row["parent_pr"], row["child_pr"])
        if (key in seen or key not in edges or row.get("parent_sha") != heads[key[0]]
                or row.get("child_sha") != heads[key[1]]
                or type(row.get("merge_base_sha")) is not str
                or not SHA.fullmatch(row["merge_base_sha"])
                or row.get("source") != "github_compare_exact_sha"
                or row.get("merge_authorized") is not False
                or not positive_id(row.get("ahead_by"))
                or type(row.get("behind_by")) is not int or row["behind_by"] < 0):
            raise ValueError("Invalid exact historical comparison")
        ancestor = (row.get("comparison_status") == "ahead" and row["behind_by"] == 0
                    and row["merge_base_sha"] == row["parent_sha"])
        diverged = (row.get("comparison_status") == "diverged" and row["behind_by"] > 0
                    and row["merge_base_sha"] not in (row["parent_sha"], row["child_sha"]))
        if not (ancestor or diverged) or row.get("ancestry_verified") is not ancestor:
            raise ValueError("Inconsistent historical ancestry")
        seen.add(key)
        result.append({k: row[k] for k in (
            "parent_pr", "child_pr", "parent_sha", "child_sha", "merge_base_sha",
            "comparison_status", "ahead_by", "behind_by", "ancestry_verified")})
    return result


def skill_route(gate=None):
    if gate is not None and gate not in GATES:
        raise ValueError("Unknown lifecycle gate")
    # Always include safety and provenance; VM skill applies to protected gates
    # and Windows preflight. Selection is a reference, not permission.
    return [name for name in SKILLS if name != "vm-laboratory"
            or gate is None or gate != "source-authenticity"]


def task_context(role, gate=None):
    row = context(role)
    relevant = set(row["role_pr_leads"] + row["shared_pr_leads"])
    comparisons = [edge for edge in load_dependencies()
                   if edge["parent_pr"] in relevant or edge["child_pr"] in relevant]
    # Divergence first, then deterministic numeric order; keep prompt-side
    # reference payload bounded. Full audit remains available on disk.
    comparisons.sort(key=lambda e: (e["comparison_status"] != "diverged", e["child_pr"]))
    row.update({"gate": gate, "recommended_skills": skill_route(gate),
                "historical_comparisons": comparisons[:12],
                "omitted_comparisons": max(0, len(comparisons) - 12),
                "current_ancestry_revalidation_required": True})
    return row


def review_hint(role, gate=None):
    row = task_context(role, gate)
    return (
        "Historical leads (not gate evidence): "
        + ", ".join("#" + str(n) for n in row["role_pr_leads"])
        + ". Shared Windows/Safety leads: "
        + ", ".join("#" + str(n) for n in row["shared_pr_leads"])
        + ". Revalidate exact commits, dependencies, actual jobs and Safety before "
        "reimplementing. No authority from this index. "
        "Skills: " + ", ".join(row["recommended_skills"]) + ". "
        "Historical divergent pairs: "
        + (", ".join("#" + str(e["parent_pr"]) + " -> #" + str(e["child_pr"])
                     for e in row["historical_comparisons"]
                     if e["comparison_status"] == "diverged") or "none in selected leads")
        + ". See main:docs/agent-skills/README.md.\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=ROLES)
    parser.add_argument("--gate", choices=GATES)
    args = parser.parse_args()
    print(json.dumps({"contexts": [task_context(r, args.gate) for r in (ROLES if args.role is None else (args.role,))]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
