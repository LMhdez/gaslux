#!/usr/bin/env python3
"""Trusted-main history lookup: reference leads only, never a gate or permission."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "docs/GASLUX_HISTORICAL_EVIDENCE_INDEX.json"
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


def review_hint(role):
    row = context(role)
    return (
        "Historical leads (not gate evidence): "
        + ", ".join("#" + str(n) for n in row["role_pr_leads"])
        + ". Shared Windows/Safety leads: "
        + ", ".join("#" + str(n) for n in row["shared_pr_leads"])
        + ". Revalidate exact commits, dependencies, actual jobs and Safety before "
        "reimplementing. No authority from this index. "
        "See main:docs/agent-skills/history-reuse/SKILL.md.\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=ROLES)
    args = parser.parse_args()
    print(json.dumps({"contexts": [context(r) for r in (ROLES if args.role is None else (args.role,))]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
