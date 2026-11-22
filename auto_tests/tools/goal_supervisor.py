#!/usr/bin/env python3
"""Fail-closed, read-only Gaslux delivery-goal planner.

Reads explicit project acceptance criteria and provenance records, chooses
the next unmet gate and emits an auditable JSON report. Does not execute
generated source, trust model opinions, write to GitHub, or grant release
authority. A record is REPORTED evidence, not an independent certification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

DEFAULT_GOAL = Path("docs/autonomy/goal.json")
DEFAULT_EVIDENCE = Path("docs/autonomy/evidence.json")
DEFAULT_OUTPUT = Path("evidence/goal-progress.json")
SHA = re.compile(r"^[0-9a-f]{40}$")
GITHUB_ACTION = re.compile(r"^https://github\.com/LMhdez/gaslux/actions/runs/[0-9]+$")
GITHUB_REVIEW = re.compile(r"^https://github\.com/LMhdez/gaslux/pull/[0-9]+(?:#.*)?$")
ALLOWED_PLATFORMS = frozenset({
    "windows10-bios-mbr", "windows10-uefi-gpt", "windows11-uefi-gpt"
})


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError(f"Wrong schema version or object: {path}")
    return value


def validate(goal: dict, evidence: dict) -> tuple[list[dict], set[tuple[str, str, str]]]:
    backends = goal["backends"]
    gates = goal["gates"]
    safe = set(goal["automatic_safe_gates"])
    guarded = set(goal["protected_gates"])
    if not backends or len({b["id"] for b in backends}) != len(backends):
        raise ValueError("Missing or duplicate backends")
    if len(set(gates)) != len(gates) or set(gates) != safe | guarded or safe & guarded:
        raise ValueError("Every acceptance gate must have exactly one safety class")
    if set(goal["platforms"]) != ALLOWED_PLATFORMS:
        raise ValueError("Unsupported or missing Windows platform")
    all_tasks = []
    valid = set()
    for backend in sorted(backends, key=lambda b: b["priority"]):
        if backend["id"] == "bazzite" and "windows10-bios-mbr" in backend["platforms"]:
            raise ValueError("Bazzite BIOS/MBR must remain rejected")
        if not set(backend["platforms"]) <= ALLOWED_PLATFORMS:
            raise ValueError("Unsupported backend platform")
        for platform in goal["platforms"]:
            if platform not in backend["platforms"]:
                continue
            for gate in gates:
                key = (backend["id"], platform, gate)
                valid.add(key)
                all_tasks.append({
                    "backend": backend["id"],
                    "platform": platform,
                    "gate": gate,
                    "issue_numbers": backend.get("issue_numbers", []),
                    "safety_class": "read_only_research" if gate in safe else "independent_safety_gate",
                })
    if not all_tasks:
        raise ValueError("Empty release acceptance matrix")
    if not isinstance(evidence.get("records"), list):
        raise ValueError("Evidence records must be a list")
    recorded = set()
    for entry in evidence["records"]:
        if not isinstance(entry, dict):
            raise ValueError("Bad evidence record")
        key = (entry.get("backend"), entry.get("platform"), entry.get("gate"))
        if key not in valid or key in recorded:
            raise ValueError("Unknown, unsupported, or duplicate evidence gate")
        # Provenance and independent review references are required, but these
        # strings are not independently verified by this report generator.
        if not SHA.fullmatch(entry.get("head_sha", "")):
            raise ValueError("Invalid evidence commit SHA")
        if not GITHUB_ACTION.fullmatch(entry.get("ci_url", "")):
            raise ValueError("Invalid CI evidence URL")
        if not GITHUB_REVIEW.fullmatch(entry.get("review_url", "")):
            raise ValueError("Missing independent review reference")
        if entry.get("status") != "independently_reviewed":
            raise ValueError("Unreviewed result cannot complete an acceptance gate")
        recorded.add(key)
    return all_tasks, recorded


def evaluate(goal: dict, evidence: dict) -> dict:
    tasks, recorded = validate(goal, evidence)
    remaining = [
        {**task, "state": "missing_reviewed_evidence"}
        for task in tasks
        if (task["backend"], task["platform"], task["gate"]) not in recorded
    ]
    next_safe = next(
        (entry for entry in remaining if entry["safety_class"] == "read_only_research"), None
    )
    next_gate = remaining[0] if remaining else None
    return {
        "project": goal["project"],
        "objective": goal["objective"],
        "complete": not remaining,
        "total_required_gates": len(tasks),
        "recorded_reviewed_gates": len(recorded),
        "remaining_gates": len(remaining),
        "next_gate": next_gate,
        "next_auto_research": next_safe,
        "blocked_for_automerge": True,
        "release_eligible": False,
        "evidence_assurance": (
            "Recorded references are schema-checked, NOT fetched or "
            "independently verified by this tool; a separate Safety "
            "verifier and release gate remain mandatory."
        ),
        "allowed_automation": (
            "Read-only diagnostics, isolated tests, bounded experimental "
            "patch proposals. No production install, arbitrary code merge "
            "or release promotion."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--goal", type=Path, default=DEFAULT_GOAL)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = evaluate(load_json(args.goal), load_json(args.evidence))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
