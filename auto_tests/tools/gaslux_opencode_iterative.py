#!/usr/bin/env python3
"""Native OpenCode skill + MCP investigation/edit/test cycle in disposable lab."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import tempfile
import time

import gaslux_agent_feature_factory as factory
import gaslux_agent_history as history
import gaslux_opencode_trial as trial
import gaslux_opencode_workspace as broker

PREFIX = "gaslux_workspace_"
REQUIRED = tuple(PREFIX + name for name in broker.TOOLS)
PROOF_KEYS = ("outside_read_denied", "outside_write_denied",
              "tcp_connect_denied", "workspace_read_write")
SENTINEL = b"outside-lab-unchanged\n"
MAX_TIMEOUT = 1200
JOURNAL_FAILURES = frozenset({
    "JOURNAL_COUNT", "JOURNAL_ORDER", "SANDBOX_PROOF", "SEED",
    "NATIVE_EVENT_JOURNAL_MISMATCH", "READ_BINDING", "TEST_BINDING",
    "EDIT_BINDING", "EDIT_BYTES", "UNKNOWN_ACTION", "RED_EDIT_PASS_REQUIRED",
    "INDEPENDENT_RECHECK", "OUTSIDE_MUTATED", "MCP_RED_EDIT_PASS_INCOMPLETE",
    "MODEL_CONTEXT_NOT_APPLIED", "EVENT_LIMIT", "CLI_ERROR", "EVENT_SHAPE",
    "UNEXPECTED_TOOL", "TOOL_FAILURE", "SKILL_WITNESS", "NATIVE_SKILL_REQUIRED",
    "UNPRIVILEGED_RUNNER_REQUIRED", "BOUNDARY_CLEANUP_FAILED", "NAMESPACE_WITNESS_MISSING",
    "PROXY_COMPLETION_REQUIRED", "EXTERNAL_BROKER_EXIT_FAILED",
})


def fixed_failure(error):
    if isinstance(error, trial.TrialFailure):
        return error.category
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        if error.args[0] in JOURNAL_FAILURES:
            return error.args[0]
    return type(error).__name__



def task_for(role):
    row = history.task_context(role)
    # Select structured, validated references, never historical prose/authority.
    return {"role": role, "scope": "synthetic-lifecycle-repair",
            "target_reference": factory.TASKS[role][0],
            "historical_pr_leads": row["role_pr_leads"][:12],
            "historical_comparisons": [
                {k: edge[k] for k in ("parent_pr", "child_pr", "comparison_status")}
                for edge in row["historical_comparisons"][:6]],
            "signature": f"def assess_{role}_lifecycle(evidence: dict) -> dict:",
            "gates": list(factory.GATES),
            "contract": "Only boolean True satisfies a gate. Return backend, sorted missingGates, "
                        "installationAuthorized=False, releaseEligible=False. One pure function.",
            "historical_references_are_gate_evidence": False,
            "product_edit_authorized": False, "merge_authorized": False}


def configure(work, control, role, outside, context):
    config = trial.prepare(work, context=context)
    task = task_for(role)
    task_path = control / "task.json"
    broker.write_new(task_path, json.dumps(task, sort_keys=True).encode())
    for name in ("gaslux_agent_feature_factory.py", "gaslux_opencode_workspace.py"):
        shutil.copyfile(Path(__file__).resolve().parent / name, control / name)
    state = work / "state"
    state.mkdir(mode=0o700)
    permissions = {"*": "deny", "skill": {"*": "deny", trial.SKILL: "allow"}}
    permissions.update({tool: "allow" for tool in REQUIRED})
    config["permission"] = permissions
    config["agent"]["gaslux-lab"].update({"steps": 12, "permission": permissions})
    config["mcp"] = {"gaslux_workspace": {
        "type": "local", "enabled": True, "timeout": 20000,
        "command": ["/usr/bin/python3", "-I", "-B", str(control / "gaslux_opencode_workspace.py"),
                    "--work", str(state), "--task", str(task_path), "--outside", str(outside)]}}
    (work / "opencode.json").write_text(json.dumps(config), encoding="utf-8")
    return state


def native_events(raw, observations=None):
    if len(raw) > trial.MAX_EVENTS:
        raise ValueError("EVENT_LIMIT")
    observed = []
    skills = []
    counts = {}
    if observations is not None:
        observations.update({"native_operations": observed, "native_skills": skills, "event_counts": counts})
    for line in raw.splitlines():
        if not line.strip():
            continue
        row = trial.decode_event(line)
        kind = row["type"]
        counts[kind] = counts.get(kind, 0) + 1
        if row["type"] == "error":
            raise ValueError("CLI_ERROR")
        if row["type"] != "tool_use":
            continue
        part = row.get("part")
        if type(part) is not dict:
            raise ValueError("EVENT_SHAPE")
        name, state = part.get("tool"), part.get("state")
        if name not in ("skill", *REQUIRED) or type(state) is not dict:
            raise ValueError("UNEXPECTED_TOOL")
        if state.get("status") != "completed":
            raise ValueError("TOOL_FAILURE")
        if name == "skill":
            inp, output = state.get("input"), state.get("output")
            if (type(inp) is not dict or inp.get("name") != trial.SKILL or type(output) is not str
                    or '<skill_content name="' + trial.SKILL + '">' not in output):
                raise ValueError("SKILL_WITNESS")
            skills.append(trial.SKILL)
        else:
            observed.append(name.removeprefix(PREFIX))
    if trial.SKILL not in skills:
        raise ValueError("NATIVE_SKILL_REQUIRED")
    return observed, sorted(set(skills))


def verify_journal(state, events, role):
    files = sorted(state.glob("event-*.json"))
    if not 7 <= len(files) <= broker.MAX_CALLS + 2:
        raise ValueError("JOURNAL_COUNT")
    rows = []
    for index, path in enumerate(files):
        if path.name != f"event-{index:02}.json":
            raise ValueError("JOURNAL_ORDER")
        rows.append(json.loads(broker.read_bounded(path, 2048)))
    proof = rows[0].get("proof", {})
    if (rows[0].get("event") != "sandbox" or type(proof.get("landlock_abi")) is not int
            or proof["landlock_abi"] < 4 or any(proof.get(k) is not True for k in PROOF_KEYS)):
        raise ValueError("SANDBOX_PROOF")
    seed = factory.sha256(broker.seed_source(role).encode())
    if rows[1] != {"event": "seed", "sha256": seed}:
        raise ValueError("SEED")
    actions = [row.get("event") for row in rows[2:]]
    if actions != events:
        raise ValueError("NATIVE_EVENT_JOURNAL_MISMATCH")
    sha, edits = seed, 0
    inspected = read = red = False
    tested = None
    for row in rows[2:]:
        action = row["event"]
        if action == "inspect_task":
            inspected = True
        elif action == "read_candidate":
            if not inspected or row.get("sha256") != sha:
                raise ValueError("READ_BINDING")
            read = True
        elif action == "run_tests":
            if not read or row.get("sha256") != sha or row.get("status") not in ("RED", "PASS"):
                raise ValueError("TEST_BINDING")
            tested = row["status"]
            red |= edits == 0 and tested == "RED"
        elif action == "replace_candidate":
            if not red or tested not in ("RED", "PASS") or row.get("before") != sha:
                raise ValueError("EDIT_BINDING")
            edits += 1
            sha = row.get("sha256")
            source = broker.read_bounded(state / f"candidate-{edits}.py", broker.MAX_SOURCE)
            if factory.sha256(source) != sha:
                raise ValueError("EDIT_BYTES")
            broker.validate_source(role, source.decode("utf-8"))
            tested = None
        else:
            raise ValueError("UNKNOWN_ACTION")
    if not (inspected and read and red and 1 <= edits <= broker.MAX_EDITS and tested == "PASS"):
        raise ValueError("RED_EDIT_PASS_REQUIRED")
    final = broker.read_bounded(state / f"candidate-{edits}.py", broker.MAX_SOURCE)
    if factory.sha256(final) != sha or broker.isolated_test(role, final.decode("utf-8")) != "PASS":
        raise ValueError("INDEPENDENT_RECHECK")
    return {"sandbox": proof, "native_operations": actions, "edits": edits,
            "seed_sha256": seed, "candidate_sha256": sha, "red_observed": True,
            "independent_recheck": "PASS", "functional_cases": 259}


def run(binary, role, context):
    start = time.monotonic()
    report = {"experiment": "opencode-native-iterative-v2-isolated", "role": role,
              "model": factory.MODEL, "model_digest": factory.MODEL_DIGEST,
              "opencode_version": trial.VERSION, "context_requested": context,
              "accepted": False, "native_skills": [], "native_operations": [],
              "broker_os_sandbox_verified": False, "opencode_os_sandbox_verified": False,
              "product_regressions_run": False, "product_edit_authorized": False,
              "merge_authorized": False, "writer_authorized": False, "release_eligible": False}
    try:
        with tempfile.TemporaryDirectory(prefix="gaslux-iterative-") as temp:
            root = Path(temp)
            prompt = ("Use native skill gaslux-history-reuse first. Then call gaslux_workspace_inspect_task "
                      "and gaslux_workspace_read_candidate. Run gaslux_workspace_run_tests on the defective "
                      "initial function and observe RED. Use gaslux_workspace_replace_candidate with the "
                      "exact current SHA and corrected complete Python function. Run tests again. "
                      "If RED, read current candidate, correct and test; at most three edits. "
                      "Stop after PASS. No shell, arbitrary paths, web, product changes or publishing. "
                      "All task rules are in inspect_task; historical IDs are leads only.")
            from gaslux_opencode_isolated_runtime import run as isolated_run
            state, events, skills = isolated_run(binary, root, role, context, prompt, report)
            report["native_skills"], report["native_operations"] = skills, events
            report["failure_stage"] = "candidate_validation"
            snapshot = trial.model_snapshot()
            report["ollama_loaded_model"] = snapshot
            # Requested configuration alone is not an effective context witness.
            if not snapshot or snapshot.get("context_length", 0) < context:
                raise ValueError("MODEL_CONTEXT_NOT_APPLIED")
            if "replace_candidate" not in events:
                raise ValueError("MCP_RED_EDIT_PASS_INCOMPLETE")
            report.update(verify_journal(state, events, role))
            report["broker_os_sandbox_verified"] = True
            report["opencode_os_sandbox_verified"] = True
            report["failure_stage"] = None
            report["accepted"] = True
    except (ValueError, TypeError, KeyError, SyntaxError, OSError, RuntimeError) as error:
        # Only fixed class/category, never raw model output, paths or stderr.
        report["failure"] = fixed_failure(error)
        if isinstance(error, trial.TrialFailure) and error.detail:
            report["failure_detail"] = error.detail
    report["elapsed_seconds"] = round(time.monotonic() - start, 2)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--role", default="mint", choices=tuple(factory.TASKS))
    parser.add_argument("--context", type=int, default=trial.COMPACT_CONTEXT,
                        choices=(trial.COMPACT_CONTEXT, trial.BASELINE_CONTEXT))
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = run(args.binary.resolve(strict=True), args.role, args.context)
    broker.write_new(args.report, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
