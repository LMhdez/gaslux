#!/usr/bin/env python3
"""Bounded local AI candidate repair for Observer screenshot-ranking utility.

No GitHub write token. Never edits repository code on disk. On pull_request,
a seeded fault is tested exclusively in memory. On trusted dev execution,
the existing source must fail an independent functional assertion first.
Only one sorted(...) return-line replacement is in scope.
"""
from __future__ import annotations

import ast
import difflib
import json
import os
from pathlib import Path
import sys
import time

import structured_coder_probe as engine


TASK = engine.TASKS[0]
TARGET = TASK["path"]
SIMULATE = os.environ.get("GASLUX_RANK_SIMULATE") == "1"
REPORT = Path("evidence/ai-rank-repair.json")
CANDIDATE = Path("evidence/ai-rank-candidate.py")
MAX_ATTEMPTS = 2


def candidate_function_and_line(source: str) -> str:
    tree = ast.parse(source)
    functions = [x for x in tree.body
                 if isinstance(x, ast.FunctionDef) and x.name == "ranked_changes"]
    if len(functions) != 1:
        raise ValueError("Expected one ranked_changes function")
    result = [n for n in ast.walk(functions[0])
              if isinstance(n, ast.Return)
              and isinstance(n.value, ast.Call)
              and isinstance(n.value.func, ast.Name)
              and n.value.func.id == "sorted"]
    if len(result) != 1:
        raise ValueError("Expected one sorted return")
    return source.splitlines()[result[0].lineno - 1].strip()


def test(source: str) -> tuple[bool, str]:
    return engine.run_rank_test(source)


def preflight() -> int:
    if SIMULATE:
        print("needs_model=true; reason=disposable PR simulation")
        return 2
    source = TARGET.read_text()
    try:
        ok, diagnosis = test(source)
    except Exception as exc:
        print("needs_model=false; unsupported baseline:", type(exc).__name__)
        return 1
    print("needs_model=" + ("false" if ok else "true"))
    print(diagnosis)
    return 0 if ok else 2


def main() -> int:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    original = TARGET.read_bytes()
    source = original.decode("utf-8")
    report = {
        "model": engine.MODEL, "target": str(TARGET),
        "source_sha256": engine.sha256(original), "simulated": SIMULATE,
        "passed": False, "attempts": [], "status": "started",
    }
    result = 1
    try:
        if SIMULATE:
            if source.count(TASK["good"]) != 1:
                raise ValueError("Seed fixture changed: no known good source")
            source = source.replace(TASK["good"], TASK["fault"], 1)
        ok, diagnosis = test(source)
        report["baseline_red"] = not ok
        if ok:
            report["status"] = "idle" if not SIMULATE else "invalid_simulation"
            return 0 if not SIMULATE else 1
        suspect = candidate_function_and_line(source)
        prompt = (
            "You are fixing a regression in the Gaslux Observer screenshot frame "
            "ranking utility. Only ONE single-line code change is permitted. "
            "Return JSON with old_line and new_line as one-line Python strings. "
            "old_line MUST be the following exact existing line; new_line MUST be "
            "a corrected replacement return statement. No explanation, no "
            "full file. Patch must satisfy the independent functional test.\n"
            "CURRENT LINE:\n" + suspect + "\n"
            "CURRENT FUNCTION:\n" + engine.extract_function(source, "ranked_changes")
            + "\nFAILING TEST:\n" + diagnosis + "\n"
        )
        for attempt in range(1, MAX_ATTEMPTS + 1):
            entry = {"attempt": attempt, "passed": False}
            report["attempts"].append(entry)
            try:
                response = engine.ask(prompt)
                entry["model_seconds"] = round(response.get("total_duration", 0) / 1e9, 3)
                patch = json.loads(response.get("response", ""))
                entry["response"] = patch
                if set(patch) != {"old_line", "new_line"} or patch["old_line"].strip() != suspect:
                    raise ValueError("Model response does not target the exact suspect line")
                updated = engine.apply_candidate(source, TASK, patch["old_line"], patch["new_line"])
                green, failure = test(updated)
                if not green:
                    raise AssertionError("GREEN test failed: " + failure[:300])
                report["passed"] = True
                report["status"] = "simulated_green" if SIMULATE else "candidate_green"
                report["candidate_sha256"] = engine.sha256(updated.encode())
                report["diff"] = "".join(difflib.unified_diff(
                    source.splitlines(keepends=True), updated.splitlines(keepends=True),
                    fromfile="baseline", tofile="candidate"))
                if not SIMULATE:
                    CANDIDATE.write_text(updated)
                entry["passed"] = True
                result = 0
                break
            except Exception as exc:
                entry["error"] = f"{type(exc).__name__}: {str(exc)[:250]}"
                prompt += "\nPrevious candidate rejected: " + entry["error"] + "\nTry one different line."
        return result
    except Exception as exc:
        report["status"] = "unsupported_or_error"
        report["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        return 1
    finally:
        if TARGET.read_bytes() != original:
            raise RuntimeError("Worker unexpectedly modified checkout source")
        report["wall_seconds"] = round(time.monotonic() - start, 3)
        REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(preflight() if "--preflight" in sys.argv else main())
