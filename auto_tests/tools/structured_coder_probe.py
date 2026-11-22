#!/usr/bin/env python3
"""Isolated, model-authored repair evaluation on actual Gaslux Python functions.

Two intentionally seeded regressions. Model chooses old and replacement lines;
no solution is hard-coded into the prompt or patch generator. Test or AST
failure rejects the candidate. Never pushes or edits the repository remotely.
The target checkout is disposable, tests run without a GitHub write token.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request


MODEL = os.environ["GASLUX_PROBE_MODEL"]
OUTPUT = Path("evidence/structured-code-repair.json")
TASKS = (
    {
        "id": "ranked_changes_descending",
        "path": Path("auto_tests/tools/rank_capture_changes.py"),
        "good": "return sorted(changes, reverse=True, key=lambda item: item[0])",
        "fault": "return sorted(changes, reverse=False, key=lambda item: item[0])",
        "function": "ranked_changes",
    },
    {
        "id": "logging_previous_handler_closed",
        "path": Path("auto_tests/app/logging_config.py"),
        "good": "        handler.close()",
        "fault": "        pass",
        "function": "configure_logging",
    },
)
MAX_ATTEMPTS = 2
SCHEMA = {
    "type": "object",
    "properties": {
        "old_line": {"type": "string"},
        "new_line": {"type": "string"},
    },
    "required": ["old_line", "new_line"],
    "additionalProperties": False,
}


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def extract_function(source: str, name: str) -> str:
    tree = ast.parse(source)
    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(functions) != 1:
        raise ValueError("Target function changed or ambiguous")
    text = ast.get_source_segment(source, functions[0])
    if not text:
        raise ValueError("Function source extraction failed")
    return text


def guard(task: dict, old: str, new: str) -> None:
    if len(new) > 250 or len(old) > 250 or new == old:
        raise ValueError("No short one-line change")
    stripped = new.strip()
    if len(stripped.splitlines()) != 1 or ";" in stripped or "#" in stripped:
        raise ValueError("Only a single expression/statement without comments allowed")
    if task["id"] == "logging_previous_handler_closed":
        expression = ast.parse(new.strip(), mode="exec")
        if len(expression.body) != 1:
            raise ValueError("Expected single Python expression")
        statement = expression.body[0]
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            raise ValueError("Only a method call is allowed")
        call = statement.value
        if call.args or call.keywords:
            raise ValueError("No call arguments allowed")
        if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name):
            raise ValueError("Method on a local variable required")
        if call.func.value.id not in ("handler", "file_handler") or call.func.attr != "close":
            raise ValueError("Only closing a local handler is in scope")
    else:
        expression = ast.parse("def f():\n    " + new.strip() + "\n")
        statement = expression.body[0].body[0]
        if not isinstance(statement, ast.Return) or not isinstance(statement.value, ast.Call):
            raise ValueError("Expected a returned sorted expression")
        call = statement.value
        if not isinstance(call.func, ast.Name) or call.func.id != "sorted":
            raise ValueError("Must use sorted on the existing changes")
        allowed = (
            ast.Module, ast.FunctionDef, ast.arguments, ast.Return, ast.Call,
            ast.Name, ast.Load, ast.Constant, ast.keyword, ast.Lambda,
            ast.arg, ast.Subscript, ast.Tuple, ast.List, ast.UnaryOp, ast.USub,
        )
        if any(not isinstance(n, allowed) for n in ast.walk(expression)):
            raise ValueError("Unexpected expression construct")
        if any(n.id not in ("sorted", "changes", "item", "x") for n in ast.walk(expression)
               if isinstance(n, ast.Name)):
            raise ValueError("Unexpected identifier")


def apply_candidate(source: str, task: dict, old: str, new: str) -> str:
    lines = source.splitlines(keepends=True)
    matches = [i for i, s in enumerate(lines) if s.strip() == old.strip()]
    if len(matches) != 1:
        raise ValueError("Exact old line is missing or ambiguous")
    index = matches[0]
    actual = lines[index]
    indent = actual[:len(actual) - len(actual.lstrip())]
    candidate = indent + new.strip() + ("\n" if actual.endswith("\n") else "")
    guard(task, actual, candidate)
    lines[index] = candidate
    updated = "".join(lines)
    if len(updated) - len(source) > 200:
        raise ValueError("Candidate unexpectedly expanded source")
    if task["function"] not in extract_function(updated, task["function"]):
        raise ValueError("Target was removed")
    return updated


def run_rank_test(source: str) -> tuple[bool, str]:
    node = next(
        node for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "ranked_changes"
    )
    code = compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                   "<rank_test>", "exec")
    with tempfile.TemporaryDirectory(prefix="gaslux-rank-") as d:
        root = Path(d)
        for n in ("01.png", "02.png", "03.png", "04.png"):
            (root / n).touch()
        values = {"02.png": 2.0, "03.png": 9.0, "04.png": 1.0}
        namespace = {
            "__builtins__": {
                "zip": zip, "sorted": sorted, "print": print,
                "OSError": OSError, "list": list, "tuple": tuple, "float": float,
            },
            "Path": Path,
            "image_score": lambda a, b: values[b.name],
        }
        exec(code, namespace)
        actual = [x[0] for x in namespace["ranked_changes"](root, "*.png")]
        wanted = [9.0, 2.0, 1.0]
        return actual == wanted, f"AssertionError: expected sorted scores {wanted}, got {actual}"


def run_test(task: dict, source: str) -> tuple[bool, str]:
    if task["id"] == "ranked_changes_descending":
        return run_rank_test(source)
    path = task["path"]
    current = path.read_bytes()
    try:
        path.write_text(source)
        run = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_logging_config.py", "-q"],
            cwd="auto_tests", capture_output=True, text=True, timeout=80, check=False,
            env={k: v for k, v in os.environ.items()
                 if k not in ("GH_TOKEN", "GITHUB_TOKEN")},
        )
        return run.returncode == 0, (run.stdout + "\n" + run.stderr)[-1500:]
    finally:
        path.write_bytes(current)


def ask(prompt: str) -> dict:
    data = {
        "model": MODEL, "prompt": prompt, "stream": False,
        "format": SCHEMA,
        "options": {"temperature": 0, "num_ctx": 3072, "num_predict": 180},
        "think": False,
    }
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=240) as response:
        return json.load(response)


def do_task(task: dict) -> dict:
    path = task["path"]
    original = path.read_bytes()
    source = original.decode("utf-8")
    record = {
        "task": task["id"], "path": str(path),
        "source_sha256": sha256(original), "baseline_red": False,
        "passed": False, "attempts": [],
    }
    if source.count(task["good"]) != 1:
        record["error"] = "Original source fixture changed; no test performed"
        return record
    mutated = source.replace(task["good"], task["fault"], 1)
    try:
        before_ok, failure = run_test(task, mutated)
        if before_ok:
            record["error"] = "No failing baseline; test is invalid"
            return record
        record["baseline_red"] = True
        record["failed_test_excerpt"] = failure[-700:]
        function = extract_function(mutated, task["function"])
        prompt = (
            "You are a local coding assistant repairing a failing REAL Gaslux Python "
            "function in a disposable checkout. Propose exactly ONE LINE replacement. "
            "Respond with a JSON object containing old_line (the exact existing line, "
            "without leading spaces) and new_line (the replacement line, without leading "
            "spaces). Do not include tests, explanations or an entire file. "
            "Do not change any other line. The new statement must preserve the function's "
            "intended behavior and fix the observed failing test.\n"
            "GIT DIFF / EXACT SUSPECT LINE (provide this as old_line, with no indentation):\n"
            + task["fault"].strip() + "\n"
            "Do not replace a multi-line expression or rewrite the file. The old_line MUST "
            "match the suspect line exactly, new_line must be a SINGLE statement.\n"
            "FUNCTION:\n" + function + "\n"
            "FAILING TEST OUTPUT:\n" + failure[-800:] + "\n"
        )
        for attempt in range(1, MAX_ATTEMPTS + 1):
            item = {"attempt": attempt, "passed": False}
            record["attempts"].append(item)
            try:
                response = ask(prompt)
                item["total_duration_seconds"] = round(
                    response.get("total_duration", 0) / 1e9, 3)
                raw = response.get("response", "")
                item["response_excerpt"] = raw[:550]
                patch = json.loads(raw)
                if set(patch) != {"old_line", "new_line"}:
                    raise ValueError("Unrecognized response keys")
                new_source = apply_candidate(mutated, task, patch["old_line"], patch["new_line"])
                passed, diagnostics = run_test(task, new_source)
                if not passed:
                    raise AssertionError("Test still RED: " + diagnostics[-350:])
                item["passed"] = True
                record["passed"] = True
                record["candidate_sha256"] = sha256(new_source.encode())
                record["diff"] = "".join(difflib.unified_diff(
                    mutated.splitlines(keepends=True), new_source.splitlines(keepends=True),
                    fromfile="mutated/" + str(path), tofile="candidate/" + str(path)))
                break
            except Exception as exc:
                item["error"] = f"{type(exc).__name__}: {str(exc)[:250]}"
                prompt += (
                    "\nPREVIOUS FAILED ATTEMPT:\n" + item["error"] +
                    "\nTry a different single-line replacement. JSON only.\n"
                )
    finally:
        if path.read_bytes() != original:
            path.write_bytes(original)
    return record


def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    report = {"model": MODEL, "tasks": [], "passed": 0, "total": len(TASKS)}
    try:
        for task in TASKS:
            try:
                result = do_task(task)
            except Exception as exc:
                result = {
                    "task": task["id"], "passed": False,
                    "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                }
            report["tasks"].append(result)
            report["passed"] += int(result.get("passed", False))
    finally:
        report["wall_seconds"] = round(time.monotonic() - start, 3)
        OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
