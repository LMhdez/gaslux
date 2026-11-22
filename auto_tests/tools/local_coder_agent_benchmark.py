#!/usr/bin/env python3
"""Read-only local LLM repair benchmark against a mutated Gaslux utility.

This benchmark NEVER edits the checkout or proposes a production code change.
It mutates one line in-memory, asks the model to repair it, validates the AST,
and runs deterministic tests in a restricted Python namespace. Do not generalize
this restriction to arbitrary model-generated source.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.request


TARGET = Path("auto_tests/tools/rank_capture_changes.py")
GOOD = "return sorted(changes, reverse=True, key=lambda item: item[0])"
BAD = "return sorted(changes, reverse=False, key=lambda item: item[0])"
MODEL = os.environ.get("GASLUX_AGENT_MODEL", "qwen2.5-coder:3b")
OUTPUT = Path("evidence/repair-benchmark.json")
MAX_ATTEMPTS = 2


def source_function(source: str) -> ast.FunctionDef:
    module = ast.parse(source)
    found = [
        item for item in module.body
        if isinstance(item, ast.FunctionDef) and item.name == "ranked_changes"
    ]
    if len(found) != 1:
        raise ValueError("Expected exactly one ranked_changes function")
    return found[0]


def normalize(raw: str) -> str:
    text = raw.strip()
    lines = text.splitlines()
    fence = chr(96) * 3
    if len(lines) >= 3 and lines[0].lower() in (fence, fence + "python") and lines[-1] == fence:
        text = "\n".join(lines[1:-1]).strip()
    if len(text) > 500 or len(text.splitlines()) != 1:
        raise ValueError("Candidate must contain exactly one short Python line")
    return text.strip()


def validate_replacement(line: str) -> None:
    # This pilot intentionally accepts ONLY a single safe sorted(...) return.
    # Never use this check as a general-purpose source-code security boundary.
    if not line.startswith("return sorted(changes,") or ";" in line or "\\" in line:
        raise ValueError("Replacement violates the single-return guard")
    tree = ast.parse("def f():\n    " + line + "\n")
    ret = tree.body[0].body[0]
    if not isinstance(ret, ast.Return) or not isinstance(ret.value, ast.Call):
        raise ValueError("Expected a return of sorted(...)")
    call = ret.value
    if not isinstance(call.func, ast.Name) or call.func.id != "sorted":
        raise ValueError("Only sorted is permitted")
    if len(call.args) != 1 or not isinstance(call.args[0], ast.Name) or call.args[0].id != "changes":
        raise ValueError("Expected the original changes collection")
    allowed = (
        ast.Module, ast.FunctionDef, ast.Return, ast.Call, ast.Name, ast.Load,
        ast.keyword, ast.Lambda, ast.arguments, ast.arg, ast.Subscript,
        ast.Constant,
    )
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise ValueError("Unsupported AST node in return expression")
    for name in (item.id for item in ast.walk(tree) if isinstance(item, ast.Name)):
        if name not in {"sorted", "changes", "item", "x"}:
            raise ValueError("Unexpected identifier in candidate")


def regression_check(source: str) -> None:
    # Extract ONLY this function. Pillow and the rest of Gaslux are not run.
    node = source_function(source)
    module = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
    with tempfile.TemporaryDirectory(prefix="gaslux-repair-") as directory:
        root = Path(directory)
        for index in range(1, 5):
            (root / f"{index:03d}.png").touch()
        values = {"002.png": 2.0, "003.png": 9.0, "004.png": 1.0}
        def score(previous: Path, current: Path) -> float:
            return values[current.name]
        safe = {
            "__builtins__": {
                "zip": zip, "sorted": sorted, "print": print, "OSError": OSError,
                "list": list, "tuple": tuple, "float": float,
            },
            "Path": Path,
            "image_score": score,
        }
        exec(compile(module, "<ranked_changes_benchmark>", "exec"), safe)
        ranking = safe["ranked_changes"](root, "*.png")
        assert [entry[0] for entry in ranking] == [9.0, 2.0, 1.0], ranking
        assert [(a.name, b.name) for _, a, b in ranking] == [
            ("002.png", "003.png"),
            ("001.png", "002.png"),
            ("003.png", "004.png"),
        ]
        assert safe["ranked_changes"](root, "*.missing") == []


def call_model(prompt: str) -> dict:
    payload = {
        "model": MODEL, "stream": False, "prompt": prompt,
        "options": {"temperature": 0, "num_ctx": 2048, "num_predict": 192},
    }
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=360) as reply:
        return json.load(reply)


def main() -> int:
    OUTPUT.parent.mkdir(exist_ok=True, parents=True)
    t0 = time.monotonic()
    result = {
        "model": MODEL, "target": str(TARGET), "passed": False,
        "baseline_bug_reproduced": False, "attempts": [],
        "scope": "mutated isolated Gaslux Python utility, no repository writes",
    }
    try:
        original = TARGET.read_text()
        result["source_sha256"] = hashlib.sha256(original.encode()).hexdigest()
        if original.count(GOOD) != 1:
            raise RuntimeError("Original baseline no longer matches benchmark target")
        mutated = original.replace(GOOD, BAD, 1)
        try:
            regression_check(mutated)
        except AssertionError:
            result["baseline_bug_reproduced"] = True
        if not result["baseline_bug_reproduced"]:
            raise RuntimeError("RED baseline missing: test cannot evaluate a fix")
        function = source_function(mutated)
        excerpt = ast.get_source_segment(mutated, function) or ""
        prompt = (
            "You are fixing one regression in a real Gaslux Python utility. "
            "Tests require ranked_changes to return changes in DESCENDING order "
            "by their numeric score (9 before 2 before 1). "
            "Return ONLY the complete replacement Python 'return sorted(...)' line, "
            "without leading indentation or explanations or Markdown.\n"
            "Current buggy function:\n" + excerpt + "\n"
        )
        for attempt in range(1, MAX_ATTEMPTS + 1):
            entry: dict = {"number": attempt}
            result["attempts"].append(entry)
            try:
                data = call_model(prompt)
                raw = data.get("response", "")
                entry["response"] = raw[:500]
                entry["inference_total_seconds"] = round(data.get("total_duration", 0) / 1e9, 3)
                candidate_line = normalize(raw)
                validate_replacement(candidate_line)
                candidate = mutated.replace(BAD, candidate_line, 1)
                regression_check(candidate)
                entry["passed"] = True
                result["passed"] = True
                result["proposed_replacement"] = candidate_line
                break
            except Exception as exc:
                entry["passed"] = False
                entry["error"] = f"{type(exc).__name__}: {str(exc)[:220]}"
                prompt += "\nPrevious attempt failed: " + entry["error"] + "\nGive the corrected single line only."
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        result["wall_seconds"] = round(time.monotonic() - t0, 3)
        OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
