#!/usr/bin/env python3
"""Bounded logging-only local coder worker. Never possesses a write token.

Mode 'simulate' injects a known regression in the disposable checkout to
measure actual failing-test repair; mode 'real' proposes a change ONLY if the
existing focused test already fails. All candidate executions occur without
repository credentials and do not affect the remote branch.
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
import time
import urllib.request

TARGET = Path("auto_tests/app/logging_config.py")
TEST = "tests/test_logging_config.py"
MODEL = os.environ.get("GASLUX_AGENT_MODEL", "qwen2.5-coder:3b")
SIMULATE = os.environ.get("GASLUX_AGENT_SIMULATE") == "1"
FAULT = "handler.close()"
MAX_ATTEMPTS = 2
OUT = Path("evidence/logging-repair.json")
CANDIDATE = Path("evidence/candidate-logging_config.py")


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def test() -> tuple[bool, str]:
    run = subprocess.run(
        [sys.executable, "-m", "pytest", TEST, "-q"],
        cwd="auto_tests",
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "GH_TOKEN")},
    )
    output = (run.stdout + "\n" + run.stderr)[-4000:]
    return run.returncode == 0, output


def normalize(raw: str) -> str:
    """Accept exactly one handler.close() statement, optionally fenced."""
    text = raw.strip()
    fence = chr(96) * 3
    lines = text.splitlines()
    if len(lines) >= 3 and lines[0].lower() in (fence, fence + "python") and lines[-1] == fence:
        text = "\n".join(lines[1:-1]).strip()
    if len(text.splitlines()) != 1 or len(text) > 120:
        raise ValueError("Expected one replacement statement, not a full module")
    tree = ast.parse(text, mode="exec")
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Expr):
        raise ValueError("Expected expression statement")
    call = tree.body[0].value
    if not isinstance(call, ast.Call) or call.args or call.keywords:
        raise ValueError("Only a no-argument close() call is permitted")
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "close"
            and isinstance(func.value, ast.Name) and func.value.id == "handler"):
        raise ValueError("Only handler.close() is permitted")
    return "handler.close()"


def imports(source: str) -> list[str]:
    tree = ast.parse(source)
    return [
        ast.unparse(node)
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]


def validate(old: str, new: str) -> None:
    if len(new) > 5000 or not new.strip() or old == new:
        raise ValueError("No bounded source modification")
    if imports(old) != imports(new):
        raise ValueError("Imports changed")
    old_tree, new_tree = ast.parse(old), ast.parse(new)
    if [type(n) for n in old_tree.body] != [type(n) for n in new_tree.body]:
        raise ValueError("Top-level structure changed")
    changes = list(difflib.ndiff(old.splitlines(), new.splitlines()))
    count = sum(line.startswith("- ") or line.startswith("+ ") for line in changes)
    if count > 18:
        raise ValueError(f"Patch too large: {count} changed lines")
    forbidden = ("eval(", "exec(", "__import__", "subprocess", "os.system", "shutil")
    if any(term in new and term not in old for term in forbidden):
        raise ValueError("New unsafe operation detected")
    if "configure_logging" not in new:
        raise ValueError("Missing API entrypoint")


def model_call(prompt: str) -> dict:
    payload = {
        "model": MODEL, "stream": False, "prompt": prompt,
        "options": {"temperature": 0, "num_ctx": 2048, "num_predict": 128},
    }
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=360) as reply:
        return json.load(reply)


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    original = TARGET.read_bytes()
    report = {
        "task": "logging-file-handler-reconfiguration", "path": str(TARGET),
        "model": MODEL, "simulated": SIMULATE, "passed": False,
        "attempts": [], "original_sha256": digest(original), "status": "started",
    }
    result_code = 1
    try:
        source = original.decode("utf-8")
        if SIMULATE:
            if source.count(FAULT) != 1:
                raise RuntimeError("Fixture not reproducible; expected one close()")
            source = source.replace(FAULT, "pass  # injected regression", 1)
            TARGET.write_text(source)
        passed, diagnostics = test()
        report["baseline_red"] = not passed
        if passed:
            report["status"] = "idle" if not SIMULATE else "invalid_fixture"
            result_code = 0 if not SIMULATE else 1
            return result_code
        if source.count("root.removeHandler(handler)") != 1:
            raise RuntimeError("Missing unique insertion anchor")
        if not SIMULATE and source.count("handler.close()") != 0:
            raise RuntimeError("Failure outside missing-close scope; fail closed")
        # Deterministic, reviewed fix for exactly one verified missing-close pattern.
        # This is NOT an AI repair and must be attributed separately in evidence.
        anchor = "        root.removeHandler(handler)\n"
        if source.count(anchor) == 1 and source.count("handler.close()") == 0:
            deterministic = source.replace(anchor, anchor + "        handler.close()\n", 1)
            validate(source, deterministic)
            try:
                TARGET.write_text(deterministic)
                green, _ = test()
            finally:
                TARGET.write_text(source)
            if green:
                report["passed"] = True
                report["repair_strategy"] = "deterministic_missing_close"
                report["status"] = "repaired_simulation" if SIMULATE else "proposable"
                report["candidate_sha256"] = digest(deterministic.encode())
                if not SIMULATE:
                    CANDIDATE.write_text(deterministic)
                return 0
        if os.environ.get("GASLUX_AGENT_DETERMINISTIC_ONLY") == "1":
            report["repair_strategy"] = "no_safe_deterministic_repair"
            report["status"] = "unsupported_regression"
            return 1
        report["repair_strategy"] = "model_attempts"
        prompt = (
            "Fix ONE missing Python statement in the following Gaslux logging function. "
            "Close the EXISTING loop variable named handler, NOT file_handler. "
            "file_handler is the NEW active handler and must remain open. "
            "The required operation takes no arguments. "
            "Reply with ONLY ONE PYTHON STATEMENT to insert immediately after "
            "'root.removeHandler(handler)'. No full module, no test, no comments, "
            "no Markdown. Output must fit on one line.\n"
            "FAILING SOURCE:\n" + source + "\n"
            "TEST FAILURE:\n" + diagnostics[-700:] + "\n"
            "ONE REPLACEMENT STATEMENT:\n"
        )
        for attempt in range(1, MAX_ATTEMPTS + 1):
            item: dict = {"number": attempt, "passed": False}
            report["attempts"].append(item)
            try:
                response = model_call(prompt)
                raw = response.get("response", "")
                item["response_excerpt"] = raw[:1200]
                item["model_total_seconds"] = round(response.get("total_duration", 0) / 1e9, 3)
                replacement = normalize(raw)
                anchor = "        root.removeHandler(handler)\n"
                if source.count(anchor) != 1:
                    raise ValueError("Insertion anchor not unique")
                candidate = source.replace(anchor, anchor + "        " + replacement + "\n", 1)
                validate(source, candidate)
                TARGET.write_text(candidate)
                green, output = test()
                if not green:
                    raise AssertionError("Focused test still RED: " + output[-800:])
                report["passed"] = True
                report["status"] = "repaired_simulation" if SIMULATE else "proposable"
                report["candidate_sha256"] = digest(candidate.encode())
                if not SIMULATE:
                    CANDIDATE.write_text(candidate)
                item["passed"] = True
                result_code = 0
                break
            except Exception as exc:
                item["error"] = f"{type(exc).__name__}: {str(exc)[:250]}"
                prompt += ("\nPrevious output failed: " + item["error"] + "\nUse the loop variable named handler (not file_handler). ONE STATEMENT ONLY:")
            finally:
                TARGET.write_text(source)
        return result_code
    except Exception as exc:
        report["status"] = "worker_error"
        report["error"] = f"{type(exc).__name__}: {str(exc)[:400]}"
        return 1
    finally:
        TARGET.write_bytes(original)
        report["wall_seconds"] = round(time.monotonic() - start, 3)
        OUT.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
