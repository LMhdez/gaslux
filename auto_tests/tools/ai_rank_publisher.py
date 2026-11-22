#!/usr/bin/env python3
"""Strict Draft PR publisher for a single tested, model-authored Observer patch.

Separate privileged GitHub Actions job, no LLM inference or candidate execution.
Requires exact repo/base/file/digest and one AST-limited return-line change.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.request


REPO = "LMhdez/gaslux"
BASE = "dev"
BRANCH = "bot/ai-observer-rank-candidate"
TARGET = "auto_tests/tools/rank_capture_changes.py"
API = f"https://api.github.com/repos/{REPO}"


def api(method: str, url: str, payload: dict | None = None, optional: bool = False):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + os.environ["GH_TOKEN"])
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=25) as reply:
            return json.load(reply)
    except urllib.error.HTTPError as exc:
        if optional and exc.code == 404:
            return None
        raise RuntimeError(f"GitHub API {method} {url}: HTTP {exc.code}") from exc


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate(old: str, new: str) -> None:
    before, after = old.splitlines(keepends=True), new.splitlines(keepends=True)
    if len(before) != len(after) or old == new or len(new) > 10000:
        raise ValueError("Candidate size or line count outside contract")
    differences = [(i, a, b) for i, (a, b) in enumerate(zip(before, after)) if a != b]
    if len(differences) != 1:
        raise ValueError("Only one changed line is authorized")
    index, oldline, newline = differences[0]
    def function_return_line(source: str) -> int:
        module = ast.parse(source)
        function = [node for node in module.body
                    if isinstance(node, ast.FunctionDef) and node.name == "ranked_changes"]
        if len(function) != 1:
            raise ValueError("Unexpected target function layout")
        statements = [node for node in ast.walk(function[0]) if isinstance(node, ast.Return)]
        if len(statements) != 1:
            raise ValueError("Ambiguous ranking return")
        return statements[0].lineno
    if index + 1 != function_return_line(old) or index + 1 != function_return_line(new):
        raise ValueError("Changed line is not the ranking return statement")
    if not oldline.strip().startswith("return sorted(changes,"):
        raise ValueError("Original line outside ranking scope")
    if not newline.strip().startswith("return sorted(changes,"):
        raise ValueError("Candidate must retain sorted ranking")
    if ";" in newline or "#" in newline or "\r" in newline:
        raise ValueError("Unsupported syntax in candidate")
    new_tree = ast.parse("def rank():\n    " + newline.strip() + "\n")
    call = new_tree.body[0].body[0].value
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "sorted":
        raise ValueError("Not a sorted() call")
    allowed = (
        ast.Module, ast.FunctionDef, ast.arguments, ast.Return, ast.Call,
        ast.Name, ast.Load, ast.Constant, ast.keyword, ast.Lambda,
        ast.arg, ast.Subscript, ast.Tuple, ast.List, ast.UnaryOp, ast.USub,
    )
    if any(not isinstance(n, allowed) for n in ast.walk(new_tree)):
        raise ValueError("Candidate AST contains out-of-scope construct")
    if any(n.id not in ("sorted", "changes", "item", "x")
           for n in ast.walk(new_tree) if isinstance(n, ast.Name)):
        raise ValueError("Unexpected name in candidate")
    if not any(isinstance(n, ast.FunctionDef) and n.name == "ranked_changes"
               for n in ast.parse(new).body):
        raise ValueError("Original function missing")


def verify_evidence() -> tuple[dict, bytes]:
    report = json.loads(Path("evidence/ai-rank-repair.json").read_text())
    attempts = report.get("attempts", [])
    if not (
        report.get("simulated") is False
        and report.get("passed") is True
        and report.get("status") == "candidate_green"
        and report.get("baseline_red") is True
        and report.get("model") == "qwen3.5:9b"
        and report.get("target") == TARGET
        and 1 <= len(attempts) <= 2
        and attempts[-1].get("passed") is True
    ):
        raise ValueError("Absent/invalid no-token RED/GREEN evidence")
    candidate = Path("evidence/ai-rank-candidate.py").read_bytes()
    if digest(candidate) != report.get("candidate_sha256"):
        raise ValueError("Candidate SHA-256 mismatch")
    return report, candidate


def main() -> None:
    report, candidate = verify_evidence()
    orig = api("GET", f"{API}/contents/{TARGET}?ref={BASE}")
    base_source = base64.b64decode(orig["content"])
    if digest(base_source) != report.get("source_sha256"):
        raise ValueError("Dev source changed since unprivileged test")
    validate(base_source.decode("utf-8"), candidate.decode("utf-8"))
    branch_ref = f"refs/heads/{BRANCH}"
    if api("GET", f"{API}/git/ref/heads/{BRANCH}", optional=True):
        print("Existing proposal branch: duplicate is blocked")
        return
    base = api("GET", f"{API}/git/ref/heads/{BASE}")
    api("POST", f"{API}/git/refs", {"ref": branch_ref, "sha": base["object"]["sha"]})
    api("PUT", f"{API}/contents/{TARGET}", {
        "message": "fix(observer): model-authored, tested screenshot ranking candidate",
        "content": base64.b64encode(candidate).decode(),
        "sha": orig["sha"], "branch": BRANCH,
    })
    pr = api("POST", f"{API}/pulls", {
        "title": "fix(observer): proposed local AI ranking regression repair",
        "head": BRANCH, "base": BASE, "draft": True,
        "body": (
            "Experimental local Qwen3.5 9B code candidate. A focused regression "
            "was RED before the patch and GREEN on a separate ephemeral runner "
            "without write credentials. Exactly one noncritical Python return "
            "line changed; base SHA-256 and scoped AST/diff independently "
            "revalidated. **Draft only**: independent safety review and "
            "exact-head CI required. Never auto-merge or modify disk/boot paths."
        ),
    })
    print("Created Draft proposal:", pr["html_url"])


if __name__ == "__main__":
    main()
