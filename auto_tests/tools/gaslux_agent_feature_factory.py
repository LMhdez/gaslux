#!/usr/bin/env python3
"""Trusted, bounded six-distro coding proposals: Draft PR only, never merge."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

REPO = "LMhdez/gaslux"
MODEL = "qwen3.5:9b"
MODEL_DIGEST = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
SHA = re.compile(r"[0-9a-f]{40}\Z")
GATES = (
    "source-authenticity", "windows-preflight", "install", "linux-first-boot",
    "windows-return", "linux-update-reboot", "uninstall-windows-integrity",
    "fault-injection-rollback",
)
TASKS = {
    "mint": ("assets/live/gaslux_distribution_capabilities.py", "test_distribution_capabilities.py",
             "Provide fail-closed Mint lifecycle evidence classification, no release permission"),
    "zorin": ("assets/live/gaslux_candidate_handoff.py", "test_candidate_handoff.py",
              "Provide fail-closed Zorin handoff/lifecycle evidence classification"),
    "cachyos": ("assets/live/gaslux_distribution_capabilities.py", "test_distribution_capabilities.py",
                "Provide fail-closed CachyOS lifecycle and UEFI evidence classification"),
    "popos": ("assets/live/gaslux_popos_preflight.py", "test_popos_native_preflight.py",
              "Provide fail-closed native Pop!_OS lifecycle evidence classification"),
    "q4os": ("assets/live/gaslux_q4os_preflight.py", "test_q4os_native_preflight.py",
             "Provide fail-closed Q4OS lifecycle evidence classification"),
    "bazzite": ("assets/live/gaslux_bazzite_preflight.py", "test_bazzite_atomic_preflight.py",
                "Provide fail-closed Bazzite Atomic lifecycle evidence classification"),
}
SAFE_BUILTINS = {
    "all": all, "any": any, "bool": bool, "dict": dict, "isinstance": isinstance,
    "len": len, "list": list, "set": set, "sorted": sorted, "str": str, "tuple": tuple,
}
FORBIDDEN = (ast.Import, ast.ImportFrom, ast.ClassDef, ast.AsyncFunctionDef,
             ast.Lambda, ast.With, ast.AsyncWith, ast.Try, ast.Raise, ast.While,
             ast.For, ast.AsyncFor, ast.Delete, ast.Global, ast.Nonlocal,
             ast.Yield, ast.YieldFrom, ast.Await)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def origin_branch(role: str, base: str) -> str:
    if role not in TASKS or not SHA.fullmatch(base):
        raise ValueError("Invalid role or source SHA")
    return f"bot/gaslux-feature-{role}-{base[:12]}"


def plan(root: Path) -> dict:
    base = git(root, "rev-parse", "HEAD")
    if not SHA.fullmatch(base):
        raise ValueError("Invalid pinned dev checkout")
    start = int(os.environ.get("GASLUX_ROLE_OFFSET", "0")) % len(TASKS)
    roles = list(TASKS)
    for offset in range(len(roles)):
        role = roles[(start + offset) % len(roles)]
        target = root / TASKS[role][0]
        if not target.is_file() or f"def assess_{role}_lifecycle(" in target.read_text():
            continue
        branch = origin_branch(role, base)
        check = subprocess.run(
            ["gh", "api", f"repos/{REPO}/git/ref/heads/{branch}"],
            text=True, capture_output=True, check=False, timeout=20,
        )
        if check.returncode == 0:
            continue
        # A 404 means unclaimed; other GitHub failures must never trigger work.
        if "404" not in check.stderr and "Not Found" not in check.stderr:
            raise RuntimeError("Cannot establish bot branch absence")
        return {"status": "pending", "role": role, "base": base, "task": TASKS[role][2]}
    return {"status": "idle", "role": "", "base": base}


def validate_addition(role: str, addition: str, *, execute: bool) -> None:
    if role not in TASKS or type(addition) is not str or not 75 <= len(addition) <= 5500:
        raise ValueError("Invalid scope or empty proposal")
    if "\r" in addition or "\x00" in addition or addition.count("\n") > 100:
        raise ValueError("Oversized or noncanonical source")
    if not addition.startswith(f"def assess_{role}_lifecycle(evidence: dict) -> dict:"):
        raise ValueError("Model must implement the exact scoped lifecycle function")
    parsed = ast.parse(addition)
    if len(parsed.body) != 1 or not isinstance(parsed.body[0], ast.FunctionDef):
        raise ValueError("Only one function permitted")
    node = parsed.body[0]
    if (node.decorator_list or len(node.args.args) != 1 or
        node.args.args[0].arg != "evidence" or node.args.defaults or
        node.args.kwonlyargs or node.args.vararg or node.args.kwarg):
        raise ValueError("Unexpected callable signature")
    for n in ast.walk(node):
        if isinstance(n, FORBIDDEN):
            raise ValueError("Code includes a prohibited operation")
        if isinstance(n, ast.Attribute) and n.attr != "get":
            raise ValueError("Only read-only dict.get is permitted")
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                if f.id not in SAFE_BUILTINS:
                    raise ValueError("Unauthorized call")
            elif not (isinstance(f, ast.Attribute) and f.attr == "get"):
                raise ValueError("Unauthorized call")
        if isinstance(n, ast.Name) and (n.id.startswith("__") or
                                         n.id in {"open", "exec", "eval", "compile", "globals", "locals"}):
            raise ValueError("Untrusted runtime reference")
    if not execute:
        return
    env = {"__builtins__": SAFE_BUILTINS}
    scope: dict = {}
    exec(compile(parsed, "<isolated-lifecycle-proposal>", "exec"), env, scope)
    fn = scope[f"assess_{role}_lifecycle"]
    for checked in ((), GATES):
        evidence = {gate: (gate in checked) for gate in GATES}
        result = fn(evidence)
        if (type(result) is not dict or set(result) !=
                {"backend", "missingGates", "installationAuthorized", "releaseEligible"} or
            result["backend"] != role or
            result["installationAuthorized"] is not False or
            result["releaseEligible"] is not False or
            type(result["missingGates"]) is not list or
            result["missingGates"] != sorted(set(GATES) - set(checked))):
            raise ValueError("Failed real lifecycle evidence acceptance")
    if fn({})["missingGates"] != sorted(GATES):
        raise ValueError("Untrusted empty evidence was treated as proof")


def expected_source(root: Path, role: str, addition: str) -> tuple[bytes, bytes]:
    path = root / TASKS[role][0]
    original = path.read_bytes()
    if len(original) > 25000 or b"\r" in original:
        raise ValueError("Unexpected source file format")
    if f"def assess_{role}_lifecycle(".encode() in original:
        raise ValueError("Feature already implemented")
    proposed = original.rstrip(b"\n") + b"\n\n" + addition.rstrip().encode("utf-8") + b"\n"
    if len(proposed) > 32000:
        raise ValueError("Proposed source too large")
    return original, proposed


def verify(root: Path, evidence_dir: Path, role: str, base: str, *, execute: bool) -> dict:
    if role not in TASKS or not SHA.fullmatch(base) or git(root, "rev-parse", "HEAD") != base:
        raise ValueError("Wrong immutable source checkout")
    report = json.loads((evidence_dir / "report.json").read_text(encoding="utf-8"))
    addition_raw = (evidence_dir / "addition.py").read_bytes()
    addition = addition_raw.decode("utf-8")
    if (report.get("role") != role or report.get("base") != base or
        report.get("task") != TASKS[role][2] or
        report.get("target") != TASKS[role][0] or
        report.get("model") != MODEL or report.get("model_digest") != MODEL_DIGEST or
        report.get("addition_sha256") != sha256(addition_raw)):
        raise ValueError("Untrusted source/report identity")
    validate_addition(role, addition, execute=execute)
    before, after = expected_source(root, role, addition)
    if (report.get("source_sha256") != sha256(before) or
        report.get("candidate_sha256") != sha256(after)):
        raise ValueError("Model artifact/source digest mismatch")
    return report


def call_model(prompt: str) -> str:
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps({"model": MODEL, "stream": False, "think": False,
                         "prompt": prompt,
                         "format": {"type": "object",
                                    "properties": {"addition": {"type": "string"}},
                                    "required": ["addition"], "additionalProperties": False},
                         "options": {"temperature": 0, "num_ctx": 5800, "num_predict": 1000}}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=350) as response:
        data = json.load(response)
    result = json.loads(data["response"])
    if type(result) is not dict or set(result) != {"addition"}:
        raise ValueError("Invalid model output schema")
    return result["addition"]



def rejection_category(addition: str | None, error: Exception) -> str:
    """Describe rejected AST *types*, never log or echo untrusted model source."""
    if type(addition) is str:
        try:
            nodes = tuple(ast.walk(ast.parse(addition)))
        except SyntaxError:
            return "SyntaxError"
        denied = sorted({type(n).__name__ for n in nodes if isinstance(n, FORBIDDEN)})
        if denied:
            return "Forbidden AST nodes: " + ", ".join(denied)
        if any(isinstance(n, ast.Attribute) and n.attr != "get" for n in nodes):
            return "Forbidden AST attribute"
        if any(isinstance(n, ast.Call) and
               not ((isinstance(n.func, ast.Name) and n.func.id in SAFE_BUILTINS) or
                    (isinstance(n.func, ast.Attribute) and n.func.attr == "get"))
               for n in nodes):
            return "Unauthorized AST call"
    if isinstance(error, ValueError):
        # These messages are fixed by trusted validation, not generated text.
        return str(error)[:120]
    return type(error).__name__


def generate(root: Path, evidence_dir: Path, role: str, base: str) -> None:
    if git(root, "rev-parse", "HEAD") != base or role not in TASKS:
        raise ValueError("Wrong worker source identity")
    source, test, objective = TASKS[role]
    original = (root / source).read_bytes()
    task = (
        f"ROLE {role}; real Gaslux product source: {source}; task: {objective}.\n"
        "Write a pure fail-closed diagnostic helper (not install authorization).\n"
        f"EXACT signature: def assess_{role}_lifecycle(evidence: dict) -> dict:\n"
        f"Return EXACT dict keys: backend='{role}', missingGates=list of sorted missing strings, "
        "installationAuthorized=False, releaseEligible=False.\n"
        f"The eight required gate keys are: {list(GATES)!r}. Only an actual boolean True "
        "can satisfy each key, absent/false/non-boolean never satisfies.\n"
        "Produce exactly ONE top-level Python function, and no other statements "
        "outside it. The addition string MUST begin with the exact signature above.\n"
        "Inside the function, define a tuple named gates containing the eight exact "
        "gate keys shown above, then compute missing as "
        "sorted([name for name in gates if evidence.get(name) is not True]). "
        "The list comprehension is ALLOWED; a standalone 'for' statement (AST For) "
        "and 'while' statement (AST While) are FORBIDDEN. "
        "Do not use other loops, helper functions, classes, imports, decorators, "
        "I/O, OS/shell operations, comprehensions with side effects or globals.\n"
        "Only use literals, assignments, a list comprehension, identity comparison "
        "'is not True', return, and dict construction. "
        "The only permitted attribute is evidence.get; do not use .append, .keys, "
        ".items, .sort or any other attribute. "
        "Permitted built-in calls: sorted, list, set, tuple, len, bool, "
        "isinstance, dict, all, any, str. "
        "Never grant installation or release: both flags must be literal False.\n"
        "Respond with a JSON object containing exactly one key, 'addition', "
        "whose value is ONLY the Python function source. "
        "No markdown, prose, explanation, surrounding source or code fences.\n"
    )
    last: Exception | None = None
    last_category = "No response"
    for attempt in range(2):
        addition: str | None = None
        try:
            addition = call_model(task)
            validate_addition(role, addition, execute=True)
            before, after = expected_source(root, role, addition)
            evidence_dir.mkdir(parents=True, exist_ok=True)
            data = addition.rstrip().encode() + b"\n"
            (evidence_dir / "addition.py").write_bytes(data)
            report = {
                "role": role, "base": base, "task": objective, "target": source,
                "model": MODEL, "model_digest": MODEL_DIGEST,
                "source_sha256": sha256(before), "candidate_sha256": sha256(after),
                "addition_sha256": sha256(data),
            }
            (evidence_dir / "report.json").write_text(
                json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            return
        except (ValueError, KeyError, SyntaxError, OSError) as error:
            last = error
            last_category = rejection_category(addition, error)
            print(f"Qwen attempt {attempt + 1}/2 rejected: {last_category}",
                  file=sys.stderr)
            task += (
                f"\nPrior attempt rejected: {last_category}. "
                "Correct the rejected construct; never use a standalone for/while "
                "statement. A side-effect-free list comprehension is allowed. "
                "Return only the exact scoped Python function in JSON addition.\n"
            )
    raise RuntimeError(
        f"Isolated Qwen proposal failed acceptance ({last_category}): {last}"
    )



def safe_forward_draft_base(root: Path, role: str, old: str, current: str) -> bool:
    """Only a forward-only unchanged feature source+test may reuse model evidence.

    This does NOT grant auto-merge: the result is always a Draft PR, and the
    model's old-base product tests are never presented as live-base CI.
    """
    if role not in TASKS or not SHA.fullmatch(old) or not SHA.fullmatch(current):
        return False
    if old == current:
        return True
    ancestor = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", old, current],
        check=False, capture_output=True, timeout=20,
    )
    if ancestor.returncode != 0:
        return False
    source, test, _ = TASKS[role]
    for path in (source, "auto_tests/tests/" + test):
        try:
            original = subprocess.check_output(
                ["git", "-C", str(root), "show", old + ":" + path],
                timeout=20,
            )
            now = subprocess.check_output(
                ["git", "-C", str(root), "show", current + ":" + path],
                timeout=20,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False
        if original != now:
            return False
    return True

def publish(root: Path, evidence_dir: Path, role: str, base: str) -> None:
    if os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true":
        raise RuntimeError("GASLUX_AUTONOMY_PAUSED: model Draft publisher blocked")
    if os.getenv("GITHUB_REPOSITORY") != REPO or os.getenv("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Only trusted default-branch Actions may publish")
    # Static-only checks: never execute model text in a token-bearing job.
    verify(root, evidence_dir, role, base, execute=False)
    git(root, "fetch", "origin", "refs/heads/dev:refs/remotes/origin/dev")
    live = git(root, "rev-parse", "refs/remotes/origin/dev")
    if not safe_forward_draft_base(root, role, base, live):
        print(json.dumps({"status": "stale_or_relevant_dev_change", "role": role}))
        return
    branch = origin_branch(role, base)
    addition = (evidence_dir / "addition.py").read_text(encoding="utf-8")
    # Safe forward-only changes are included by ancestry, but this review PR
    # is still always Draft. No model text runs with publication credentials.
    git(root, "checkout", "-b", branch, live)
    _, proposed = expected_source(root, role, addition)
    (root / TASKS[role][0]).write_bytes(proposed)
    if git(root, "diff", "--name-only") != TASKS[role][0]:
        raise ValueError("Unexpected changed product path")
    subprocess.run(["git", "-C", str(root), "diff", "--check"], check=True)
    git(root, "add", "--", TASKS[role][0])
    subprocess.run(["git", "-C", str(root), "config", "user.name", "github-actions[bot]"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", f"feat({role}): isolated lifecycle evidence proposal"], check=True)
    # No implicit token is available in any model-inference or test runner.
    subprocess.run(["gh", "auth", "setup-git"], check=True)
    subprocess.run(["git", "-C", str(root), "push", "origin", f"HEAD:refs/heads/{branch}"], check=True)
    body = (f"Unprivileged Qwen3.5 9B proposal for {role}, pinned base {base}.\n\n"
            "Pure read-only lifecycle evidence helper appended to real backend source. "
            "Static AST scope and independent isolated acceptance checked; the PR is a "
            "**Draft**. Requires backend owner, independent Safety review, full "
            "Windows/Linux VM acceptance and normal CI. **No auto-merge permission; "
            "no installed guest, dual boot, uninstall, disk writer or release proof.**")
    subprocess.run(["gh", "pr", "create", "--repo", REPO, "--draft", "--base", "dev",
                    "--head", branch, "--title", f"feat({role}): autonomous lifecycle evidence proposal",
                    "--body", body], check=True)


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("action", choices=("plan", "generate", "verify", "publish"))
    cli.add_argument("--repo", type=Path, required=True)
    cli.add_argument("--evidence", type=Path, default=Path("evidence/feature-factory"))
    cli.add_argument("--role", choices=tuple(TASKS))
    cli.add_argument("--base")
    args = cli.parse_args()
    root = args.repo.resolve(strict=True)
    if args.action == "plan":
        print(json.dumps(plan(root), sort_keys=True))
        return
    if not args.role or not args.base:
        cli.error("Pinned role/base SHA required")
    if args.action == "generate":
        generate(root, args.evidence, args.role, args.base)
    elif args.action == "verify":
        print(json.dumps(verify(root, args.evidence, args.role, args.base, execute=True), sort_keys=True))
    else:
        publish(root, args.evidence, args.role, args.base)


if __name__ == "__main__":
    main()
