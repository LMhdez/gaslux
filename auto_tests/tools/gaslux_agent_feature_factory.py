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
# P0 Phase 2B: one trusted, reviewable, read-only product feature. This exact
# scope requires independent Safety review before its code is merged to main.
# Issue #404 remains a task request, not an executable authorization itself.
SCOPE2B_ID = "mint-iso-pins-v1"
SCOPE2B_ISSUE = 404
SCOPE2B_FN = "match_mint_223_iso_descriptor"
SCOPE2B_TARGET = TASKS["mint"][0]
SCOPE2B_PLATFORM = "windows10-bios-mbr"
SCOPE2B_GATE = "source-authenticity"
SCOPE2B_TASK = ("Check the pinned Mint 22.3 ISO descriptor against trusted release "
                "identity without granting authenticity, installation or release.")
SCOPE2B_PINS = {
    "id": "mint",
    "isoInstaller": "https://pub.linuxmint.io/stable/22.3/linuxmint-22.3-cinnamon-64bit.iso",
    "isoInstallerSha256": "a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4",
    "isoInstallerSizeBytes": 3091660800,
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


def scope2b_branch(base: str) -> str:
    if not SHA.fullmatch(base):
        raise ValueError("Invalid scope2b dev SHA")
    return f"bot/gaslux-scope2b-mint-pins-{base[:12]}"


def scope2b_eligible(root: Path, base: str) -> bool:
    """Admission uses authenticated GitHub issue data AND trusted main scope."""
    target = root / SCOPE2B_TARGET
    if (not target.is_file() or
        f"def {SCOPE2B_FN}(".encode() in target.read_bytes()):
        return False
    release_file = root / "release-config.json"
    if not release_file.is_file():
        return False
    release = json.loads(release_file.read_text(encoding="utf-8"))
    items = release.get("distributions")
    if (type(items) is not list or
        len([x for x in items if type(x) is dict and x.get("id") == "mint"]) != 1):
        raise ValueError("Untrusted release descriptor shape")
    mint = next(x for x in items if type(x) is dict and x.get("id") == "mint")
    if any(type(mint.get(k)) is not type(v) or mint.get(k) != v
           for k, v in SCOPE2B_PINS.items()):
        raise ValueError("Dev Mint media pins moved: scope needs re-review")
    issue = subprocess.run(
        ["gh", "api", f"repos/{REPO}/issues/{SCOPE2B_ISSUE}"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if issue.returncode != 0:
        raise RuntimeError("Cannot authenticate reviewed scope issue")
    row = json.loads(issue.stdout)
    if (type(row) is not dict or row.get("number") != SCOPE2B_ISSUE or
        row.get("state") != "open" or row.get("repository_url") !=
        f"https://api.github.com/repos/{REPO}" or
        type(row.get("user")) is not dict or
        row["user"].get("login") != "github-actions[bot]" or
        row["user"].get("type") != "Bot" or
        row["user"].get("id") != 41898282 or
        row.get("title") !=
        "[GASLUX-AUTO] mint / windows10-bios-mbr / source-authenticity: scope & acceptance" or
        not isinstance(row.get("body"), str) or
        row["body"].splitlines()[0] !=
        "<!-- GASLUX-AUTOTASK:mint:windows10-bios-mbr:source-authenticity -->"):
        raise ValueError("Unexpected issue #404 identity or gate")
    branch = scope2b_branch(base)
    check = subprocess.run(
        ["gh", "api", f"repos/{REPO}/git/ref/heads/{branch}"],
        text=True, capture_output=True, check=False, timeout=20,
    )
    if check.returncode == 0:
        return False
    if "404" not in check.stderr and "Not Found" not in check.stderr:
        raise RuntimeError("Cannot establish scoped bot branch absence")
    return True


def discover_goal_backlog(root: Path) -> dict:
    """Read-only triage of real missing distro gates; NEVER grant code authority.

    The dev goal and evidence are *data*, not trusted instructions or external
    attestations. A declared record is never equivalent to an independently
    proven installation, so no slot can be marked verified here.
    """
    goal_path = root / "docs/autonomy/goal.json"
    evidence_path = root / "docs/autonomy/evidence.json"
    if (not goal_path.is_file() or not evidence_path.is_file() or
        goal_path.stat().st_size > 32768 or evidence_path.stat().st_size > 131072):
        raise ValueError("Bounded goal and evidence inputs required")
    goal = json.loads(goal_path.read_text(encoding="utf-8"))
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    platforms = ("windows10-bios-mbr", "windows10-uefi-gpt", "windows11-uefi-gpt")
    if (type(goal) is not dict or type(evidence) is not dict or
        type(goal.get("schema_version")) is not int or goal["schema_version"] != 1 or
        type(evidence.get("schema_version")) is not int or
        evidence["schema_version"] != 1 or
        goal.get("gates") != list(GATES) or
        goal.get("platforms") != list(platforms) or
        goal.get("automatic_safe_gates") != list(GATES[:2]) or
        goal.get("protected_gates") != list(GATES[2:])):
        raise ValueError("Untrusted lifecycle gate matrix")
    backends, records = goal.get("backends"), evidence.get("records")
    if (type(backends) is not list or len(backends) != len(TASKS) or
        type(records) is not list or len(records) > 400):
        raise ValueError("Unexpected backend or evidence registry")
    seen, verified_claims = set(), set()
    for row in backends:
        if type(row) is not dict or row.get("id") not in TASKS:
            raise ValueError("Unknown backend in goal")
        role = row["id"]
        if role in seen:
            raise ValueError("Duplicate backend goal")
        seen.add(role)
        supported = row.get("platforms")
        if (type(supported) is not list or not supported or
            len(set(supported)) != len(supported) or
            any(p not in platforms for p in supported) or
            (role == "bazzite" and supported != list(platforms[1:])) or
            (role != "bazzite" and supported != list(platforms)) or
            type(row.get("priority")) is not int or
            not 0 <= row["priority"] < len(TASKS) or
            type(row.get("issue_numbers")) is not list or
            any(type(n) is not int or n <= 0 for n in row["issue_numbers"])):
            raise ValueError("Unsupported backend/platform scope")
    if seen != set(TASKS) or {b["priority"] for b in backends} != set(range(len(TASKS))):
        raise ValueError("Missing or ambiguous backend priorities")
    for row in records:
        if type(row) is not dict:
            raise ValueError("Malformed evidence row")
        key = (row.get("backend"), row.get("platform"), row.get("gate"))
        if (key in verified_claims or key[0] not in TASKS or
            key[1] not in next(b["platforms"] for b in backends if b["id"] == key[0]) or
            key[2] not in GATES):
            raise ValueError("Unknown or duplicated evidence slot")
        verified_claims.add(key)
    next_gates = []
    for row in sorted(backends, key=lambda item: item["priority"]):
        role = row["id"]
        platform, gate = row["platforms"][0], GATES[0]
        next_gates.append({
            "role": role, "platform": platform, "gate": gate,
            "state": ("declared_unverified" if (role, platform, gate) in verified_claims
                      else "missing_evidence"),
            "code_authorized": False, "release_eligible": False,
            "related_issues": row["issue_numbers"],
        })
    return {
        "status": "blocked", "role": "", "next_gates": next_gates,
        "required_gate_slots": sum(len(b["platforms"]) * len(GATES) for b in backends),
        "independently_verified_slots": 0,
        "reason": "No remaining approved code scope; real gate evidence/review pending",
    }


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
        return {"status": "pending", "role": role, "base": base, "task": TASKS[role][2], "scope": "lifecycle"}
    backlog = discover_goal_backlog(root)
    if scope2b_eligible(root, base):
        return {
            "status": "pending", "role": "mint", "base": base,
            "scope": SCOPE2B_ID, "task": SCOPE2B_TASK,
            "gate": SCOPE2B_GATE, "platform": SCOPE2B_PLATFORM,
            "issue": SCOPE2B_ISSUE,
        }
    return {"base": base, **backlog}


def validate_addition(
    role: str, addition: str, *, execute: bool, scope: str = "lifecycle",
) -> None:
    if scope not in ("lifecycle", SCOPE2B_ID) or (scope == SCOPE2B_ID and role != "mint"):
        raise ValueError("Unreviewed code task scope")
    if role not in TASKS or type(addition) is not str or not 75 <= len(addition) <= 5500:
        raise ValueError("Invalid scope or empty proposal")
    if "\r" in addition or "\x00" in addition or addition.count("\n") > 100:
        raise ValueError("Oversized or noncanonical source")
    function_name = SCOPE2B_FN if scope == SCOPE2B_ID else f"assess_{role}_lifecycle"
    argument_name = "candidate" if scope == SCOPE2B_ID else "evidence"
    if not addition.startswith(f"def {function_name}({argument_name}: dict) -> dict:"):
        raise ValueError("Model must implement the exact reviewed function signature")
    parsed = ast.parse(addition)
    if len(parsed.body) != 1 or not isinstance(parsed.body[0], ast.FunctionDef):
        raise ValueError("Only one function permitted")
    node = parsed.body[0]
    if (node.decorator_list or len(node.args.args) != 1 or
        node.args.args[0].arg != argument_name or node.args.defaults or
        node.args.kwonlyargs or node.args.vararg or node.args.kwarg):
        raise ValueError("Unexpected callable signature")
    for n in ast.walk(node):
        if isinstance(n, ast.FunctionDef) and n is not node:
            raise ValueError("Nested function is forbidden")
        if isinstance(n, (ast.Subscript, ast.Attribute)) and not isinstance(n.ctx, ast.Load):
            raise ValueError("Only local variable assignments are permitted")
        if isinstance(n, (ast.AugAssign, ast.NamedExpr)):
            raise ValueError("In-place mutation is forbidden")
        if isinstance(n, FORBIDDEN):
            raise ValueError("Code includes a prohibited operation")
        if isinstance(n, ast.Attribute) and n.attr != "get":
            raise ValueError("Only read-only dict.get is permitted")
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                if f.id == "type" and scope == SCOPE2B_ID:
                    # Only introspection of the exact reviewed input/fields:
                    # never type(name, bases, namespace) or arbitrary objects.
                    if len(n.args) != 1 or n.keywords:
                        raise ValueError("Scoped type check must have one argument")
                    arg = n.args[0]
                    if isinstance(arg, ast.Name):
                        admitted = arg.id == "candidate"
                    elif (isinstance(arg, ast.Call) and
                          isinstance(arg.func, ast.Attribute) and
                          arg.func.attr == "get" and
                          isinstance(arg.func.value, ast.Name) and
                          arg.func.value.id == "candidate" and
                          len(arg.args) == 1 and
                          isinstance(arg.args[0], ast.Constant) and
                          type(arg.args[0].value) is str and
                          arg.args[0].value in SCOPE2B_PINS and
                          not arg.keywords):
                        admitted = True
                    else:
                        admitted = False
                    if not admitted:
                        raise ValueError("Unapproved scoped type introspection")
                elif f.id not in SAFE_BUILTINS:
                    raise ValueError("Unauthorized call")
            elif not (isinstance(f, ast.Attribute) and f.attr == "get"):
                raise ValueError("Unauthorized call")
        if isinstance(n, ast.Name) and (n.id.startswith("__") or
                                         n.id in {"open", "exec", "eval", "compile", "globals", "locals"}):
            raise ValueError("Untrusted runtime reference")
    if scope == SCOPE2B_ID:
        # Provable static invariant: no branch may turn authentication,
        # installation or release flags on, including inputs outside fixtures.
        returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
        if len(returns) != 1 or not isinstance(returns[0].value, ast.Dict):
            raise ValueError("Scoped task requires one literal result dict")
        returned = returns[0].value
        if any(not isinstance(k, ast.Constant) or type(k.value) is not str
               for k in returned.keys):
            raise ValueError("Scoped return keys must be literal strings")
        values = dict(zip((k.value for k in returned.keys), returned.values))
        if set(values) != {
            "backend", "pinnedDescriptorMatches", "sourceAuthenticityVerified",
            "installationAuthorized", "releaseEligible"
        } or any(not isinstance(values[k], ast.Constant) or values[k].value is not False
                 for k in ("sourceAuthenticityVerified",
                           "installationAuthorized", "releaseEligible")):
            raise ValueError("Protected flags must be literal False in AST")
    if not execute:
        return
    # Do not expand the legacy AST/builtins. "int" is an immutable type
    # reference, not an allowed call; "type" is single-argument, scope2b-only.
    admitted_builtins = (
        {**SAFE_BUILTINS, "type": type, "int": int}
        if scope == SCOPE2B_ID else SAFE_BUILTINS
    )
    env = {"__builtins__": admitted_builtins}
    namespace: dict = {}
    exec(compile(parsed, "<isolated-code-proposal>", "exec"), env, namespace)
    fn = namespace[function_name]
    if scope == SCOPE2B_ID:
        good = dict(SCOPE2B_PINS)
        class _StrSubclass(str):
            pass

        class _IntSubclass(int):
            pass

        class _DictSubclass(dict):
            def get(self, *_args, **_kwargs):
                raise ValueError("Subclass .get must never be executed")

        mutations = [
            {"id": "zorin"},
            {"isoInstaller": "https://invalid.example/mint.iso"},
            {"isoInstallerSha256": "0" * 64},
            {"isoInstallerSizeBytes": 3091660799},
            {"isoInstallerSizeBytes": 3091660800.0},
            {"isoInstallerSizeBytes": "3091660800"},
            {"isoInstallerSizeBytes": True},
            {"isoInstallerSizeBytes": _IntSubclass(3091660800)},
            {"isoInstaller": _StrSubclass(SCOPE2B_PINS["isoInstaller"])},
            {"isoInstallerSha256": _StrSubclass(SCOPE2B_PINS["isoInstallerSha256"])},
            {"id": _StrSubclass("mint")},
            {"id": True},
        ]
        fixtures = [good, {}, {"id": "mint"}, None, [], "mint",
                    _DictSubclass(good)]
        fixtures += [{**good, **row} for row in mutations]
        for candidate in fixtures:
            before = dict(candidate) if type(candidate) is dict else candidate
            result = fn(candidate)
            expected = type(candidate) is dict and all(
                type(candidate.get(k)) is type(v) and candidate.get(k) == v
                for k, v in SCOPE2B_PINS.items()
            )
            if type(candidate) is dict and candidate != before:
                raise ValueError("Model mutated source descriptor")
            if (type(result) is not dict or set(result) != {
                "backend", "pinnedDescriptorMatches", "sourceAuthenticityVerified",
                "installationAuthorized", "releaseEligible"
            } or result["backend"] != "mint" or
                type(result["pinnedDescriptorMatches"]) is not bool or
                result["pinnedDescriptorMatches"] != expected or
                result["sourceAuthenticityVerified"] is not False or
                result["installationAuthorized"] is not False or
                result["releaseEligible"] is not False):
                raise ValueError("Mint media pin contract failed")
        return
    for checked in ((), GATES):
        evidence = {gate: (gate in checked) for gate in GATES}
        expected_evidence = dict(evidence)
        result = fn(evidence)
        if evidence != expected_evidence:
            raise ValueError("Lifecycle helper mutated input evidence")
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


def expected_source(root: Path, role: str, addition: str, *, scope: str = "lifecycle") -> tuple[bytes, bytes]:
    path = root / TASKS[role][0]
    original = path.read_bytes()
    if len(original) > 25000 or b"\r" in original:
        raise ValueError("Unexpected source file format")
    if scope not in ("lifecycle", SCOPE2B_ID) or (scope == SCOPE2B_ID and role != "mint"):
        raise ValueError("Unexpected code scope")
    function_name = SCOPE2B_FN if scope == SCOPE2B_ID else f"assess_{role}_lifecycle"
    if f"def {function_name}(".encode() in original:
        raise ValueError("Feature already implemented")
    proposed = original.rstrip(b"\n") + b"\n\n" + addition.rstrip().encode("utf-8") + b"\n"
    if len(proposed) > 32000:
        raise ValueError("Proposed source too large")
    return original, proposed


def verify(root: Path, evidence_dir: Path, role: str, base: str, *, execute: bool,
           scope: str = "lifecycle") -> dict:
    if role not in TASKS or not SHA.fullmatch(base) or git(root, "rev-parse", "HEAD") != base:
        raise ValueError("Wrong immutable source checkout")
    report = json.loads((evidence_dir / "report.json").read_text(encoding="utf-8"))
    addition_raw = (evidence_dir / "addition.py").read_bytes()
    addition = addition_raw.decode("utf-8")
    expected_task = SCOPE2B_TASK if scope == SCOPE2B_ID else TASKS[role][2]
    if scope not in ("lifecycle", SCOPE2B_ID):
        raise ValueError("Unapproved source scope")
    if (report.get("scope", "lifecycle") != scope or
        (scope == SCOPE2B_ID and
         (report.get("issue") != SCOPE2B_ISSUE or
          report.get("gate") != SCOPE2B_GATE or
          report.get("platform") != SCOPE2B_PLATFORM))):
        raise ValueError("Scope evidence binding mismatch")
    if (report.get("role") != role or report.get("base") != base or
        report.get("task") != expected_task or
        report.get("target") != TASKS[role][0] or
        report.get("model") != MODEL or report.get("model_digest") != MODEL_DIGEST or
        report.get("addition_sha256") != sha256(addition_raw)):
        raise ValueError("Untrusted source/report identity")
    validate_addition(role, addition, execute=execute, scope=scope)
    before, after = expected_source(root, role, addition, scope=scope)
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


def generate(root: Path, evidence_dir: Path, role: str, base: str, *, scope: str = "lifecycle") -> None:
    if (git(root, "rev-parse", "HEAD") != base or role not in TASKS or
        scope not in ("lifecycle", SCOPE2B_ID) or
        (scope == SCOPE2B_ID and role != "mint")):
        raise ValueError("Wrong worker source identity or scope")
    source, test, objective = TASKS[role]
    if scope == SCOPE2B_ID:
        objective = SCOPE2B_TASK
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
    if scope == SCOPE2B_ID:
        task = (
            "Implement a REAL read-only preflight function that compares the "
            "Linux Mint 22.3 Cinnamon ISO descriptor fields with the exact "
            "trusted pinned release metadata. No I/O, SHA calculation, install "
            "or release authority. Only match already-declared pins. "
            "EXACT signature: def match_mint_223_iso_descriptor(candidate: dict) -> dict:\n"
            "The descriptor keys/values to compare are: "
            f"{SCOPE2B_PINS!r}. Require type(candidate) is dict (never "
            "isinstance, as dict subclasses are forbidden). For all four "
            "fields compare BOTH type(candidate.get(key)) is str/int and "
            "candidate.get(key) == its exact pinned value. The size MUST "
            "have type int, rejecting 3091660800.0, bool and int subclasses. "
            "For id, URL and SHA256 require type str, rejecting str subclasses. "
            "The safe type(x) call is allowed in THIS scope only, with exactly "
            "one argument: candidate or candidate.get(one of four pin keys). "
            "Do not use type(x,y,z), int(...), or other constructor calls. "
            "Missing, wrong-type or mismatched fields MUST be rejected. "
            "Return EXACT dict keys: "
            "backend='mint', pinnedDescriptorMatches=boolean match, "
            "sourceAuthenticityVerified=False, installationAuthorized=False, "
            "releaseEligible=False. All three protected flags MUST be "
            "literal False constants in exactly ONE return dict literal. "
            "Descriptor matching is NOT authentication. "
            "Do not use import, class, nested function, for, while, I/O, "
            "filesystem, globals, external data, side effects or assert. "
            "Only permitted attribute is candidate.get. Only approved "
            "legacy builtins and scoped single-argument type(...) are allowed. "
            "The int name is a type identity, never a callable conversion. "
            "Return ONE function in JSON with EXACT key addition; no markdown.\n"
        )
    last: Exception | None = None
    last_category = "No response"
    for attempt in range(2):
        addition: str | None = None
        try:
            addition = call_model(task)
            validate_addition(role, addition, execute=True, scope=scope)
            before, after = expected_source(root, role, addition, scope=scope)
            evidence_dir.mkdir(parents=True, exist_ok=True)
            data = addition.rstrip().encode() + b"\n"
            (evidence_dir / "addition.py").write_bytes(data)
            report = {
                "role": role, "base": base, "task": objective, "target": source,
                "scope": scope,
                "model": MODEL, "model_digest": MODEL_DIGEST,
                "source_sha256": sha256(before), "candidate_sha256": sha256(after),
                "addition_sha256": sha256(data),
            }
            if scope == SCOPE2B_ID:
                report.update({
                    "issue": SCOPE2B_ISSUE, "gate": SCOPE2B_GATE,
                    "platform": SCOPE2B_PLATFORM,
                })
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

def publish(root: Path, evidence_dir: Path, role: str, base: str, *, scope: str = "lifecycle") -> None:
    if os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true":
        raise RuntimeError("GASLUX_AUTONOMY_PAUSED: model Draft publisher blocked")
    if os.getenv("GITHUB_REPOSITORY") != REPO or os.getenv("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Only trusted default-branch Actions may publish")
    # Static-only checks: never execute model text in a token-bearing job.
    verify(root, evidence_dir, role, base, execute=False, scope=scope)
    git(root, "fetch", "origin", "refs/heads/dev:refs/remotes/origin/dev")
    live = git(root, "rev-parse", "refs/remotes/origin/dev")
    if not safe_forward_draft_base(root, role, base, live):
        print(json.dumps({"status": "stale_or_relevant_dev_change", "role": role}))
        return
    if scope == SCOPE2B_ID:
        # The source and acceptance test are unchanged on a forward-only
        # rebase; also reject an unrelated change to the pinned release.
        # Validate CURRENT live-dev metadata, not the old artifact checkout.
        live_release = subprocess.check_output(
            ["git", "-C", str(root), "show", f"{live}:release-config.json"],
            text=True, timeout=20,
        )
        release = json.loads(live_release)
        if type(release) is not dict or type(release.get("distributions")) is not list:
            raise ValueError("Unexpected live dev release descriptor")
        mint = [x for x in release["distributions"]
                if type(x) is dict and x.get("id") == "mint"]
        if (len(mint) != 1 or any(type(mint[0].get(k)) is not type(v) or
                                  mint[0].get(k) != v for k, v in SCOPE2B_PINS.items())):
            raise ValueError("Mint release pins drifted; regenerate under new review")
        branch = scope2b_branch(base)
    else:
        branch = origin_branch(role, base)
    addition = (evidence_dir / "addition.py").read_text(encoding="utf-8")
    # Safe forward-only changes are included by ancestry, but this review PR
    # is still always Draft. No model text runs with publication credentials.
    git(root, "checkout", "-b", branch, live)
    _, proposed = expected_source(root, role, addition, scope=scope)
    (root / TASKS[role][0]).write_bytes(proposed)
    if git(root, "diff", "--name-only") != TASKS[role][0]:
        raise ValueError("Unexpected changed product path")
    subprocess.run(["git", "-C", str(root), "diff", "--check"], check=True)
    git(root, "add", "--", TASKS[role][0])
    subprocess.run(["git", "-C", str(root), "config", "user.name", "github-actions[bot]"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], check=True)
    commit_subject = (f"feat({role}): check pinned Mint 22.3 ISO descriptor"
                      if scope == SCOPE2B_ID else
                      f"feat({role}): isolated lifecycle evidence proposal")
    subprocess.run(["git", "-C", str(root), "commit", "-m", commit_subject], check=True)
    # No implicit token is available in any model-inference or test runner.
    subprocess.run(["gh", "auth", "setup-git"], check=True)
    subprocess.run(["git", "-C", str(root), "push", "origin", f"HEAD:refs/heads/{branch}"], check=True)
    body = (f"Unprivileged Qwen3.5 9B proposal for {role}, pinned base {base}.\n\n"
            "Pure read-only lifecycle evidence helper appended to real backend source. "
            "Static AST scope and independent isolated acceptance checked; the PR is a "
            "**Draft**. Requires backend owner, independent Safety review, full "
            "Windows/Linux VM acceptance and normal CI. **No auto-merge permission; "
            "no installed guest, dual boot, uninstall, disk writer or release proof.**")
    if scope == SCOPE2B_ID:
        body = (
            f"Qwen 3.5 9B task scoped by trusted main for issue #{SCOPE2B_ISSUE}; "
            f"dev base {base}; platform {SCOPE2B_PLATFORM}; gate {SCOPE2B_GATE}.\n\n"
            "Adds a **read-only pinned ISO descriptor match**, not cryptographic "
            "origin validation. Source authenticity remains UNVERIFIED even "
            "when all declared fields match. No disk/boot/installation authority. "
            "Independent AST/functional checks and product regressions required. "
            "This PR must remain Draft pending backend Safety, normal CI and "
            "separate Windows/Linux VM acceptance. Never auto-merge or release."
        )
    title = (f"feat(mint): pinned ISO descriptor preflight from task #{SCOPE2B_ISSUE}"
             if scope == SCOPE2B_ID else
             f"feat({role}): autonomous lifecycle evidence proposal")
    subprocess.run(["gh", "pr", "create", "--repo", REPO, "--draft", "--base", "dev",
                    "--head", branch, "--title", title, "--body", body], check=True)


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("action", choices=("plan", "generate", "verify", "publish"))
    cli.add_argument("--repo", type=Path, required=True)
    cli.add_argument("--evidence", type=Path, default=Path("evidence/feature-factory"))
    cli.add_argument("--role", choices=tuple(TASKS))
    cli.add_argument("--scope", choices=("lifecycle", SCOPE2B_ID), default="lifecycle")
    cli.add_argument("--base")
    args = cli.parse_args()
    root = args.repo.resolve(strict=True)
    if args.action == "plan":
        print(json.dumps(plan(root), sort_keys=True))
        return
    if not args.role or not args.base:
        cli.error("Pinned role/base SHA required")
    if args.action == "generate":
        generate(root, args.evidence, args.role, args.base, scope=args.scope)
    elif args.action == "verify":
        print(json.dumps(verify(root, args.evidence, args.role, args.base,
                                execute=True, scope=args.scope), sort_keys=True))
    else:
        publish(root, args.evidence, args.role, args.base, scope=args.scope)


if __name__ == "__main__":
    main()
