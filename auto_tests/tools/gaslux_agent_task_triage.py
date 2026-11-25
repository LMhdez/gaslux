#!/usr/bin/env python3
"""Trusted, main-only task-queue admission for genuine six-distro gate gaps.

This publishes *review requests*, never model code, installer authority, or
an evidence pass. The caller's job must have issues:write but no App private key.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

from gaslux_agent_feature_factory import (
    REPO, SHA, TASKS, discover_goal_backlog,
)

from gaslux_agent_history import review_hint

API = "https://api.github.com/repos/" + REPO
BOT_BRANCH = re.compile(
    r"bot/gaslux-feature-(mint|zorin|cachyos|popos|q4os|bazzite)-[0-9a-f]{12}\Z"
)
KEY = re.compile(
    r"<!-- GASLUX-AUTOTASK:(mint|zorin|cachyos|popos|q4os|bazzite):"
    r"(windows10-bios-mbr|windows10-uefi-gpt|windows11-uefi-gpt):"
    r"(source-authenticity|windows-preflight|install|linux-first-boot|"
    r"windows-return|linux-update-reboot|uninstall-windows-integrity|"
    r"fault-injection-rollback) -->"
)


def api(method: str, route: str, payload: dict | None = None):
    """No arbitrary endpoint or token ever originates from dev JSON."""
    if not (method == "GET" and route in (
        "/git/ref/heads/dev", "/pulls?state=open&per_page=100"
    ) or method == "GET" and re.fullmatch(
        r"/issues\?state=all&per_page=100&page=(?:[1-9]|1[0-9]|20)", route
    ) or method == "POST" and route == "/issues"):
        raise ValueError("Unapproved task-triage API operation")
    if method == "POST" and (
        type(payload) is not dict or set(payload) != {"title", "body"} or
        type(payload["title"]) is not str or len(payload["title"]) > 160 or
        type(payload["body"]) is not str or len(payload["body"]) > 6000
    ):
        raise ValueError("Invalid bounded task issue")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise RuntimeError("Missing read/write identity")
    req = urllib.request.Request(
        API + route, method=method,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if payload else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub task-triage API HTTP {exc.code}") from exc


def all_issues() -> list[dict]:
    """Read the full bounded history; never rely on eventually indexed search."""
    found = []
    for page in range(1, 21):
        batch = api("GET", f"/issues?state=all&per_page=100&page={page}")
        if type(batch) is not list or any(type(x) is not dict for x in batch):
            raise ValueError("Unexpected issue history")
        found.extend(x for x in batch if "pull_request" not in x)
        if len(batch) < 100:
            return found
    raise RuntimeError("Issue history exceeds bounded dedup scope")


# Exact issue author identities only; contributor-controlled text has no authority.
TRUSTED_TASK_BOT = "github-actions[bot]"


def trusted_task_keys(issues: list[dict]) -> set[tuple[str, str, str]]:
    """Only canonical, same-repository issues written by the trusted bot count."""
    if type(issues) is not list:
        raise ValueError("Untrusted issue history")
    result = set()
    for issue in issues:
        if type(issue) is not dict:
            raise ValueError("Malformed issue")
        body = issue.get("body") or ""
        if type(body) is not str:
            raise ValueError("Malformed issue body")
        author = issue.get("user")
        if (issue.get("repository_url") != API or
            type(author) is not dict or author.get("login") != TRUSTED_TASK_BOT or
            "pull_request" in issue):
            continue
        # A foreign user's pasted marker, even in a legitimate issue, is inert.
        first = body.split("\n", 1)[0]
        match = KEY.fullmatch(first)
        if match is None or not body.startswith(first + "\n"):
            continue
        role, platform, gate = match.groups()
        expected_title = (
            f"[GASLUX-AUTO] {role} / {platform} / {gate}: scope & acceptance"
        )
        if issue.get("title") == expected_title:
            result.add((role, platform, gate))
    return result


# Owner-vetted canonical existing issue IDs. Mapping resides only in trusted main,
# never in dev goal JSON or user-supplied issue text. A broad source-authenticity
# prerequisite may apply to multiple firmware profiles; this grants NO code scope.
CANONICAL_ISSUE_SCOPE = {
    3: {
        "author": "Dinisiho",
        "title": "CachyOS production-stability acceptance criteria (UEFI, dual boot, rollback)",
        "keys": frozenset((
            ("cachyos", "windows10-bios-mbr", "source-authenticity"),
            ("cachyos", "windows10-uefi-gpt", "source-authenticity"),
            ("cachyos", "windows11-uefi-gpt", "source-authenticity"),
        )),
    },
    71: {
        "author": "Dinisiho",
        "title": "CachyOS: prove Windows 11 UEFI/GPT coexistence, ESP/BCD/WinRE preservation and rollback in QEMU",
        "keys": frozenset((
            ("cachyos", "windows11-uefi-gpt", "windows-return"),
            ("cachyos", "windows11-uefi-gpt", "fault-injection-rollback"),
        )),
    },
    254: {
        "author": "LMhdez",
        "title": "Bazzite: bloquear promoção até provar ISO autenticada, write-set e recuperação Windows",
        "keys": frozenset((
            ("bazzite", "windows10-uefi-gpt", "source-authenticity"),
            ("bazzite", "windows11-uefi-gpt", "source-authenticity"),
        )),
    },
}
APP_BOT_LOGIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,78})\[bot\]\Z")


def checked_app_bot_login(value: str) -> str:
    """Trusted workflow setting, not a role/issue value from dev."""
    if type(value) is not str or (value and not APP_BOT_LOGIN.fullmatch(value)):
        raise ValueError("Unverified GitHub App bot login configuration")
    if value == TRUSTED_TASK_BOT:
        raise ValueError("App identity must differ from the legacy Actions bot")
    return value


def trusted_related_issues(
    issues: list[dict], role: str, platform: str, gate: str, numbers: list[int],
) -> list[int]:
    """A dev reference only counts with an exact main-pinned gate and issue ID."""
    if type(numbers) is not list or any(type(n) is not int or n <= 0 for n in numbers):
        raise ValueError("Untrusted related issue list")
    key = (role, platform, gate)
    matching = []
    for issue in issues:
        if type(issue) is not dict:
            raise ValueError("Malformed issue")
        n = issue.get("number")
        vetted = CANONICAL_ISSUE_SCOPE.get(n) if type(n) is int else None
        if vetted is None or n not in numbers or key not in vetted["keys"]:
            continue
        author = issue.get("user")
        if (issue.get("repository_url") != API or
            issue.get("state") != "open" or
            "pull_request" in issue or
            type(author) is not dict or
            author.get("login") != vetted["author"] or
            issue.get("title") != vetted["title"]):
            continue
        matching.append(n)
    return sorted(set(matching))


def choose(
    backlog: dict, prs: list[dict], issues: list[dict], *, app_bot_login: str = "",
) -> dict:
    """Choose one gate; unknown internal App bots fail closed to prevent duplicates."""
    app_bot_login = checked_app_bot_login(app_bot_login)
    if backlog.get("status") != "blocked" or type(backlog.get("next_gates")) is not list:
        raise ValueError("Unreviewed task-discovery status")
    if type(prs) is not list or len(prs) >= 100:
        raise ValueError("Unbounded PR history")
    open_roles = set()
    for pr in prs:
        if type(pr) is not dict:
            raise ValueError("Malformed PR")
        head, base, author = pr.get("head"), pr.get("base"), pr.get("user")
        if type(head) is not dict or type(base) is not dict:
            raise ValueError("Malformed PR refs")
        name = head.get("ref", "")
        match = BOT_BRANCH.fullmatch(name) if type(name) is str else None
        if (match is not None and base.get("ref") == "dev" and
            type(head.get("repo")) is dict and
            head["repo"].get("full_name") == REPO and
            type(base.get("repo")) is dict and
            base["repo"].get("full_name") == REPO and
            type(author) is dict and author.get("type") == "Bot"):
            if author.get("login") in (TRUSTED_TASK_BOT, app_bot_login):
                open_roles.add(match.group(1))
            else:
                # Not safe to dedupe as a known App, nor to create a duplicate
                # review task while a same-repo bot candidate is unexplained.
                raise ValueError("Unknown same-repository bot PR actor")
    tracked = trusted_task_keys(issues)
    pending = []
    for task in backlog["next_gates"]:
        if (type(task) is not dict or task.get("role") not in TASKS or
            task.get("code_authorized") is not False or
            task.get("release_eligible") is not False or
            task.get("state") not in ("missing_evidence", "declared_unverified") or
            task.get("gate") != "source-authenticity"):
            raise ValueError("Task authority or gate mismatch")
        role = task["role"]
        key = (role, task["platform"], task["gate"])
        if role in open_roles:
            pending.append({"role": role, "status": "pending_existing_pr"})
            continue
        # IDs from dev are untrusted until a live issue verifies origin and role.
        related = trusted_related_issues(
            issues, role, task["platform"], task["gate"], task["related_issues"]
        )
        if related:
            pending.append({"role": role, "status": "linked_existing_issue",
                            "issues": related})
            continue
        if key in tracked:
            pending.append({"role": role, "status": "already_queued"})
            continue
        return {"status": "ready_for_scope_review", "role": role,
                "platform": task["platform"], "gate": task["gate"],
                "key": key, "pending": pending}
    return {"status": "waiting_for_review", "pending": pending}


def issue_payload(task: dict, base: str) -> dict:
    role = task["role"]
    source, test, _ = TASKS[role]
    marker = f"<!-- GASLUX-AUTOTASK:{role}:{task['platform']}:{task['gate']} -->"
    return {
        "title": f"[GASLUX-AUTO] {role} / {task['platform']} / {task['gate']}: scope & acceptance",
        "body": (
            f"{marker}\n"
            "**Autonomously identified goal gap — scope review required.**\n\n"
            f"- Backend: `{role}`; Windows platform: `{task['platform']}`; "
            f"missing gate: `{task['gate']}`\n"
            f"- Source snapshot (dev): `{base}`\n"
            f"- Candidate source for owner review: `{source}`\n"
            f"- Existing regression suite: `auto_tests/tests/{test}`\n"
            "- Next step: backend owner defines a **real** missing capability, precise "
            "code paths and positive/negative tests. Reconcile existing PRs first.\n"
            f"- {review_hint(role, task['gate'])}"
            "- Required evidence: authentic release/media provenance, Windows preflight "
            "and reproducible read-only contracts; do not confuse declared JSON with "
            "independent proof.\n"
            "- Safety status: **NEEDS_SCOPE_REVIEW**. Qwen has **no** code authorization "
            "from this issue, even for a gate labelled automatic_safe.\n"
            "- Installation, disk/ESP/BCD/WinRE changes, VM writes, boot, uninstall "
            "and release remain prohibited until their separate approvals and evidence.\n"
            "- Dedup identity is backend/platform/gate; no duplicate issue on source "
            "revision. No force-push or auto-merge.\n\n"
            "Parent: #401. Product objective: AGENTS.md and "
            "dev:docs/autonomy/goal.json.\n"
        ),
    }


def sync(root: Path, *, dry_run: bool = False) -> dict:
    if (os.getenv("GITHUB_REPOSITORY") != REPO or
        os.getenv("GITHUB_REF") != "refs/heads/main" or
        os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true" or
        os.getenv("GITHUB_EVENT_NAME") not in ("push", "schedule", "workflow_dispatch")):
        raise RuntimeError("Trusted unpaused main event required")
    base = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True, timeout=12
    ).strip()
    if not SHA.fullmatch(base):
        raise ValueError("Untrusted dev checkout SHA")
    current = api("GET", "/git/ref/heads/dev")
    if current.get("object", {}).get("sha") != base:
        raise RuntimeError("Dev moved; refuse stale task issue")
    backlog = discover_goal_backlog(root)
    prs = api("GET", "/pulls?state=open&per_page=100")
    issues = all_issues()
    picked = choose(
        backlog, prs, issues,
        app_bot_login=os.environ.get("GASLUX_PUBLISH_APP_BOT_LOGIN", ""),
    )
    if picked["status"] != "ready_for_scope_review":
        return {"base": base, **picked}
    payload = issue_payload(picked, base)
    if dry_run:
        return {"base": base, "status": "dry_run", "title": payload["title"]}
    if api("GET", "/git/ref/heads/dev").get("object", {}).get("sha") != base:
        raise RuntimeError("Dev changed during triage")
    # Re-read issue history immediately before create. A concurrent runner
    # must never create a second issue with the same stable marker.
    if picked["key"] in trusted_task_keys(all_issues()):
        return {"status": "already_queued", "base": base, "role": picked["role"]}
    created = api("POST", "/issues", payload)
    if (type(created) is not dict or type(created.get("number")) is not int or
        created["number"] <= 0):
        raise RuntimeError("GitHub did not confirm task issue")
    return {"status": "review_issue_created", "base": base, "role": picked["role"],
            "issue": created["number"]}


# The existing issue publisher is reused; no PR/code/merge authority.
REPAIR_KEY = re.compile(
    r"<!-- GASLUX-STALE-CANDIDATE-V1:([1-9][0-9]{0,5}):([0-9a-f]{40}) -->"
)


def repair_eligible(row, number, role, head):
    return (
        type(row) is dict and row.get("pr") == number and row.get("role") == role
        and row.get("head") == head and isinstance(row.get("base"), str)
        and SHA.fullmatch(row["base"]) is not None
        and row.get("exact_scope_verified") is True
        and row.get("current_base_verified") is False
        and row.get("ci_verified") is True
        and row.get("ci_workflow_provenance_verified") is True
        and row.get("technical_objection") is False
        and row.get("merge_authorized") is False
        and row.get("release_eligible") is False
        and row.get("next_action") == "REFRESH_CANDIDATE_BASE"
    )


def repair_issue_payload(number, head, base, role):
    if (type(number) is not int or not 1 <= number <= 999999
            or not isinstance(head, str) or not SHA.fullmatch(head)
            or not isinstance(base, str) or not SHA.fullmatch(base)
            or role not in ("zorin", "bazzite", "cachyos", "popos", "q4os")):
        raise ValueError("Invalid repair identity")
    return {
        "title": f"[GASLUX-REPAIR] #{number} stale candidate base",
        "body": (
            f"<!-- GASLUX-STALE-CANDIDATE-V1:{number}:{head} -->\n"
            "Automatically routed by trusted Safety/Integrator triage. "
            "NEEDS_SCOPE_REVIEW; not a code or merge authorization.\n\n"
            f"- Backend: {role}; candidate: #{number}; exact HEAD: {head}\n"
            f"- Observed dev: {base}\n"
            "- Compare original parent to current dev, preserve the old PR and "
            "any unique evidence; check if its helper is already integrated.\n"
            "- If still needed, prepare a fresh exact-scope proposal only after "
            "the applicable existing Factory/Safety gates. Re-run CI on its "
            "new HEAD; previous CI cannot transfer.\n"
            "- No automatic close, rebase, force-push, installation, disk writes, "
            "approval, merge or release. Resolve this task in the same issue; "
            "a changed dev alone must not create another issue.\n"
        ),
    }


def repair_keys(issues):
    keys = set()
    for issue in issues:
        if type(issue) is not dict:
            raise ValueError("Malformed issue history")
        user = issue.get("user") or {}
        body = issue.get("body") or ""
        if (issue.get("repository_url") != API or "pull_request" in issue
                or user.get("login") != TRUSTED_TASK_BOT
                or type(user.get("id")) is not int or user["id"] != 41898282
                or not isinstance(body, str)):
            continue
        first, sep, _ = body.partition("\n")
        match = REPAIR_KEY.fullmatch(first)
        if sep and match and issue.get("title") == (
                f"[GASLUX-REPAIR] #{match[1]} stale candidate base"):
            keys.add((int(match[1]), match[2]))
    return keys


def sync_admission_repair(*, dry_run=False):
    """Recompute current Safety result; never consume untrusted report artifacts."""
    if (os.getenv("GITHUB_REPOSITORY") != REPO
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true"
            or os.getenv("GITHUB_EVENT_NAME") not in ("push", "schedule", "workflow_dispatch")):
        raise RuntimeError("Trusted unpaused main event required")
    import gaslux_distro_admission as admission
    candidates = admission.discover_candidates()
    tracked = repair_keys(all_issues())
    for number, (role, head) in candidates.items():
        if (number, head) in tracked:
            continue
        row = admission.inspect(number, role, None, expected_head=head)
        if not repair_eligible(row, number, role, head):
            continue
        payload = repair_issue_payload(number, head, row["base"], role)
        if dry_run:
            return {"status": "repair_dry_run", "pr": number, "head": head}
        # Recompute rather than trust the earlier assessment, then check live
        # dev and dedup again. The ordinary issue API is the only write route.
        fresh = admission.inspect(number, role, None, expected_head=head)
        if not repair_eligible(fresh, number, role, head) or fresh["base"] != row["base"]:
            return {"status": "repair_retry", "pr": number}
        if (number, head) in repair_keys(all_issues()):
            return {"status": "repair_already_queued", "pr": number}
        if api("GET", "/git/ref/heads/dev").get("object", {}).get("sha") != row["base"]:
            return {"status": "repair_retry", "pr": number}
        if admission.discover_candidates().get(number) != (role, head):
            return {"status": "repair_retry", "pr": number}
        created = api("POST", "/issues", payload)
        if (type(created) is not dict or type(created.get("number")) is not int
                or created["number"] <= 0):
            raise RuntimeError("GitHub did not confirm repair issue")
        return {"status": "repair_issue_created", "pr": number, "head": head,
                "issue": created["number"]}
    return {"status": "no_repair_action"}


def discover_missing_implementations(root):
    """Discover explicit stubs and missing APIs demanded by existing tests."""
    root = root.resolve(strict=True)
    result = []
    seen = set()
    def read_python(path):
        if path.resolve(strict=True) != path or path.stat().st_size > 262144:
            raise ValueError("Untrusted or oversized Python source")
        return path.read_bytes()
    for role, (source, test, _) in TASKS.items():
        path = root / source
        if not path.is_file():
            continue
        raw = read_python(path)
        tree = ast.parse(raw, filename=source)
        suite = "auto_tests/tests/" + test
        def record(symbol, line, reason, witness):
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", symbol):
                return
            identity = hashlib.sha256(f"{source}:{symbol}".encode()).hexdigest()
            if identity in seen:
                return
            seen.add(identity)
            result.append({"key": identity, "role": role, "source": source,
                           "test": suite, "symbol": symbol, "line": line,
                           "witness": witness, "source_sha256": hashlib.sha256(raw).hexdigest(),
                           "reason": reason, "code_authorized": False,
                           "installation_authorized": False, "release_eligible": False})
            if len(result) > 64:
                raise ValueError("Unbounded implementation gap inventory")
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = list(node.body)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body.pop(0)
            if len(body) != 1 or not isinstance(body[0], ast.Raise):
                continue
            exc = body[0].exc
            if isinstance(exc, ast.Call):
                exc = exc.func
            if isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
                record(node.name, node.lineno, "EXPLICIT_NOT_IMPLEMENTED", source)
        # Only direct top-level test imports and actual call sites, not comments,
        # speculative model output or attributes of arbitrary objects. Skip
        # modules with dynamic/conditional exports rather than guess absence.
        test_path = root / suite
        if not test_path.is_file():
            continue
        exported = set()
        dynamic = False
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                exported.add(node.name)
                dynamic |= node.name == "__getattr__"
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    dynamic |= alias.name == "*"
                    exported.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        exported.add(target.id)
                    else:
                        dynamic = True
            elif isinstance(node, (ast.If, ast.Try, ast.With, ast.For, ast.While, ast.Match)):
                dynamic = True
        if dynamic:
            continue
        test_tree = ast.parse(read_python(test_path), filename=suite)
        called = {node.func.id for node in ast.walk(test_tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        module = Path(source).stem
        for node in test_tree.body:
            if not isinstance(node, ast.ImportFrom) or node.level or node.module != module:
                continue
            for alias in node.names:
                if alias.name not in exported and (alias.asname or alias.name) in called:
                    record(alias.name, node.lineno, "TEST_REQUIRES_MISSING_API", suite)
    return result


def sync_implementation_gap(root, *, dry_run=False):
    """Route one concrete source gap to the backend; never infer write authority."""
    if (os.getenv("GITHUB_REPOSITORY") != REPO
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch", "push")
            or os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true"):
        raise RuntimeError("Trusted unpaused main event required")
    base = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True, timeout=12).strip()
    if not SHA.fullmatch(base) or api("GET", "/git/ref/heads/dev")["object"]["sha"] != base:
        raise ValueError("Unpinned source discovery")
    candidates = discover_missing_implementations(root)
    def tracked(issues, marker, title):
        return any((i.get("user") or {}).get("id") == 41898282
                   and (i.get("user") or {}).get("login") == TRUSTED_TASK_BOT
                   and i.get("repository_url") == API and i.get("title") == title
                   and str(i.get("body", "")).splitlines()[:1] == [marker]
                   for i in issues)
    issues = all_issues()
    import gaslux_distro_admission as admission
    prs = admission.complete_page(admission.api("GET", "/pulls?state=open&base=dev&per_page=100"))
    for row in candidates:
        marker = f"<!-- GASLUX-IMPLEMENTATION-GAP-V1:{row['key']} -->"
        title = f"[GASLUX-GAP] {row['role']}: implement {row['symbol']}"
        if tracked(issues, marker, title):
            continue
        # Defer if another same-repository candidate changes the actual file.
        overlap = False
        for pr in prs:
            if (pr["head"].get("repo") or {}).get("full_name") != REPO:
                continue
            n = pr["number"]
            if type(n) is not int or not 1 <= n <= 1000000:
                raise ValueError("Malformed PR identity")
            files = admission.complete_page(admission.api("GET", f"/pulls/{n}/files?per_page=100"))
            if any(item.get("filename") == row["source"] or
                   item.get("previous_filename") == row["source"] for item in files):
                overlap = True
                break
        if overlap:
            continue
        payload = {"title": title, "body": (
            marker + "\n\n"
            f"Concrete source gap, assigned backend: {row['role']}.\n"
            f"Exact dev: {base}; source: {row['source']}; "
            f"Witness: {row['witness']}:{row['line']} ({row['reason']}); "
            f"symbol: {row['symbol']}; source SHA256: {row['source_sha256']}.\n"
            f"Regression suite: {row['test']}.\n"
            "Investigate callers and native semantics; reproduce the missing behavior, "
            "define positive and adversarial tests, then propose the smallest isolated implementation. "
            "This discovery does not authorize arbitrary code, protected writers, installation, "
            "merge or release. Preserve independent Safety and backend acceptance.")}
        if dry_run:
            return {"status": "implementation_gap_dry_run", "base": base, **row}
        if (api("GET", "/git/ref/heads/dev")["object"]["sha"] != base
                or tracked(all_issues(), marker, title)):
            return {"status": "implementation_gap_retry"}
        created = api("POST", "/issues", payload)
        if type(created.get("number")) is not int or created["number"] <= 0:
            raise RuntimeError("GitHub did not confirm gap issue")
        return {"status": "implementation_gap_routed", "issue": created["number"], "base": base, **row}
    return {"status": "no_unclaimed_implementation_gap", "discovered": len(candidates)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--with-admission-repair", action="store_true")
    parser.add_argument("--with-implementation-discovery", action="store_true")
    args = parser.parse_args()
    result = sync_admission_repair(dry_run=args.dry_run) if args.with_admission_repair else {
        "status": "no_repair_action"
    }
    if result["status"] == "no_repair_action" and args.with_implementation_discovery:
        result = sync_implementation_gap(args.repo.resolve(strict=True), dry_run=args.dry_run)
    if result["status"] in ("no_repair_action", "no_unclaimed_implementation_gap"):
        result = sync(args.repo.resolve(strict=True), dry_run=args.dry_run)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
