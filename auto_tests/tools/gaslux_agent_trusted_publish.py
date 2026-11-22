#!/usr/bin/env python3
"""Trusted default-branch Gaslux agent Safety/publisher for a tiny code allowlist.

Executes from default main, NOT from the model-controlled checkout.
Nothing supplied by the LLM is executed here. Only exact vetted Windows
keyboard mapping additions can become Draft PRs. Physical disk/boot/recovery
or main source edits are denied.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

REPO = "LMhdez/gaslux"
API = f"https://api.github.com/repos/{REPO}"
SOURCE = "Installation/WindowsKeyboardLayout.cs"
ARTIFACT = Path("evidence/autonomous-agent")
MODEL = "qwen3.5:9b"
DIGEST = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
TASKS = {
    "MINT-PT-KEYBOARD-01": ("mint", "00000809", "00000816", "pt"),
    "ZORIN-BR-KEYBOARD-01": ("zorin", "0000040C", "00000416", "br"),
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate(report: dict, original: bytes, candidate: bytes) -> tuple[str, str]:
    task_id = report.get("task_id")
    if task_id not in TASKS:
        raise ValueError("Unsupported product mission")
    role, anchor, identifier, layout = TASKS[task_id]
    if (report.get("role") != role or report.get("target") != SOURCE
        or report.get("task_identifier") != identifier or report.get("expected_layout") != layout
        or report.get("model") != MODEL or report.get("model_digest") != DIGEST
        or report.get("status") != "candidate_green" or report.get("candidate_valid") is not True
        or not SHA40.fullmatch(str(report.get("base_commit", "")))
        or not SHA64.fullmatch(str(report.get("source_sha256", "")))
        or not SHA64.fullmatch(str(report.get("candidate_sha256", "")))):
        raise ValueError("Missing or mismatched model/source/test evidence")
    attempts = report.get("attempts", [])
    if not isinstance(attempts, list) or len(attempts) not in (1, 2) or attempts[-1].get("passed") is not True:
        raise ValueError("No independently checkable model attempt")
    if report["source_sha256"] != sha(original) or report["candidate_sha256"] != sha(candidate):
        raise ValueError("Source or candidate SHA-256 mismatch")
    old, new = original.decode("utf-8"), candidate.decode("utf-8")
    if "\r" in old or "\r" in new or len(new) > 20_000:
        raise ValueError("Unexpected C# line endings or size")
    if '"' + identifier + '"' in old or old.count('"' + anchor + '"') != 1:
        raise ValueError("Feature completed or ambiguous source baseline")
    matches = list(re.finditer(
        r'^(\s*\{\s*"' + anchor + r'"\s*,[^\r\n]*\n)', old, re.MULTILINE
    ))
    if len(matches) != 1:
        raise ValueError("Exact safe insertion anchor missing")
    indent = re.match(r"^\s*", matches[0].group(1)).group(0)
    new_line = indent + '{ "' + identifier + '", Mapping("' + layout + '") },\n'
    wanted = old[:matches[0].end()] + new_line + old[matches[0].end():]
    if new != wanted or len(new.splitlines()) != len(old.splitlines()) + 1:
        raise ValueError("Model code changes anything outside the one approved line")
    return task_id, role


def request(method: str, route: str, body: dict | None = None, *, missing_ok=False):
    if (not route.startswith("/") or "://" in route or
        (".." in route and not re.fullmatch(r"/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}", route))):
        raise ValueError("Untrusted REST path")
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise RuntimeError("GitHub token required")
    req = urllib.request.Request(API + route, data=None if body is None else json.dumps(body).encode(),
        method=method, headers={"Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if body is not None else {})})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = resp.read()
            return json.loads(data) if data else {}
    except urllib.error.HTTPError as exc:
        if missing_ok and exc.code == 404:
            return None
        raise RuntimeError(f"GitHub {method} {route}: HTTP {exc.code}") from exc


def admit_nonproduct_dev_advance(old: str, current: str) -> None:
    """Only read-only/docs/workflow file changes may advance dev without rebuilding.

    The candidate's exact C# source bytes must ALSO remain identical; all
    project/solution/build/installer/recovery files are outside this allowlist.
    """
    if not SHA40.fullmatch(old) or not SHA40.fullmatch(current) or old == current:
        raise ValueError("Untrusted or empty dev advance")
    changes = request("GET", f"/compare/{old}...{current}")
    files = changes.get("files")
    if (changes.get("status") != "ahead" or changes.get("behind_by") != 0
        or not isinstance(changes.get("ahead_by"), int)
        or not 1 <= changes["ahead_by"] <= 64
        or not isinstance(files, list) or not 1 <= len(files) <= 60
        or changes.get("total_commits", 65) > 64):
        raise RuntimeError("dev history moved in an unverified direction or volume")
    for entry in files:
        name, status = entry.get("filename", ""), entry.get("status", "")
        safe = (name.startswith("docs/")
                or name.startswith("auto_tests/")
                or name.startswith(".github/workflows/"))
        if (not safe or status not in ("added", "modified", "removed")
            or name.startswith("auto_tests/tools/gaslux_agent_")
            or name.startswith("auto_tests/tests/test_gaslux_agent_")
            or name.startswith(".github/workflows/gaslux-agent-")):
            raise RuntimeError("dev changed a product or agent-sensitive path")
    print(f"TRUSTED_NONPRODUCT_DEV_ADVANCE: {old} -> {current}; "
          f"{len(files)} read-only/docs paths")


def verify_evidence() -> tuple[dict, bytes, str, str]:
    report = json.loads((ARTIFACT / "report.json").read_text())
    candidate = (ARTIFACT / "candidate.cs").read_bytes()
    if report.get("status") != "candidate_green":
        raise ValueError("No passed model-built product feature")
    base = report.get("base_commit", "")
    if not SHA40.fullmatch(str(base)):
        raise ValueError("Invalid source commit")
    ref = request("GET", "/git/ref/heads/dev")
    current = ref["object"]["sha"]
    if not SHA40.fullmatch(str(current)):
        raise RuntimeError("Current dev ref is not a SHA")
    blob = request("GET", f"/contents/{SOURCE}?ref={base}")
    original = base64.b64decode("".join(blob["content"].split()), validate=True)
    task_id, role = validate(report, original, candidate)
    if current != base:
        admit_nonproduct_dev_advance(base, current)
        latest_source = request("GET", f"/contents/{SOURCE}?ref={current}")
        current_raw = base64.b64decode(
            "".join(latest_source["content"].split()), validate=True
        )
        if sha(current_raw) != sha(original):
            raise RuntimeError("C# source changed since model/Windows acceptance")
    latest = request("GET", "/git/ref/heads/dev")
    if latest["object"]["sha"] != current:
        raise RuntimeError("dev moved during validation")
    verified = dict(report)
    verified["effective_base_commit"] = current
    return verified, candidate, task_id, role


def publish() -> None:
    if (os.getenv("GITHUB_REPOSITORY") != REPO
        or os.getenv("GITHUB_EVENT_NAME") not in ("schedule", "workflow_dispatch", "push")
        or os.getenv("GITHUB_REF") != "refs/heads/main"):
        raise RuntimeError("Publishing only permitted from trusted main scheduler")
    report, candidate, task, role = verify_evidence()
    base = report["effective_base_commit"]
    branch = f"bot/gaslux-{role}-keyboard-{base[:12]}"
    if request("GET", f"/git/ref/heads/{branch}", missing_ok=True):
        print("Same-base model candidate branch exists; duplicate attempt blocked")
        return
    source = request("GET", f"/contents/{SOURCE}?ref={base}")
    fetched_raw = base64.b64decode("".join(source["content"].split()), validate=True)
    if sha(fetched_raw) != report["source_sha256"]:
        raise RuntimeError("Latest dev C# source differs from reviewed candidate source")
    ref = request("GET", "/git/ref/heads/dev")
    if ref["object"]["sha"] != base:
        raise RuntimeError("dev changed immediately before commit")
    request("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": base})
    created_commit = None
    try:
        result = request("PUT", f"/contents/{SOURCE}", {
            "message": f"feat(keyboard): model-authored {role} Windows keyboard mapping",
            "content": base64.b64encode(candidate).decode(),
            "sha": source["sha"], "branch": branch,
        })
        created_commit = result.get("commit", {}).get("sha")
        if not SHA40.fullmatch(str(created_commit)):
            raise RuntimeError("No committed candidate SHA returned")
        pr = request("POST", "/pulls", {
            "head": branch, "base": "dev", "draft": True,
            "title": f"feat(keyboard): {task} — local AI proposal",
            "body": (
                f"Curated, real missing product feature: {task}. "
                f"Implementation by {MODEL} on an unprivileged GitHub runner. "
                f"Reviewed source dev: {report['base_commit']}; current dev: {base}. Exactly one mapping line added to "
                f"{SOURCE}; publisher verified SHA-256 and the one-line change. "
                "Windows WPF build, full PR CI and independent Safety assessment "
                "are still required before merge. Draft only; no installer/boot/"
                "rollback evidence or automatic release/physical disk authority."
            ),
        })
        print("AUTONOMOUS_DRAFT_PR_CREATED:", pr["html_url"])
    except Exception:
        try:
            current = request("GET", f"/git/ref/heads/{branch}", missing_ok=True)
            if current and created_commit and current["object"]["sha"] == created_commit:
                request("DELETE", f"/git/refs/heads/{branch}")
                print("Owned orphan proposal ref removed")
        except Exception as exc:
            print("Manual bot-ref inspection needed:", type(exc).__name__)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["verify", "publish"])
    args = parser.parse_args()
    if args.action == "verify":
        report, _, task, role = verify_evidence()
        print(json.dumps({"safety_admissible_for_draft": True, "task": task, "role": role,
                          "base": report["base_commit"], "merge_authorized": False}))
    else:
        publish()


if __name__ == "__main__":
    main()
