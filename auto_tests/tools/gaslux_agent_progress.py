#!/usr/bin/env python3
"""Read-only checkpoint dashboard: Actions job evidence, not Linux/Windows proof.

Runs only trusted main code; no model-produced source is imported or executed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import urllib.request

REPO = "LMhdez/gaslux"
API = "https://api.github.com/repos/" + REPO
WORKFLOWS = {
    "gaslux-agent-clock.yml": ("Curated keyboard agent",
        ("supervisor", "backend_developer", "safety_review",
         "windows_wpf_acceptance", "integrator_publisher")),
    "gaslux-agent-feature-factory.yml": ("Six-distro proposals",
        ("select", "model", "safety", "publish_draft")),
    "gaslux-agent-integrator.yml": ("Dev integrator",
        ("select", "windows_acceptance", "trusted_integrator")),
    "gaslux-agent-lifecycle-research.yml": ("Read-only lifecycle research",
        ("backend_research", "mint_live_boot")),
}
EVENTS = {"schedule", "workflow_dispatch", "push", "workflow_run"}
FAILURES = {"failure", "cancelled", "timed_out", "startup_failure", "action_required"}
SHA = re.compile(r"^[0-9a-f]{40}$")


def job_state(jobs: list[dict], name: str) -> str:
    """Never credit skipped, unknown or absent jobs as checkpoints."""
    found = [j for j in jobs if j.get("name") == name
             or str(j.get("name", "")).startswith(name + " / ")
             or str(j.get("name", "")).startswith(name + " (")]
    if not found:
        return "unobserved"
    results = []
    for j in found:
        status, conclusion = j.get("status"), j.get("conclusion")
        if conclusion in FAILURES:
            results.append("blocked")
        elif status == "completed" and conclusion == "success":
            results.append("passed")
        elif status == "completed" and conclusion == "skipped":
            results.append("skipped")
        elif status in ("in_progress", "queued", "waiting", "pending", "requested"):
            results.append("running")
        else:
            results.append("unobserved")
    if "blocked" in results:
        return "blocked"
    if "running" in results:
        return "running"
    if "unobserved" in results:
        return "unobserved"
    if all(v == "skipped" for v in results):
        return "skipped"
    return "passed" if all(v == "passed" for v in results) else "unobserved"


def pipeline(workflow: str, runs: list[dict], jobs: list[dict]) -> dict:
    title, stages = WORKFLOWS[workflow]
    production = [r for r in runs if r.get("event") in EVENTS]
    production.sort(key=lambda r: (str(r.get("created_at", "")), int(r.get("id", 0))),
                    reverse=True)
    if not production:
        return {"workflow": workflow, "title": title, "state": "not_observed",
                "passed": 0, "total": len(stages),
                "stages": {s: "unobserved" for s in stages},
                "run_id": None, "run_url": None, "recent_failures": 0, "recent_runs": 0}
    r = production[0]
    run_id = r.get("id")
    if type(run_id) is not int or run_id <= 0 or not SHA.fullmatch(str(r.get("head_sha", ""))):
        raise ValueError("Untrusted workflow run identity")
    states = {s: job_state(jobs, s) for s in stages}
    passed = sum(v == "passed" for v in states.values())
    if r.get("conclusion") in FAILURES or "blocked" in states.values():
        overall = "blocked"
    elif r.get("status") in ("in_progress", "queued", "requested", "waiting", "pending"):
        overall = "running"
    elif states[stages[0]] == "passed" and all(
            states[s] == "skipped" for s in stages[1:]):
        overall = "idle"
    elif r.get("status") == "completed" and r.get("conclusion") == "success":
        overall = "passed" if passed == len(stages) else "partial"
    else:
        overall = "unobserved"
    recent = production[:8]
    return {"workflow": workflow, "title": title, "state": overall,
            "passed": passed, "total": len(stages), "stages": states,
            "source_sha": r["head_sha"], "run_id": run_id,
            "run_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
            "recent_failures": sum(item.get("conclusion") in FAILURES for item in recent),
            "recent_runs": len(recent)}


def release_claims(source: Path) -> dict:
    """Schema-level goal count ONLY; no claim becomes independently attested here."""
    goal = json.loads((source / "docs/autonomy/goal.json").read_text(encoding="utf-8"))
    evidence = json.loads((source / "docs/autonomy/evidence.json").read_text(encoding="utf-8"))
    if goal.get("schema_version") != 1 or evidence.get("schema_version") != 1:
        raise ValueError("Invalid goal/evidence schema")
    slots = {(b["id"], p, g) for b in goal["backends"]
             for p in b["platforms"] for g in goal["gates"]}
    if not slots or len(slots) != sum(len(b["platforms"]) * len(goal["gates"])
                                     for b in goal["backends"]):
        raise ValueError("Duplicate or empty acceptance slots")
    recorded = set()
    for row in evidence.get("records", []):
        if not isinstance(row, dict):
            raise ValueError("Malformed evidence record")
        key = (row.get("backend"), row.get("platform"), row.get("gate"))
        if key not in slots or key in recorded:
            raise ValueError("Unknown or duplicate evidence record")
        recorded.add(key)
    return {"required": len(slots), "registered_claims": len(recorded),
            "externally_attested": 0, "release_eligible": False,
            "assurance": "GitHub citations in source registry NOT independently verified"}


def progress_bar(passed: int, total: int) -> str:
    if total <= 0 or not 0 <= passed <= total:
        raise ValueError("Bad checkpoint progress")
    n = 12 * passed // total
    return "█" * n + "░" * (12 - n)


def render(report: dict) -> str:
    release = report["release"]
    lines = ["## GASLUX — desenvolvimento autónomo: checkpoints", "",
             f"**Interruptor:** {'PAUSED' if report['paused'] else 'ACTIVE (roles limited)'}  ",
             f"**Aceitação real do produto:** {release['externally_attested']}/{release['required']} "
             f"atestados externamente; {release['registered_claims']} registos declarados ainda não "
             "validados por esta ferramenta.  ",
             "**Release:** BLOQUEADO — CI verde, PR Draft ou código gerado não provam instalação.", "",
             "| Fluxo | Checkpoints | Estado | Falhas / últimas 8 | Execução |",
             "|---|---|---|---:|---|"]
    for p in report["pipelines"]:
        link = f"[#{p['run_id']}]({p['run_url']})" if p["run_id"] else "Sem execução"
        lines.append(f"| {p['title']} | \`{progress_bar(p['passed'], p['total'])}\` "
                     f"{p['passed']}/{p['total']} | **{p['state'].upper()}** | "
                     f"{p['recent_failures']}/{p['recent_runs']} | {link} |")
    lines.extend(["", "**Checkpoints da última execução**:", ""])
    for p in report["pipelines"]:
        states = " · ".join(f"\`{name}={status}\`" for name, status in p["stages"].items())
        lines.append(f"- **{p['title']}**: {states}")
    lines.extend(["", "**Limite:** estas barras medem fases comprovadas por jobs Actions, "
                  "não a percentagem de funcionalidades concluídas. Skipped/idle/unknown "
                  "não provam execução. O painel tem apenas permissões de leitura.", "",
                  "**Pausa de emergência:** definir a variável de Actions "
                  "\`GASLUX_AUTONOMY_PAUSED=true\` e cancelar também as execuções já iniciadas.", ""])
    return "\n".join(lines)


def fetch(token: str, route: str) -> dict:
    if not token or not route.startswith("/actions/") or ".." in route:
        raise ValueError("Read-only API route or token missing")
    request = urllib.request.Request(API + route, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def collect(token: str, source: Path, paused: bool) -> dict:
    result = []
    for wf in WORKFLOWS:
        payload = fetch(token, f"/actions/workflows/{wf}/runs?per_page=12")
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise ValueError("Actions run list unavailable")
        actual = [r for r in runs if r.get("event") in EVENTS]
        actual.sort(key=lambda r: (str(r.get("created_at", "")), int(r.get("id", 0))),
                    reverse=True)
        jobs = []
        if actual:
            run_id = actual[0].get("id")
            if type(run_id) is not int or run_id <= 0:
                raise ValueError("Bad Actions run id")
            job_payload = fetch(token, f"/actions/runs/{run_id}/jobs?per_page=100")
            jobs = job_payload.get("jobs")
            if (not isinstance(jobs, list) or
                    job_payload.get("total_count", len(jobs)) > 100):
                raise ValueError("Incomplete latest-run job results")
        result.append(pipeline(wf, runs, jobs))
    return {"schema_version": 1, "project": "gaslux",
            "main_source_sha": os.environ.get("GITHUB_SHA"),
            "dev_source_sha": os.environ.get("GASLUX_DEV_SHA"),
            "paused": paused, "release": release_claims(source),
            "pipelines": result, "write_or_merge_authority": False,
            "evidence_level": "ACTIONS_JOB_STAGES_ONLY"}


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--source", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--summary", type=Path, required=True)
    args = cli.parse_args()
    report = collect(os.getenv("GH_TOKEN", ""), args.source,
                     os.getenv("GASLUX_AUTONOMY_PAUSED", "").strip().lower() == "true")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    with args.summary.open("a", encoding="utf-8") as stream:
        stream.write(render(report))
    print(json.dumps({"status": "CHECKPOINTS_REPORTED",
                      "pipelines": len(report["pipelines"]), "release_eligible": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
