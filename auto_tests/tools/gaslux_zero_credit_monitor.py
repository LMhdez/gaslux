#!/usr/bin/env python3
"""Read-only, model-free Gaslux GitHub progress monitor.

Never mutates a repository or runs third-party code from PRs. Designed for
GitHub Actions standard public runners with a read-only GITHUB_TOKEN.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_REPO = "LMhdez/gaslux"
API_ROOT = "https://api.github.com"
USER_AGENT = "gaslux-zero-credit-monitor/1.0"
MAX_PAGES = 5


def api_get(url: str, token: str) -> Any:
    """Read GitHub API JSON; never forward auth to another host."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com":
        raise ValueError("Refusing non-GitHub API address")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def fetch_paged(url: str, token: str, max_pages: int = MAX_PAGES) -> list[dict]:
    """Bound pagination by page number and repository URL."""
    items: list[dict] = []
    for page in range(1, max_pages + 1):
        separator = "&" if "?" in url else "?"
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != "api.github.com":
            raise ValueError("Unexpected API origin")
        result = api_get(f"{url}{separator}per_page=100&page={page}", token)
        if not isinstance(result, list):
            raise ValueError("Unexpected GitHub API collection")
        items.extend(result)
        if len(result) < 100:
            break
    return items


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def names(pr: dict) -> str:
    return str(pr.get("title", "")).lower()


def lane(pr: dict) -> str:
    """Deterministic triage, never a release or merge authorization."""
    title = names(pr)
    if re.search(r"mint|zorin|libertix|wpf|integrat|core", title):
        return "core"
    if re.search(r"safety|recovery|rollback|gpt|bcd|esp|winre|destination", title):
        return "safety"
    if re.search(r"observer|qemu|guest|collector|vm", title):
        return "observer"
    if re.search(r"cachyos|popos|pop!|bazzite|q4os", title):
        return "backends"
    return "other"


def priority(pr: dict) -> tuple[int, str, int]:
    category = lane(pr)
    base = str((pr.get("base") or {}).get("ref", ""))
    # Rank only as a review order, not a claim of feasibility or readiness.
    category_score = {"core": 0, "safety": 1, "observer": 2, "backends": 3, "other": 4}[category]
    if base == "dev":
        category_score -= 1
    created = str(pr.get("created_at", "9999"))
    return category_score, created, int(pr.get("number", 0))


def snapshot(
    repo: str,
    pulls: list[dict],
    closed: list[dict],
    dev_branch: dict,
    main_branch: dict,
    workflow_runs: dict,
    now: dt.datetime,
) -> dict:
    """Summarize live metadata only, with explicit limits to claims."""
    fresh = now - dt.timedelta(hours=24)
    recent_dev_merges = [
        p for p in closed
        if (p.get("base") or {}).get("ref") == "dev"
        and (merged := parse_time(p.get("merged_at"))) is not None
        and merged >= fresh
    ]
    ranked = sorted(pulls, key=priority)
    lanes: dict[str, int] = {}
    for p in pulls:
        tag = lane(p)
        lanes[tag] = lanes.get(tag, 0) + 1
    candidates = [
        {
            "number": p.get("number"),
            "title": p.get("title"),
            "url": p.get("html_url"),
            "base": (p.get("base") or {}).get("ref"),
            "draft": bool(p.get("draft")),
            "lane": lane(p),
            "updated_at": p.get("updated_at"),
        }
        for p in ranked[:12]
    ]
    runs = workflow_runs.get("workflow_runs", [])
    return {
        "repository": repo,
        "observed_at_utc": now.isoformat().replace("+00:00", "Z"),
        "dev_sha": ((dev_branch.get("commit") or {}).get("sha")),
        "main_sha": ((main_branch.get("commit") or {}).get("sha")),
        "open_prs": len(pulls),
        "draft_prs": sum(bool(p.get("draft")) for p in pulls),
        "open_targeting_dev": sum((p.get("base") or {}).get("ref") == "dev" for p in pulls),
        "open_by_lane_heuristic": lanes,
        "dev_merges_last_24h": len(recent_dev_merges),
        "last_dev_merge_at": max((p.get("merged_at") for p in closed if p.get("merged_at") and (p.get("base") or {}).get("ref") == "dev"), default=None),
        "recent_actions_first_page": {
            "total_seen": len(runs),
            "completed_success": sum(r.get("status") == "completed" and r.get("conclusion") == "success" for r in runs),
            "completed_failure": sum(r.get("status") == "completed" and r.get("conclusion") == "failure" for r in runs),
            "queued_or_running": sum(r.get("status") in {"queued", "in_progress", "waiting", "pending"} for r in runs),
        },
        "review_queue_not_merge_approval": candidates,
        "full_native_installation_verified": "NOT_ASSESSED_BY_THIS_MONITOR",
        "ai_api_calls": 0,
        "writes_to_github": 0,
        "warnings": [
            "PR counts/CI statuses are metadata, not proof of Linux installation, Windows boot or rollback.",
            "Some Actions may be skipped or use synthetic fixtures even when the run is green.",
            "This monitor does not invoke ChatGPT, Copilot, Codex, or any paid API.",
            "Review queue is a heuristic, never permission to merge or mutate a disk.",
        ],
    }


def md_report(data: dict) -> str:
    entries = [
        "# Gaslux — monitor automático sem IA",
        "",
        f"**Observado:** {data['observed_at_utc']}  ",
        f"**Repositório:** {data['repository']}  ",
        f"**dev:** {data['dev_sha']}  ",
        f"**main:** {data['main_sha']}",
        "",
        "| Métrica | Valor |",
        "| --- | ---: |",
        f"| PRs abertas | {data['open_prs']} |",
        f"| PRs draft | {data['draft_prs']} |",
        f"| PRs diretamente contra dev | {data['open_targeting_dev']} |",
        f"| Merges em dev (24 h) | {data['dev_merges_last_24h']} |",
        "",
        "## Fila de revisão (não significa aprovação)",
        "",
    ]
    for candidate in data["review_queue_not_merge_approval"]:
        title = str(candidate["title"] or "").replace("|", "\\|").replace("\n", " ")
        url = candidate["url"]
        number = candidate["number"]
        entries.append(f"- [#{number}]({url}) — {title} ({candidate['lane']}; base {candidate['base']})")
    entries.extend(
        [
            "",
            "## Limites",
            "",
            "**Este monitor não prova instalações, não escreve no GitHub e não chama modelos de IA.**",
            "Não executa merges nem ações destrutivas. A lista é apenas uma fila para inspeção.",
            "",
            "## Prompt de supervisão no ChatGPT Plus (manual)",
            "",
            "Analisa este relatório e as PRs prioritárias em LMhdez/gaslux. "
            "Valida HEAD, CI e evidência real. Propõe uma única tarefa que acelere uma "
            "instalação e recuperação Mint/Zorin. Não abras novas PRs redundantes; "
            "não confundas CI verde com instalação comprovada.",
        ]
    )
    return "\n".join(entries) + "\n"


def collect(repo: str, token: str, now: dt.datetime) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Invalid repo")
    prefix = f"{API_ROOT}/repos/{repo}"
    pulls = fetch_paged(f"{prefix}/pulls?state=open", token)
    closed = fetch_paged(f"{prefix}/pulls?state=closed&sort=updated&direction=desc", token, max_pages=1)
    dev_branch = api_get(f"{prefix}/branches/dev", token)
    main_branch = api_get(f"{prefix}/branches/main", token)
    workflow_runs = api_get(f"{prefix}/actions/runs?per_page=100", token)
    return snapshot(repo, pulls, closed, dev_branch, main_branch, workflow_runs, now)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--output-dir", default="artifacts/gaslux-monitor")
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("ERROR: GITHUB_TOKEN is required (read-only).", file=sys.stderr)
        return 2
    try:
        data = collect(args.repo, token, dt.datetime.now(dt.timezone.utc))
    except (ValueError, urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        print(f"ERROR: Github data unavailable: {exc}", file=sys.stderr)
        return 1
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report = md_report(data)
    (output / "snapshot.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output / "report.md").write_text(report, encoding="utf-8")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(report)
    print(f"Gaslux monitor: {data['open_prs']} PRs open, "
          f"{data['dev_merges_last_24h']} dev merges/24h; no AI calls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
