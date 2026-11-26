#!/usr/bin/env python3
"""Explicit paused, disposable same-repository confinement proof. Never merges."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gaslux_lab_review_probe as lab

A = lab.A
PUBLISHER = 360620437
RULE = 28200894
BODY = "INERT paused Publisher confinement proof. No product or merge authorization."


def need(ok, message):
    if not ok:
        raise ValueError(message)


def names():
    run = os.getenv("GITHUB_RUN_ID", "")
    attempt = os.getenv("GITHUB_RUN_ATTEMPT", "")
    need(re.fullmatch(r"[1-9][0-9]{0,15}", run)
         and re.fullmatch(r"[1-9][0-9]{0,3}", attempt), "Invalid run identity")
    prefix = f"lab/gaslux-confinement-{run}-{attempt}"
    return prefix + "-base", prefix + "-candidate"


def context():
    need(os.getenv("GITHUB_EVENT_NAME") == "workflow_dispatch"
         and os.getenv("GASLUX_CONFINEMENT_PROBE") == "true"
         and os.getenv("GASLUX_AUTONOMY_PAUSED") == "true"
         and os.getenv("GASLUX_PRODUCTION_MERGE_ENABLED") == "false"
         and os.getenv("GASLUX_APP_STATUS_GATES_ENABLED") == "false",
         "Explicit paused no-production dispatch required")
    lab.context()
    need(lab.candidate()["state"] == "open", "Frozen inert fixture unavailable")
    repo = A.api("GET", "")
    need(repo.get("id") == A.REPOSITORY_ID and repo.get("full_name") == A.REPO
         and repo.get("fork") is False, "Wrong repository")
    policy = A.api("GET", f"/rulesets/{RULE}?includes_parents=false")
    need(policy.get("id") == RULE and policy.get("source") == A.REPO
         and policy.get("source_type") == "Repository" and policy.get("target") == "branch"
         and policy.get("enforcement") == "active"
         and policy.get("current_user_can_bypass") == "never"
         and policy.get("conditions") == {"ref_name": {"include": ["~ALL"], "exclude": ["refs/heads/dev"]}}
         and policy.get("rules") in ([{"type": "update"}],
                                   [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}]),
         "Exact confinement rule unavailable or bypassable")
    return lab.ref("main"), lab.ref("dev")


def push_new(root, name, sha):
    need(name in names() and sha == dict(zip(names(), (lab.BASE, lab.HEAD)))[name],
         "Only exact inert refs allowed")
    ref = "refs/heads/" + name
    result = subprocess.run(["git", "-C", str(root), "push", "--porcelain",
                             f"--force-with-lease={ref}:", "origin", f"{sha}:{ref}"],
                            check=True, capture_output=True, text=True, timeout=45)
    statuses = [line.split("\t") for line in result.stdout.splitlines() if "\t" in line]
    need(len(statuses) == 1 and len(statuses[0]) == 3 and statuses[0][0] == "*"
         and statuses[0][1].split(":")[-1] == ref and statuses[0][2] == "[new branch]",
         "Not an exclusive new ref creation")
    need(lab.ref(name) == sha, "Created ref mismatch")


def exact_pr(number):
    need(type(number) is int and 0 < number <= 1000000 and number != lab.NUMBER,
         "Unexpected disposable PR number")
    base, head = names()
    pr = A.api("GET", f"/pulls/{number}")
    need(pr.get("number") == number and pr.get("state") == "open"
         and pr.get("draft") is True and pr.get("merged") is False
         and pr.get("body") == BODY
         and pr.get("user", {}).get("id") == PUBLISHER
         and pr.get("user", {}).get("type") == "Bot"
         and pr.get("user", {}).get("login") == "gaslux-autonomous-publisher[bot]"
         and all(pr.get(k, {}).get("ref") == ref and pr[k].get("sha") == sha
                 and (pr[k].get("repo") or {}).get("full_name") == A.REPO
                 for k, ref, sha in (("base", base, lab.BASE), ("head", head, lab.HEAD)))
         and lab.ref(base) == lab.BASE and lab.ref(head) == lab.HEAD,
         "Disposable PR drift")
    files = A.complete_page(A.api("GET", f"/pulls/{number}/files?per_page=100"))
    need(len(files) == 1 and files[0].get("filename") == lab.FILE
         and files[0].get("sha") == lab.BLOB and files[0].get("status") == "added",
         "Unexpected inert diff")
    return pr


def publish(root):
    before = context()
    need(os.getenv("GASLUX_MINTED_APP_SLUG") == "gaslux-autonomous-publisher",
         "Wrong Publisher credential")
    need(subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                                 text=True, timeout=15).strip() == lab.HEAD,
         "Wrong inert checkout")
    need(subprocess.check_output(["git", "-C", str(root), "remote", "get-url", "origin"],
                                 text=True, timeout=15).strip() == "https://github.com/" + A.REPO,
         "Unexpected Git destination")
    subprocess.run(["gh", "auth", "setup-git"], check=True, timeout=20)
    for ref, sha in zip(names(), (lab.BASE, lab.HEAD)):
        context()
        push_new(root, ref, sha)
    base, head = names()
    need(context() == before, "Protected refs drifted")
    row = A.api("POST", "/pulls", {"title": "[INERT] Publisher confinement probe",
                "body": BODY, "head": head, "base": base, "draft": True})
    number = row["number"]
    exact_pr(number)
    need(context() == before, "Protected refs drifted after publication")
    return {"pr": number, "publisher_creation_verified": True, "merge_authorized": False}


def deny_and_close(number):
    before = context()
    exact_pr(number)
    base, head = names()
    # A conflict-free fast-forward on our own disposable ref must be rejected
    # under the actual merge token. No merge endpoint is used, even on failure.
    try:
        A.api("PATCH", "/git/refs/heads/" + base, {"sha": lab.HEAD, "force": False})
    except RuntimeError as exc:
        need(str(exc) in ("GitHub PATCH failed: HTTP 403", "GitHub PATCH failed: HTTP 422"),
             "Unexpected denial response")
        denial = int(str(exc).rsplit(" ", 1)[1])
    else:
        raise RuntimeError("Confinement failed: disposable ref update was accepted")
    exact_pr(number)
    need(context() == before, "Protected refs drifted")
    A.api("PATCH", f"/pulls/{number}", {"state": "closed"})
    closed = A.api("GET", f"/pulls/{number}")
    need(closed.get("state") == "closed" and closed.get("merged") is False
         and closed.get("number") == number and closed.get("body") == BODY
         and lab.ref(base) == lab.BASE and lab.ref(head) == lab.HEAD
         and context() == before, "Closure or protected ref mismatch")
    return {"schema": "gaslux-paused-publisher-confinement-v1", "pr": number,
            "publisher_creation_verified": True, "integrator_ref_update_denied": True,
            "http": denial, "closed_without_merge": True, "protected_refs_unchanged": True,
            "merge_authorized": False, "release_eligible": False}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("publish", "deny"))
    p.add_argument("--repo", type=Path)
    p.add_argument("--pr", type=int)
    args = p.parse_args()
    report = publish(args.repo) if args.mode == "publish" else deny_and_close(args.pr)
    print(json.dumps(report, sort_keys=True))
