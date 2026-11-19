#!/usr/bin/env python3
"""Independent read-only proof of archived Gaslux Git source histories."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

ARCHIVE = "archive/gaslux-experiments-preserved-20261119"
ROOT = "5be372eb1bccbe07b2c2db2f4616291345e1df0a"
ROOT_TREE = "663396d7205b73dae73b9763cf928d6bf515bc3f"
EXPECTED_SOURCES = 102


def git(*argv: str, check: bool = True) -> str:
    p = subprocess.run(["git", *argv], check=check, capture_output=True,
                       text=True, timeout=120)
    return p.stdout.strip()


def source_message(body: str) -> tuple[str, str]:
    if ("Archive-only: no experimental code included in working tree" not in body
            or "Production-merge: false" not in body):
        raise ValueError("archive commit lacks explicit no-production guarantees")
    a = re.search(r"(?m)^Source-ref: refs/heads/([^\r\n]+)$", body)
    b = re.search(r"(?m)^Source-sha: ([0-9a-f]{40})$", body)
    if a is None or b is None:
        raise ValueError("missing or malformed source ref and sha")
    if a.group(1).startswith(("archive/", "automation/")):
        raise ValueError("archive must not ingest control or archive refs")
    return a.group(1), b.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    tip = git("rev-parse", "refs/remotes/origin/" + ARCHIVE)
    root_tree = git("rev-parse", ROOT + "^{tree}")
    if root_tree != ROOT_TREE:
        raise RuntimeError("original archive snapshot differs from known tree")
    subprocess.run(["git", "merge-base", "--is-ancestor", ROOT, tip],
                   check=True, timeout=60)
    commits = git("rev-list", "--first-parent", ROOT + ".." + tip).splitlines()
    if len(commits) != EXPECTED_SOURCES:
        raise RuntimeError(f"expected {EXPECTED_SOURCES} archived sources; got {len(commits)}")
    originals = {}
    for i, node in enumerate(commits):
        parts = git("rev-list", "--parents", "-n", "1", node).split()
        if len(parts) != 3 or parts[0] != node:
            raise RuntimeError("archive not a two-parent commit: " + node)
        first_parent = commits[i + 1] if i + 1 < len(commits) else ROOT
        if parts[1] != first_parent:
            raise RuntimeError("archive first-parent lineage broken: " + node)
        ref, original_sha = source_message(git("show", "-s", "--format=%B", node))
        if (ref in originals or parts[2] != original_sha
                or git("rev-parse", node + "^{tree}") != ROOT_TREE):
            raise RuntimeError("duplicate, altered source or non-immutable tree: " + ref)
        subprocess.run(["git", "merge-base", "--is-ancestor", original_sha, tip],
                       check=True, timeout=60)
        ref_exists = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet",
             "refs/remotes/origin/" + ref],
            check=False, timeout=60,
        ).returncode
        if ref_exists != 1:
            raise RuntimeError("archived source ref unexpectedly remains: " + ref)
        originals[ref] = {"source_sha": original_sha, "archive_commit": node}
    if git("rev-parse", tip + "^{tree}") != ROOT_TREE:
        raise RuntimeError("archive HEAD changed executable working tree")
    report = {
        "archive": ARCHIVE,
        "root": ROOT,
        "archive_head": tip,
        "archive_tree_unchanged": True,
        "source_history_commit_count": len(originals),
        "all_original_shas_ancestors": True,
        "all_source_refs_removed": True,
        "installer_code_integrated": False,
        "stable_release_verified": False,
        "sources": originals,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("ARCHIVE_DAG_VERIFIED=" + str(len(originals)), flush=True)
    print("ARCHIVE_TREE_UNCHANGED=true", flush=True)
    print("NO_PRODUCTION_CODE_MERGED=true", flush=True)


if __name__ == "__main__":
    main()
