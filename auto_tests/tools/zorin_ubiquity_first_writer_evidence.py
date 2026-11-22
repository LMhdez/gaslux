#!/usr/bin/env python3
"""Source-derived call/effect candidates for SHA-pinned Zorin 18.1 Ubiquity.

Static analysis only. No source code is imported, executed or archived.
The provenance, mounting and source-regularity gates come from SOURCE-01.
The result NEVER attests runtime reachability, first write or a dry-run.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys

from zorin_ubiquity_source_coverage import (
    CORE_SOURCES,
    SourceCoverageDenied,
    exact_regular_bytes,
    inspect_authenticated_iso,
    open_pinned_archive,
    source_index,
)

MAX_LSTAT_STDOUT = 8192
MAX_CALLS_PER_SOURCE = 4096
MAX_ARG_LENGTH = 120
WATCH = re.compile(
    r"(?i)(?:partman|parted|select_disk|write_line|read_line|"
    r"write_part_entry|remove_part_entry|mkdir_part_entry|"
    r"commit|filesystem|format|mount|resize|grub|efiboot|nvram|"
    r"preseed|subprocess|popen|os\.system|\.write|\.flush|"
    r"execute|run_command|wipefs|sfdisk|mkfs|bootdev)"
)
BODIES = tuple(p for p in CORE_SOURCES if not p.endswith(("/commit.sh", "/resize.sh")))
UNATTESTED_SHELL = ("lib/partman/lib/commit.sh", "lib/partman/lib/resize.sh")
MUTABLE_GATES = (
    "firstPersistentWriteVerified",
    "precommitNonMutatingVerified",
    "completeCallGraphVerified",
    "allEffectsAuthenticated",
    "runtimeCallPathVerified",
    "diskWritesAuthorized",
)


def deny(condition: bool, code: str) -> None:
    if not condition:
        raise SourceCoverageDenied(code)


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return call_name(node.value) + "." + node.attr
    return "<dynamic>"


def arg_repr(node: ast.AST) -> str:
    value = ast.unparse(node)
    if len(value) > MAX_ARG_LENGTH:
        return value[: MAX_ARG_LENGTH - 3] + "..."
    return value


def candidate_calls(data: bytes, path: str) -> dict:
    """Collect static Python callsites and invocation arguments without executing."""
    try:
        tree = ast.parse(data.decode("utf-8", "strict"), filename=path)
    except (UnicodeError, SyntaxError) as exc:
        raise SourceCoverageDenied("E_UNPARSABLE_AUTHENTICATED_PYTHON") from exc
    result: list[dict] = []
    scopes: list[str] = []
    all_calls = 0

    class Scan(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            scopes.append(node.name)
            self.generic_visit(node)
            scopes.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            scopes.append(node.name)
            self.generic_visit(node)
            scopes.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            scopes.append(node.name)
            self.generic_visit(node)
            scopes.pop()

        def visit_Call(self, node: ast.Call) -> None:
            nonlocal all_calls
            all_calls += 1
            name = call_name(node.func)
            caller = ".".join(scopes) if scopes else "<module>"
            if WATCH.search(name) or (
                path.endswith("parted_server.py")
                or caller.endswith(("PartmanCommit.run", "GrubInstaller.run"))
            ):
                result.append(
                    {
                        "caller": caller,
                        "callee": name,
                        "line": node.lineno,
                        "argumentsStaticExpression": [arg_repr(x) for x in node.args[:4]],
                        "keywords": [x.arg or "**dynamic" for x in node.keywords],
                        "status": "STATIC_CALLSITE_NOT_EXECUTION",
                    }
                )
            self.generic_visit(node)

    Scan().visit(tree)
    deny(
        len(result) <= MAX_CALLS_PER_SOURCE,
        "E_AST_CALLSITE_COVERAGE_TRUNCATED",
    )
    return {
        "sourcePath": path,
        "method": "PYTHON_AST",
        "totalCallsParsed": all_calls,
        "selectedCalls": result,
        "selectedCallCount": len(result),
        "selectedCallsTruncated": False,
        "runtimeReachabilityProven": False,
        "persistentWriteProven": False,
    }


def lstat_member(rootfs: Path, path: str) -> dict:
    """Equivalent read-only stat of a SquashFS inode; NEVER follow its symlink."""
    deny(path in UNATTESTED_SHELL, "E_UNEXPECTED_PARTMAN_PATH")
    try:
        proc = subprocess.run(
            ["unsquashfs", "-ll", "-processors", "2", str(rootfs), path],
            capture_output=True,
            check=False,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceCoverageDenied("E_SQUASHFS_LSTAT_FAILED") from exc
    deny(
        len(proc.stdout) <= MAX_LSTAT_STDOUT and len(proc.stderr) <= MAX_LSTAT_STDOUT,
        "E_SQUASHFS_LSTAT_UNBOUNDED",
    )
    if proc.returncode != 0:
        return {"path": path, "type": "UNRESOLVED", "targetText": None,
                "reason": "NO_SINGLE_REGULAR_INODE_PROVEN"}
    text = proc.stdout.decode("utf-8", "replace")
    return parse_unsquashfs_lstat(text, path)


def parse_unsquashfs_lstat(text: str, path: str) -> dict:
    """Interpret exact metadata line; symlink target is LEXICAL, not dereferenced."""
    deny(path in UNATTESTED_SHELL, "E_UNEXPECTED_PARTMAN_PATH")
    records = []
    prefix = "squashfs-root/" + path
    for line in text.splitlines():
        found = re.search(r"(?:^|\s)" + re.escape(prefix) + r"(?:\s+->\s+(.+))?$", line)
        if found:
            perms = line.split()[0] if line.split() else ""
            records.append((perms, found.group(1)))
    if len(records) != 1:
        return {"path": path, "type": "UNRESOLVED", "targetText": None,
                "reason": "MISSING_OR_AMBIGUOUS_LSTAT_RECORD"}
    perms, target = records[0]
    if perms.startswith("l") and target:
        # Normalize text only. Do not access the target or claim its type/hash.
        lexical = (
            posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
            if not target.startswith("/")
            else posixpath.normpath(target)
        )
        return {
            "path": path,
            "type": "SYMLINK_NOT_FOLLOWED",
            "targetText": target,
            "targetLexicalPathUnverified": lexical,
            "targetProvenanceAuthenticated": False,
        }
    if perms.startswith("-") and target is None:
        # A newly observed regular inode is NOT a trusted source body until
        # strict read/hash and its package owner have been validated.
        return {
            "path": path,
            "type": "REGULAR_METADATA_ONLY",
            "targetText": None,
            "targetProvenanceAuthenticated": False,
        }
    return {"path": path, "type": "NONREGULAR_OR_UNRESOLVED", "targetText": target,
            "reason": "NOT_AN_AUTHENTICATED_REGULAR_SOURCE"}


def reject_forged_effect_graph(graph: dict) -> None:
    deny(type(graph) is dict, "E_EFFECT_GRAPH_SHAPE")
    deny(not any(graph.get(k) is True for k in MUTABLE_GATES), "E_FALSE_EFFECT_GRAPH")
    deny(graph.get("authorization", "DENY_NO_WRITER") == "DENY_NO_WRITER",
         "E_EFFECT_GRAPH_AUTHORIZATION")


def inspect(artifact: Path, iso: Path, mounted: Path) -> dict:
    # This validates the archived full map and the whole pinned 3.9GB ISO,
    # enforces hosted-runner/private workspace and authenticates the six
    # source body hashes/size before any AST analysis.
    original = open_pinned_archive(artifact)
    old = inspect_authenticated_iso(iso, mounted, original)
    index = source_index(original)
    matched = [p for p in BODIES if old["sources"][p]["status"] == "REGULAR_HASH_MATCHED"]
    deny(set(matched) == set(BODIES), "E_SOURCE_BODY_NOT_AUTHENTICATED")
    rootfs = mounted / "casper/filesystem.squashfs"
    calls = {}
    for path in BODIES:
        source, status = exact_regular_bytes(rootfs, path, index[path])
        deny(status == "REGULAR_HASH_MATCHED" and source is not None,
             "E_SOURCE_BODY_NOT_AUTHENTICATED")
        calls[path] = candidate_calls(source, path)
    shell = {p: lstat_member(rootfs, p) for p in UNATTESTED_SHELL}
    result = {
        "kind": "ZORIN_UBIQUITY_FIRST_WRITER_STATIC_SOURCE_EVIDENCE",
        "isoSha256": old["isoSha256"],
        "codeMapSha256": old["codeMapSha256"],
        "sourceHashes": {p: old["sources"][p]["sha256"] for p in BODIES},
        "sourceFilesAuthenticated": list(BODIES),
        "shellInodeMetadata": shell,
        "staticCalls": calls,
        "allSixBodiesAstScanned": True,
        "shellSourcesAuthenticated": False,
        "firstPersistentWriteVerified": False,
        "precommitNonMutatingVerified": False,
        "completeCallGraphVerified": False,
        "allEffectsAuthenticated": False,
        "runtimeCallPathVerified": False,
        "diskWritesAuthorized": False,
        "authorization": "DENY_NO_WRITER",
        "decision": "ROUTE_B",
        "classification": "UBIQUITY_PRECOMMIT_PLAN_UNAVAILABLE",
        "nativeInstallerInvoked": False,
        "stable": False,
    }
    reject_forged_effect_graph(result)
    return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifact-zip", type=Path, required=True)
    p.add_argument("--iso", type=Path, required=True)
    p.add_argument("--mounted", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    try:
        result = inspect(args.artifact_zip, args.iso, args.mounted)
        deny(args.out.parent.is_dir() and not args.out.is_symlink(),
             "E_UNSAFE_EVIDENCE_DESTINATION")
        args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    except SourceCoverageDenied as exc:
        print(exc.code, file=sys.stderr)
        return 2
    print("ROUTE_B / DENY_NO_WRITER / STATIC_CALLS_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
