#!/usr/bin/env python3
"""Read-only provenance audit for the narrow Zorin 18.1 Ubiquity source gap.

No execution/import of ISO source. No Ubiquity, partman, mkfs or GRUB calls.
This is NOT a replacement for the #333 handoff or #339 precommit classifier.
An authenticated STATIC map never proves first-write ordering or dry-run.
"""
from __future__ import annotations

import argparse
import ast
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

from jsonschema import Draft202012Validator
from zorin_native_ubiquity_map import (
    ISO_SHA,
    UBIQUITY_EXEC_SHA,
    UBIQUITY_VERSION,
    require_regular_member,
    validate_consistency,
)
from zorin_native_installer_discovery import read_member
from windows_zorin_synthetic_cow_root import verify_official_zorin

ROOT = Path(__file__).resolve().parents[2]
MAP_SCHEMA = ROOT / "schemas/zorin-native-ubiquity-capabilities.schema.json"
ARTIFACT_SHA256 = "641bf31056addd3e54126d3e636ea524d12d0a4ac16e4188510aef8ae1f08da9"
MAP_SHA256 = "47f42ce781af0eb39bc19f6c3bf4f2fb20569c5467a8f17d8e6d84b273a08f24"
EXPECTED_ARCHIVE_MEMBERS = frozenset(
    (
        "zorin-native-ubiquity-code-map.json",
        "zorin-native-installer-discovery.json",
        "zorin-native-target-denied.json",
    )
)
CORE_SOURCES = (
    "usr/bin/ubiquity",
    "usr/lib/ubiquity/plugins/ubi-partman.py",
    "usr/lib/ubiquity/ubiquity/parted_server.py",
    "usr/lib/ubiquity/ubiquity/components/partman_commit.py",
    "lib/partman/lib/commit.sh",
    "lib/partman/lib/resize.sh",
    "usr/lib/ubiquity/ubiquity/components/grubinstaller.py",
    "usr/share/ubiquity/plugininstall.py",
)
REGULAR_CODES = frozenset(("REGULAR_HASH_MATCHED", "REGULAR_NEWLY_ATTESTED"))
MAX_ARCHIVE = 512 * 1024
MAX_MEMBER = 512 * 1024
MAX_GRAPH_EDGES = 180
MUTATION_TOKENS = re.compile(
    r"(?:parted|partman|sfdisk|wipefs|mkfs|resize|mount|grub|"
    r"efibootmgr|subprocess|popen|os\.system|os\.open|os\.write|"
    r"debconf|preseed|disk|commit|format)", re.I
)


class SourceCoverageDenied(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def insist(condition: bool, code: str) -> None:
    if not condition:
        raise SourceCoverageDenied(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def open_pinned_archive(path: Path) -> dict:
    """Read one regular, non-linked ZIP; validate the *full* historical bytes."""
    insist(isinstance(path, Path), "E_UNTRUSTED_ARCHIVE_PATH")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise SourceCoverageDenied("E_UNTRUSTED_ARCHIVE_PATH") from exc
    try:
        initial = os.fstat(fd)
        insist(
            stat.S_ISREG(initial.st_mode)
            and initial.st_nlink == 1
            and 0 < initial.st_size <= MAX_ARCHIVE,
            "E_UNTRUSTED_ARCHIVE_TYPE",
        )
        with os.fdopen(os.dup(fd), "rb") as source:
            content = source.read(MAX_ARCHIVE + 1)
        final = os.fstat(fd)
        insist(
            len(content) == initial.st_size
            and (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns)
            == (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
            and sha(content) == ARTIFACT_SHA256,
            "E_UNAUTHENTICATED_ARCHIVE",
        )
    finally:
        os.close(fd)
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            names = archive.namelist()
            insist(
                len(names) == len(EXPECTED_ARCHIVE_MEMBERS)
                and set(names) == EXPECTED_ARCHIVE_MEMBERS
                and len(set(names)) == len(names),
                "E_ARCHIVE_MEMBER_SET",
            )
            for entry in archive.infolist():
                mode = (entry.external_attr >> 16) & 0o170000
                insist(
                    not entry.is_dir() and mode != stat.S_IFLNK
                    and 0 < entry.file_size <= MAX_MEMBER,
                    "E_ARCHIVE_MEMBER_TYPE",
                )
            data = archive.read("zorin-native-ubiquity-code-map.json")
    except (zipfile.BadZipFile, RuntimeError, KeyError) as exc:
        raise SourceCoverageDenied("E_ARCHIVE_FORMAT") from exc
    insist(sha(data) == MAP_SHA256, "E_UNAUTHENTICATED_CODE_MAP")
    try:
        mapped = json.loads(data)
        schema = json.loads(MAP_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(mapped)
        validate_consistency(mapped)
    except Exception as exc:
        raise SourceCoverageDenied("E_CODE_MAP_CONTRACT") from exc
    insist(
        mapped["isoSha256"] == ISO_SHA
        and mapped["installer"]["sha256"] == UBIQUITY_EXEC_SHA
        and mapped["installer"]["version"] == UBIQUITY_VERSION
        and mapped["authorization"] == "DENY_NO_WRITER",
        "E_ISO_INSTALLER_IDENTITY",
    )
    return mapped


def source_index(report: dict) -> dict:
    modules = report["modules"]
    insist(type(modules) is list, "E_SOURCE_INDEX")
    indexed = {}
    for item in modules:
        path = item["path"]
        insist(path not in indexed, "E_DUPLICATE_SOURCE_PATH")
        indexed[path] = item
    for path in CORE_SOURCES:
        if path in indexed:
            insist(
                indexed[path]["ownerVerified"] is True
                and indexed[path]["package"] == "ubiquity"
                and indexed[path]["packageVersion"] == UBIQUITY_VERSION,
                "E_SOURCE_OWNER_UNVERIFIED",
            )
        else:
            insist(path in report["unreadablePaths"], "E_UNACCOUNTED_SOURCE")
    insist(
        "lib/partman/lib/commit.sh" in report["unreadablePaths"]
        and "lib/partman/lib/resize.sh" in report["unreadablePaths"],
        "E_SOURCE_GAP_NOT_REPRODUCED",
    )
    return indexed


def exact_regular_bytes(
    rootfs: Path, path: str, expected: dict | None
) -> tuple[bytes | None, str]:
    """Read only member paths from immutable allowlist; never follow symlinks."""
    insist(path in CORE_SOURCES, "E_SOURCE_PATH_NOT_ALLOWED")
    try:
        require_regular_member(rootfs, path)
    except Exception:
        return None, "MISSING_OR_NONREGULAR"
    limit = min(MAX_MEMBER, int(expected["sizeBytes"]) + 1) if expected else MAX_MEMBER
    try:
        data = read_member(rootfs, path, limit, optional=False)
    except Exception:
        return None, "UNREADABLE_REGULAR"
    insist(type(data) is bytes and 0 < len(data) <= MAX_MEMBER, "E_SOURCE_BOUNDS")
    if expected:
        insist(
            len(data) == expected["sizeBytes"] and sha(data) == expected["sha256"],
            "E_SOURCE_HASH_OR_SIZE_MISMATCH",
        )
        return data, "REGULAR_HASH_MATCHED"
    # Newly measured from the original SHA-pinned ISO, but NOT the old #264
    # mapping. A new source SHA is evidence, never an authority to write.
    return data, "REGULAR_NEWLY_ATTESTED"


def static_python_calls(data: bytes, path: str) -> dict:
    """Static AST call sites, never a runtime call graph/trace."""
    try:
        tree = ast.parse(data.decode("utf-8", "strict"), filename=path)
    except (SyntaxError, UnicodeDecodeError):
        return {"parse": "UNPARSABLE_PYTHON", "callSites": [], "functions": []}
    funcs = []
    candidates = []

    def label(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return label(node.value) + "." + node.attr
        return "<dynamic-expression>"

    def visit_body(nodes: list[ast.stmt], scope: str) -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = scope + "." + node.name
                funcs.append({"function": name, "line": node.lineno})
                visit_body(node.body, name)
            elif isinstance(node, ast.ClassDef):
                visit_body(node.body, scope + "." + node.name)
            else:
                for call in ast.walk(node):
                    if isinstance(call, ast.Call):
                        called = label(call.func)
                        if MUTATION_TOKENS.search(called):
                            candidates.append(
                                {
                                    "caller": scope,
                                    "callee": called,
                                    "line": call.lineno,
                                    "basis": "STATIC_AST_CALLSITE_NOT_A_TRACE",
                                }
                            )

    visit_body(tree.body, "<module>")
    return {
        "parse": "STATIC_AST_ONLY",
        "functions": funcs[:MAX_GRAPH_EDGES],
        "callSites": candidates[:MAX_GRAPH_EDGES],
        "truncated": len(funcs) > MAX_GRAPH_EDGES or len(candidates) > MAX_GRAPH_EDGES,
    }


def enforce_no_operational_claims(claim: dict | None) -> None:
    if claim is None:
        return
    insist(type(claim) is dict, "E_UNTRUSTED_ACTION_GRAPH")
    forbidden = (
        "completeActionGraph",
        "dryRunVerified",
        "firstWriteLocated",
        "writerFenceActive",
        "precommitFullyObserved",
    )
    insist(not any(claim.get(name) is True for name in forbidden), "E_FALSE_ACTION_GRAPH")
    insist(
        not any(name in claim for name in ("proposedDiskWrites", "efiWrites", "grubWrites")),
        "E_UNTRUSTED_ACTION_GRAPH",
    )


def report_gap(archive_map: dict, *, source_bodies: dict | None = None) -> dict:
    """Never promote a source fingerprint to an authenticated action graph."""
    indexed = source_index(archive_map)
    sources = {}
    source_bodies = {} if source_bodies is None else source_bodies
    insist(type(source_bodies) is dict, "E_UNTRUSTED_SOURCE_BODY_SET")
    insist(set(source_bodies).issubset(CORE_SOURCES), "E_SOURCE_PATH_NOT_ALLOWED")
    for path in CORE_SOURCES:
        expected = indexed.get(path)
        entry = source_bodies.get(path)
        if entry is None:
            sources[path] = {
                "status": "BODY_NOT_AVAILABLE",
                "knownSha256": expected["sha256"] if expected else None,
                "fileRegularPreviouslyAttested": expected is not None,
            }
            continue
        insist(
            type(entry) is dict and set(entry) == {"data", "status"}
            and entry["status"] in REGULAR_CODES and type(entry["data"]) is bytes,
            "E_UNTRUSTED_SOURCE_BODY_SET",
        )
        body = entry["data"]
        insist(0 < len(body) <= MAX_MEMBER, "E_SOURCE_BOUNDS")
        if expected:
            insist(
                entry["status"] == "REGULAR_HASH_MATCHED"
                and sha(body) == expected["sha256"]
                and len(body) == expected["sizeBytes"],
                "E_SOURCE_HASH_OR_SIZE_MISMATCH",
            )
        else:
            insist(entry["status"] == "REGULAR_NEWLY_ATTESTED", "E_SOURCE_ORIGIN")
        parsed = (
            static_python_calls(body, path)
            if path.endswith(".py") or path.endswith("/ubiquity")
            else {"parse": "SHELL_TEXT_NOT_EXECUTED", "functions": [], "callSites": []}
        )
        sources[path] = {
            "status": entry["status"],
            "sha256": sha(body),
            "sizeBytes": len(body),
            "fileRegularPreviouslyAttested": expected is not None,
            "staticCalls": parsed,
        }
    return {
        "schemaVersion": 1,
        "kind": "ZORIN_UBIQUITY_SOURCE_COVERAGE_READONLY",
        "isoSha256": ISO_SHA,
        "ubiquityVersion": UBIQUITY_VERSION,
        "codeMapSha256": MAP_SHA256,
        "sourceBodiesFromHistoricalZip": False,
        "sources": sources,
        "missingSourceBodies": [p for p in CORE_SOURCES if sources[p]["status"] == "BODY_NOT_AVAILABLE"],
        "sourceOnlyStaticCalls": True,
        "runtimeCallGraphAuthenticated": False,
        "firstPersistentMutationLocated": False,
        "nonMutatingPrecommitProven": False,
        "classification": "UBIQUITY_PRECOMMIT_PLAN_UNAVAILABLE",
        "decision": "ROUTE_B",
        "authorization": "DENY_NO_WRITER",
        "nativeInstallerInvoked": False,
        "productionStorageWritesAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "sameDiskDualBootVerified": False,
        "windowsInPlaceRollbackProven": False,
        "stable": False,
        "blockingDependencies": [
            "SOURCE_BODY_NOT_INCLUDED_IN_HISTORICAL_MAP",
            "PARTMAN_COMMIT_AND_RESIZE_SHELL_ORIGIN_UNPROVEN",
            "PARTED_SERVER_EXTERNAL_EFFECTS_NOT_RUNTIME_AUTHENTICATED",
            "NO_COMPLETE_PREWRITE_CALL_OR_EFFECT_GRAPH",
            "NO_INDEPENDENT_HOST_WRITE_FENCE_OR_WINDOWS_RECOVERY",
        ],
    }


def inspect_authenticated_iso(iso: Path, mount: Path, original_map: dict) -> dict:
    """Extract only an allowlist after complete ISO hash + read-only mount."""
    insist(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux",
        "E_UNAUTHORIZED_SOURCE_ENVIRONMENT",
    )
    scratch = Path(os.environ["RUNNER_TEMP"]).resolve()
    insist(
        iso.is_file() and not iso.is_symlink()
        and iso.stat().st_nlink == 1
        and iso.resolve().is_relative_to(scratch)
        and mount.is_dir() and not mount.is_symlink()
        and mount.resolve().is_relative_to(scratch),
        "E_UNTRUSTED_SOURCE_PATH",
    )
    verify_official_zorin(iso)  # entire 3.9 GB verified, BEFORE all source reads
    observed = subprocess.run(
        ["findmnt", "-rn", "-M", str(mount), "-o", "FSTYPE,OPTIONS"],
        capture_output=True, timeout=20, check=False, text=True,
    )
    columns = observed.stdout.strip().split()
    insist(
        observed.returncode == 0
        and len(columns) == 2 and columns[0] == "iso9660"
        and "ro" in columns[1].split(","),
        "E_ISO_NOT_MOUNTED_READONLY",
    )
    rootfs = mount / "casper/filesystem.squashfs"
    insist(
        rootfs.is_file() and not rootfs.is_symlink()
        and rootfs.resolve().is_relative_to(mount.resolve()),
        "E_UNTRUSTED_ROOTFS",
    )
    index = source_index(original_map)
    bodies = {}
    rejected = {}
    for path in CORE_SOURCES:
        data, status = exact_regular_bytes(rootfs, path, index.get(path))
        if data is None:
            rejected[path] = status
        else:
            bodies[path] = {"data": data, "status": status}
    result = report_gap(original_map, source_bodies=bodies)
    result["unavailableFromSquashfs"] = rejected
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-zip", type=Path, required=True)
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--mounted", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        insist((args.iso is None) == (args.mounted is None), "E_SOURCE_ARGUMENTS")
        historical = open_pinned_archive(args.artifact_zip)
        result = (
            inspect_authenticated_iso(args.iso, args.mounted, historical)
            if args.iso is not None
            else report_gap(historical)
        )
        insist(result["authorization"] == "DENY_NO_WRITER", "E_AUTHORIZATION")
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print("ROUTE_B / UBIQUITY_PRECOMMIT_PLAN_UNAVAILABLE / DENY_NO_WRITER")
        return 0
    except SourceCoverageDenied as exc:
        print(exc.code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
