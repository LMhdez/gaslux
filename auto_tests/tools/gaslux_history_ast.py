#!/usr/bin/env python3
"""Read-only exact Git blob AST discovery; never import historical modules."""
from __future__ import annotations

import argparse
import ast
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[a-f0-9]{40}\Z")
MAX_BLOB = 1_048_576
MAX_INDEX = 1_048_576
MAX_FILES = 320
REPO = "LMhdez/gaslux"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("unexpected redirect")


def read_json(path):
    if path.is_symlink() or path.stat().st_size > MAX_INDEX:
        raise ValueError("unsafe index")
    return json.loads(path.read_text(encoding="utf-8"))


def blob_bytes(sha, document):
    if not SHA.fullmatch(sha) or document.get("sha") != sha or document.get("encoding") != "base64":
        raise ValueError("blob identity mismatch")
    size = document.get("size")
    if type(size) is not int or not 0 <= size <= MAX_BLOB:
        raise ValueError("blob size outside bound")
    raw = base64.b64decode("".join(document["content"].split()), validate=True)
    if len(raw) != size or hashlib.sha1(b"blob " + str(size).encode() + b"\0" + raw).hexdigest() != sha:
        raise ValueError("blob digest mismatch")
    return raw


def fetch_blob(sha, token):
    if not SHA.fullmatch(sha):
        raise ValueError("invalid SHA")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/git/blobs/{sha}",
        headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "gaslux-history-ast"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        raw = response.read(2 * MAX_BLOB + 1)
    if len(raw) > 2 * MAX_BLOB:
        raise ValueError("oversized response")
    return blob_bytes(sha, json.loads(raw))


def fingerprint(node):
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def declarations(raw):
    # Bytes allow Python's own encoding-cookie handling. Never compile modules.
    root = ast.parse(raw)
    rows = []

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.stack = []

        def visit_declaration(self, node):
            name = ".".join(self.stack + [node.name])
            rows.append({"name": node.name, "qualified": name, "kind": type(node).__name__,
                         "line": node.lineno, "ast_sha256": fingerprint(node)})
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_FunctionDef = visit_declaration
        visit_AsyncFunctionDef = visit_declaration
        visit_ClassDef = visit_declaration

    Visitor().visit(root)
    return rows


def manifest():
    index = read_json(ROOT / "docs/GASLUX_HISTORICAL_SYMBOL_INVENTORY.json")
    extension = read_json(ROOT / "docs/GASLUX_HISTORICAL_SYMBOL_EXTENSION.json")
    if (index.get("repository") != REPO or extension.get("repository") != REPO
            or index.get("dev") != extension.get("dev") or not SHA.fullmatch(index["dev"])):
        raise ValueError("manifest identity mismatch")
    source = index["historical_expected"]
    current = index["dev_expected"] + extension["expected"]
    if len(source) != 42 or len(current) != 247:
        raise ValueError("unexpected fixed snapshot coverage")
    result = []
    seen = set()
    for kind, items in (("historical", source), ("dev", current)):
        for row in items:
            path = row["path"]
            if not isinstance(path, str) or not path.endswith(".py"):
                continue
            sha, commit = row["blob"], row["ref"]
            if (not SHA.fullmatch(sha) or not SHA.fullmatch(commit)
                    or (kind == "dev" and commit != index["dev"])
                    or not re.fullmatch(r"[A-Za-z0-9_./-]{1,250}", path)
                    or path.startswith("/") or ".." in path.split("/")):
                raise ValueError("unsafe manifest entry")
            key = (kind, commit, path)
            if key in seen:
                raise ValueError("duplicate manifest entry")
            seen.add(key)
            result.append({"group": kind, "ref": commit, "path": path, "blob": sha})
    if not 0 < len(result) <= MAX_FILES:
        raise ValueError("manifest bounds")
    return result


# Exact reviewed function shape only. Neither surrounding module nor arbitrary
# historical function may execute. The template is deliberately independent
# of the historical module's imports, global variables or file system.
WITNESS_TEMPLATE = r'''def has_orderly_shutdown_witness(ARG: bytes) -> bool:
    """Require a complete, line-anchored systemd or kernel poweroff witness."""
    witnesses = (
        rb"^systemd-shutdown\[\d+\]: Powering off\.$",
        rb"^\[\s*OK\s*\]\s+Finished systemd-poweroff\.service - System Power Off\.$",
        rb"^\[\s*\d+(?:\.\d+)?\s*\]\s+reboot: Power down$",
    )
    normalized = ARG.replace(b"\r\n", b"\n")
    return any(re.search(pattern, normalized, re.MULTILINE) for pattern in witnesses)
'''


def approved_witness(raw, arg):
    if arg not in ("serial_bytes", "serial_log"):
        raise ValueError("unexpected witness argument")
    tree = ast.parse(raw)
    nodes = [n for n in tree.body if type(n) is ast.FunctionDef
             and n.name == "has_orderly_shutdown_witness"]
    expected = ast.parse(WITNESS_TEMPLATE.replace("ARG", arg)).body[0]
    if len(nodes) != 1 or fingerprint(nodes[0]) != fingerprint(expected):
        raise ValueError("witness shape changed; independent review required")
    # Execute only the exact matched AST, with fixed standard library re and
    # minimal builtins; no historical module-level statements or other funcs.
    scope = {"__builtins__": {"bytes": bytes, "bool": bool, "any": any}, "re": re}
    isolated = ast.Module(body=[nodes[0]], type_ignores=[])
    exec(compile(isolated, "<reviewed-witness-only>", "exec"), scope)
    return scope["has_orderly_shutdown_witness"]


CASES = (
    (b"", False),
    (b"systemd-shutdown[1]: Powering off.", True),
    (b"systemd-shutdown[12]: Powering off.\r\n", True),
    (b"noise\nsystemd-shutdown[7]: Powering off.\n", True),
    (b"[ OK ] Finished systemd-poweroff.service - System Power Off.\n", True),
    (b"[  12.3 ] reboot: Power down\r\n", True),
    (b"[ 12 ] reboot: Power down", True),
    (b"prefix systemd-shutdown[1]: Powering off.", False),
    (b"systemd-shutdown[1]: Powering off. suffix", False),
    (b"systemd-shutdown[1]: Powering off.\r", False),
    (b"noise\rsystemd-shutdown[1]: Powering off.", False),
    (b"systemd-shutdown[x]: Powering off.", False),
    (b"[ 1.2 ] reboot: Restarting system", False),
    (b"login: root", False),
    (b"[ OK ] Finished unrelated.service - System Power Off.", False),
    (b"systemd-shutdown[1]: Powering off", False),
)


def differential(left, right):
    a, b = approved_witness(left, "serial_bytes"), approved_witness(right, "serial_log")
    for value, expected in CASES:
        if a(value) is not expected or b(value) is not expected:
            raise ValueError("differential witness regression")
    return {"scope": "shutdown_witness_only", "cases": len(CASES),
            "passed": len(CASES), "module_imported": False, "general_equivalence_verified": False}


# This second reviewed template is restricted to exactly one declaration.
# The controlled input is a memory stream, not a real filesystem path.
HASH_TEMPLATE = '''def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
'''


def approved_hash(raw):
    tree = ast.parse(raw)
    nodes = [n for n in tree.body if type(n) is ast.FunctionDef and n.name == "sha256"]
    expected = ast.parse(HASH_TEMPLATE).body[0]
    if len(nodes) != 1 or fingerprint(nodes[0]) != fingerprint(expected):
        raise ValueError("hash shape changed; independent review required")
    scope = {"__builtins__": {"str": str}, "Path": object, "hashlib": hashlib}
    exec(compile(ast.Module(body=[nodes[0]], type_ignores=[]),
                 "<reviewed-memory-hash-only>", "exec"), scope)
    return scope["sha256"]


def hash_differential(sources):
    if len(sources) != 3:
        raise ValueError("expected three reviewed hash declarations")
    functions = [approved_hash(raw) for raw in sources]
    cases = (b"", b"a", b"abc", bytes(range(256)), b"\x00" * 8192,
             b"\xff" * 262145, b"\r\n" * 8193, bytes(range(256)) * 4096)

    class MemoryPath:
        def __init__(self, value):
            self.value = value
            self.opens = 0

        def open(self, mode):
            if mode != "rb" or self.opens:
                raise ValueError("unexpected stream access")
            self.opens += 1
            return io.BytesIO(self.value)

    for value in cases:
        expected = hashlib.sha256(value).hexdigest()
        for function in functions:
            path = MemoryPath(value)
            if function(path) != expected or path.opens != 1:
                raise ValueError("hash differential regression")

    class RefusedPath:
        def open(self, mode):
            raise OSError("controlled input refusal")

    for function in functions:
        try:
            function(RefusedPath())
        except OSError:
            pass
        else:
            raise ValueError("hash swallowed input failure")
    return {"scope": "sha256_memory_stream_only", "implementations": 3,
            "cases": len(cases) + 1, "passed": len(cases) + 1,
            "function_evaluations": 3 * (len(cases) + 1),
            "historical_module_imported": False, "filesystem_access": False,
            "general_equivalence_verified": False}


def audit(token):
    files = manifest()
    unique = sorted({x["blob"] for x in files})
    with ThreadPoolExecutor(max_workers=8) as pool:
        cache = dict(zip(unique, pool.map(lambda sha: fetch_blob(sha, token), unique)))
    current = {}
    historical = []
    counts = {"historical": 0, "dev": 0}
    for row in files:
        nodes = declarations(cache[row["blob"]])
        counts[row["group"]] += len(nodes)
        for node in nodes:
            entry = {**row, **node}
            if row["group"] == "dev":
                current.setdefault(node["ast_sha256"], []).append(entry)
            else:
                historical.append(entry)
    matches = []
    pair_count = 0
    for node in historical:
        targets = current.get(node["ast_sha256"], [])
        pair_count += len(targets)
        if targets and len(matches) < 512:
            matches.append({"source": node, "targets": targets[:8], "target_count": len(targets)})
    source = {row["path"]: cache[row["blob"]] for row in files
              if row["group"] == "historical" and row["ref"] == "7ab2a431767d212566ab57b834f299f8308dbda6"}
    result = differential(source["auto_tests/tools/validate_mint_cow_boot_evidence.py"],
                          source["auto_tests/tools/windows_mint_overlay_root.py"])
    current_files = {row["path"]: cache[row["blob"]] for row in files if row["group"] == "dev"}
    hash_result = hash_differential([
        source["auto_tests/tools/windows_mint_overlay_root.py"],
        current_files["iso-tools/generate-release-metadata.py"],
        current_files["iso-tools/sync_filepool_checksums.py"],
    ])
    return {"kind": "historical_ast_discovery_only", "repository": REPO,
            "files": len(files), "unique_blobs": len(unique), "declarations": counts,
            "historical_nodes_with_identical_ast": sum(n["ast_sha256"] in current for n in historical),
            "matching_pairs": pair_count, "bounded_matches": matches,
            "differential": result, "hash_differential": hash_result, "formal_gate_verified": False, "merge_authorized": False,
            "writer_authorized": False, "release_eligible": False,
            "semantic_equivalence_verified": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise ValueError("read-only GitHub token required")
    result = audit(token)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({key: result[key] for key in
                      ("files", "unique_blobs", "declarations", "matching_pairs", "differential", "hash_differential")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
