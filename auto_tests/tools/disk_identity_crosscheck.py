#!/usr/bin/env python3
"""Read-only, fail-closed cross-environment disk identity evidence comparison.

This module is deliberately NOT a disk writer or an authorization token.
Evidence must be collected independently by trusted platform-specific probes.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_ALLOWED = {"windows", "host", "guest"}
_REQUIRED = {
    "transactionId", "diskId", "partitionTableId", "partitionStyle",
    "sizeBytes", "logicalSectorBytes", "physicalSectorBytes",
    "partitionTableSha256", "partitions",
}
_PARTITION = {"id", "offsetBytes", "sizeBytes", "typeId", "contentSha256"}


class IdentityMismatch(ValueError):
    """Disk evidence is incomplete, inconsistent or divergent."""


def _integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0 or value > 2**64 - 1:
        raise IdentityMismatch(f"{label}: invalid positive integer")
    return value


def _record(source: str, record: object) -> dict:
    if not isinstance(record, dict) or set(record) != _REQUIRED:
        raise IdentityMismatch(f"{source}: missing or unexpected evidence fields")
    if not _HEX32.fullmatch(str(record["transactionId"])):
        raise IdentityMismatch(f"{source}: invalid transaction ID")
    if record["partitionStyle"] not in ("GPT", "MBR"):
        raise IdentityMismatch(f"{source}: invalid partition style")
    for name in ("diskId", "partitionTableId"):
        if not isinstance(record[name], str) or not record[name].strip():
            raise IdentityMismatch(f"{source}: missing {name}")
    if not _HEX64.fullmatch(str(record["partitionTableSha256"])):
        raise IdentityMismatch(f"{source}: invalid table digest")
    size = _integer(record["sizeBytes"], "sizeBytes")
    logical = _integer(record["logicalSectorBytes"], "logicalSectorBytes")
    physical = _integer(record["physicalSectorBytes"], "physicalSectorBytes")
    if logical not in (512, 4096) or physical < logical or physical % logical or size % logical:
        raise IdentityMismatch(f"{source}: inconsistent sector geometry")
    parts = record["partitions"]
    if not isinstance(parts, list) or not parts:
        raise IdentityMismatch(f"{source}: empty partition inventory")
    seen = set()
    extents = []
    for p in parts:
        if not isinstance(p, dict) or set(p) != _PARTITION:
            raise IdentityMismatch(f"{source}: malformed partition")
        if not all(isinstance(p[k], str) and p[k].strip() for k in ("id", "typeId")):
            raise IdentityMismatch(f"{source}: missing partition identity")
        if not _HEX64.fullmatch(str(p["contentSha256"])):
            raise IdentityMismatch(f"{source}: missing content digest")
        offset = p["offsetBytes"]
        length = _integer(p["sizeBytes"], "partition size")
        if type(offset) is not int or offset < 0 or offset % logical or length % logical:
            raise IdentityMismatch(f"{source}: unaligned partition")
        if offset + length > size:
            raise IdentityMismatch(f"{source}: partition outside disk")
        if p["id"] in seen:
            raise IdentityMismatch(f"{source}: duplicate partition ID")
        seen.add(p["id"])
        extents.append((offset, offset + length))
    extents.sort()
    if any(a[1] > b[0] for a, b in zip(extents, extents[1:])):
        raise IdentityMismatch(f"{source}: overlapping partition extents")
    return record


def compare_evidence(evidence: dict) -> bool:
    """Require byte-exact agreement from Windows, QEMU host and Linux guest.

    A true result is evidence consistency only, NEVER permission to mutate.
    """
    if not isinstance(evidence, dict) or set(evidence) != _ALLOWED:
        raise IdentityMismatch("all three independent sources are required")
    records = [_record(name, evidence[name]) for name in sorted(_ALLOWED)]
    baseline = json.dumps(records[0], sort_keys=True, separators=(",", ":"))
    if any(json.dumps(item, sort_keys=True, separators=(",", ":")) != baseline for item in records[1:]):
        raise IdentityMismatch("cross-environment disk evidence mismatch")
    return True


def compare_files(paths: dict[str, str]) -> bool:
    if not isinstance(paths, dict) or set(paths) != _ALLOWED:
        raise IdentityMismatch("three evidence paths required")
    evidence = {}
    for name, path in paths.items():
        p = Path(path)
        if p.is_symlink() or not p.is_file():
            raise IdentityMismatch(f"{name}: unsafe evidence path")
        evidence[name] = json.loads(p.read_text(encoding="utf-8"))
    return compare_evidence(evidence)
