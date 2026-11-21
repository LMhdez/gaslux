#!/usr/bin/env python3
"""Read-only, fail-closed cross-environment disk identity evidence comparison.

This module is deliberately NOT a disk writer or an authorization token.
Evidence must be collected independently by trusted platform-specific probes.
"""
from __future__ import annotations

import json
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_ALLOWED = {"windows", "host", "guest"}
_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
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
    if record["partitionStyle"] != "GPT":
        raise IdentityMismatch(f"{source}: only GPT inventories are supported; MBR/EBR unsupported")
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


def _metadata(value: os.stat_result) -> tuple:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _regular(source: str, value: os.stat_result) -> None:
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise IdentityMismatch(f"{source}: not an exclusively linked regular evidence file")
    if value.st_size <= 0 or value.st_size > _MAX_EVIDENCE_BYTES:
        raise IdentityMismatch(f"{source}: truncated or oversized evidence file")


def _check_pin(name: str, pin: tuple) -> None:
    directory_fd, filename, evidence_fd, initial = pin
    try:
        observed = os.fstat(evidence_fd)
        current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise IdentityMismatch(f"{name}: evidence entry no longer accessible") from error
    _regular(name, observed)
    _regular(name, current)
    if _metadata(observed) != _metadata(initial) or _metadata(current) != _metadata(initial):
        raise IdentityMismatch(f"{name}: evidence entry or file changed during inspection")


def _pin(stack: ExitStack, name: str, raw_path: str | os.PathLike) -> tuple:
    """Pin each directory and leaf without following symlinks (POSIX only)."""
    if not isinstance(raw_path, (str, os.PathLike)):
        raise IdentityMismatch(f"{name}: invalid evidence path")
    path = Path(raw_path)
    if (not path.name or '..' in path.parts or
            not all(hasattr(os, flag) for flag in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC'))):
        raise IdentityMismatch(f"{name}: unsafe path or unsupported OS")
    directory_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    start = '/' if path.is_absolute() else '.'
    try:
        directory_fd = os.open(start, directory_flags)
        stack.callback(os.close, directory_fd)
        for component in path.parts[1 if path.is_absolute() else 0:-1]:
            if component == '.':
                continue
            directory_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            stack.callback(os.close, directory_fd)
        before = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        _regular(name, before)
        evidence_fd = os.open(path.name, file_flags, dir_fd=directory_fd)
        stack.callback(os.close, evidence_fd)
        opened = os.fstat(evidence_fd)
        _regular(name, opened)
        if _metadata(before) != _metadata(opened):
            raise IdentityMismatch(f"{name}: entry substituted during opening")
        pin = (directory_fd, path.name, evidence_fd, before)
        _check_pin(name, pin)
        return pin
    except OSError as error:
        raise IdentityMismatch(f"{name}: unsafe or unreadable evidence path") from error


def _read_pinned(name: str, pin: tuple) -> bytes:
    """Read exactly the observed length via a pinned FD without reopening paths."""
    _, _, fd, initial = pin
    _check_pin(name, pin)
    chunks = []
    position = 0
    try:
        while position < initial.st_size:
            chunk = os.pread(fd, min(65536, initial.st_size - position), position)
            if not chunk:
                raise IdentityMismatch(f"{name}: truncated evidence during read")
            chunks.append(chunk)
            position += len(chunk)
        if os.pread(fd, 1, initial.st_size):
            raise IdentityMismatch(f"{name}: evidence grew during read")
    except OSError as error:
        raise IdentityMismatch(f"{name}: evidence read failed") from error
    _check_pin(name, pin)
    return b''.join(chunks)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    record = {}
    for key, value in pairs:
        if key in record:
            raise IdentityMismatch("duplicate JSON evidence field")
        record[key] = value
    return record


def _reject_json_constant(value: str) -> None:
    raise IdentityMismatch(f"invalid JSON constant: {value}")


def compare_files(paths: dict[str, str]) -> bool:
    """Compare three pinned, read-only regular JSON files; never authorize writes.

    This is only syntactic consistency of caller-supplied evidence, not
    authenticated provenance, independent collection, freshness or immutability.
    Even a successful double-read cannot prevent privileged or ABA mutation.
    """
    if not isinstance(paths, dict) or set(paths) != _ALLOWED:
        raise IdentityMismatch("three evidence paths required")
    with ExitStack() as stack:
        pins = {name: _pin(stack, name, paths[name]) for name in sorted(_ALLOWED)}
        first = {name: _read_pinned(name, pins[name]) for name in sorted(_ALLOWED)}
        evidence = {}
        for name, content in first.items():
            try:
                evidence[name] = json.loads(
                    content.decode('utf-8'),
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_json_constant,
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise IdentityMismatch(f"{name}: invalid JSON evidence") from error
        result = compare_evidence(evidence)
        for name, pin in pins.items():
            if _read_pinned(name, pin) != first[name]:
                raise IdentityMismatch(f"{name}: evidence changed during re-read")
        return result
