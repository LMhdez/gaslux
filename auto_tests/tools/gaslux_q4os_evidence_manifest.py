#!/usr/bin/env python3
"""Create and verify a deterministic SHA-256 manifest for Q4OS GUI evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

MANIFEST_NAME = "evidence.sha256"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)\Z")


class EvidenceManifestError(ValueError):
    """Evidence directory or manifest failed its integrity contract."""


def _root(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise EvidenceManifestError("evidence directory must be an absolute, owned directory")
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise EvidenceManifestError("evidence directory ownership or permissions are unsafe")
    return path


def _regular_files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in root.iterdir():
        if path.name == MANIFEST_NAME:
            continue
        if not _NAME.fullmatch(path.name):
            raise EvidenceManifestError("evidence filename is outside the safe flat-name contract")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceManifestError("evidence contains a non-regular file: " + path.name)
        files[path.name] = path
    return files


def _require_nofollow() -> int:
    flag = getattr(os, "O_NOFOLLOW", None)
    if flag is None:
        raise EvidenceManifestError("platform does not expose O_NOFOLLOW; refusing unsafe evidence access")
    return flag


def _sha256(path: Path) -> str:
    flags = os.O_RDONLY | _require_nofollow()
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceManifestError("evidence changed to a non-regular file: " + path.name)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def create_manifest(directory: Path) -> Path:
    root = _root(directory)
    files = _regular_files(root)
    if not files:
        raise EvidenceManifestError("refuse to create an empty evidence manifest")
    lines = [f"{_sha256(files[name])}  {name}" for name in sorted(files)]
    target = root / MANIFEST_NAME
    temporary = root / f".{MANIFEST_NAME}.{os.getpid()}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _require_nofollow(),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def verify_manifest(directory: Path, required: set[str] | None = None) -> None:
    root = _root(directory)
    manifest = root / MANIFEST_NAME
    try:
        manifest_fd = os.open(manifest, os.O_RDONLY | _require_nofollow())
    except FileNotFoundError as exc:
        raise EvidenceManifestError("evidence SHA-256 manifest is missing or unsafe") from exc
    except OSError as exc:
        raise EvidenceManifestError("evidence SHA-256 manifest is missing or unsafe") from exc
    try:
        metadata = os.fstat(manifest_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceManifestError("evidence SHA-256 manifest is not a regular file")
        with os.fdopen(manifest_fd, "r", encoding="ascii", closefd=False) as stream:
            manifest_lines = stream.read().splitlines()
    finally:
        os.close(manifest_fd)
    entries: dict[str, str] = {}
    for line in manifest_lines:
        match = _LINE.fullmatch(line)
        if match is None:
            raise EvidenceManifestError("malformed evidence SHA-256 manifest line")
        digest, name = match.groups()
        if name == MANIFEST_NAME or name in entries:
            raise EvidenceManifestError("duplicate or recursive evidence manifest entry")
        entries[name] = digest
    if list(entries) != sorted(entries):
        raise EvidenceManifestError("evidence manifest entries are not sorted")
    files = _regular_files(root)
    if set(entries) != set(files):
        raise EvidenceManifestError("evidence files do not exactly match the manifest")
    missing = (required or set()) - set(entries)
    if missing:
        raise EvidenceManifestError("required evidence missing: " + ", ".join(sorted(missing)))
    for name in sorted(entries):
        if _sha256(files[name]) != entries[name]:
            raise EvidenceManifestError("evidence SHA-256 mismatch: " + name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--require", action="append", default=[])
    args = parser.parse_args()
    try:
        if args.mode == "create":
            if args.require:
                raise EvidenceManifestError("--require is valid only with verify")
            result = create_manifest(args.directory)
            print("GASLUX_Q4OS_EVIDENCE_MANIFEST_CREATED=" + result.name)
        else:
            verify_manifest(args.directory, set(args.require))
            print("GASLUX_Q4OS_EVIDENCE_MANIFEST_VERIFIED=PASS")
    except (EvidenceManifestError, OSError, UnicodeError) as exc:
        print("GASLUX_Q4OS_EVIDENCE_MANIFEST_REFUSED=" + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
