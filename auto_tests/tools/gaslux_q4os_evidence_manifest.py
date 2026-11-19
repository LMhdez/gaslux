#!/usr/bin/env python3
"""Create and verify a deterministic SHA-256 manifest for Q4OS GUI evidence.

All evidence access is anchored to an already-open directory descriptor. This
prevents a path or symlink swap between directory enumeration and file open.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

MANIFEST_NAME = "evidence.sha256"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\\Z")
_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)\\Z")


class EvidenceManifestError(ValueError):
    """Evidence directory or manifest failed its integrity contract."""


def _require_nofollow() -> int:
    flag = getattr(os, "O_NOFOLLOW", None)
    if flag is None:
        raise EvidenceManifestError(
            "platform does not expose O_NOFOLLOW; refusing unsafe evidence access"
        )
    return flag


def _open_root(path: Path) -> int:
    if not path.is_absolute():
        raise EvidenceManifestError("evidence directory must be an absolute, owned directory")
    nofollow = _require_nofollow()
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if directory_flag is None:
        raise EvidenceManifestError("platform does not expose O_DIRECTORY; refusing unsafe access")
    try:
        descriptor = os.open(path, os.O_RDONLY | directory_flag | nofollow)
    except OSError as exc:
        raise EvidenceManifestError("evidence directory is missing or unsafe") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        os.close(descriptor)
        raise EvidenceManifestError("evidence directory ownership or permissions are unsafe")
    return descriptor


def _regular_files(directory_fd: int) -> set[str]:
    files: set[str] = set()
    for name in os.listdir(directory_fd):
        if name == MANIFEST_NAME:
            continue
        if not _NAME.fullmatch(name):
            raise EvidenceManifestError("evidence filename is outside the safe flat-name contract")
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise EvidenceManifestError("evidence changed during directory inspection: " + name) from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceManifestError("evidence contains a non-regular file: " + name)
        files.add(name)
    return files


def _sha256_at(directory_fd: int, name: str) -> str:
    descriptor = os.open(name, os.O_RDONLY | _require_nofollow(), dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceManifestError("evidence changed to a non-regular file: " + name)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def create_manifest(directory: Path) -> Path:
    directory_fd = _open_root(directory)
    try:
        files = _regular_files(directory_fd)
        if not files:
            raise EvidenceManifestError("refuse to create an empty evidence manifest")
        lines = [f"{_sha256_at(directory_fd, name)}  {name}" for name in sorted(files)]
        temporary = f".{MANIFEST_NAME}.{os.getpid()}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _require_nofollow(),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="ascii", newline="\\n") as stream:
                stream.write("\\n".join(lines) + "\\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(
                temporary,
                MANIFEST_NAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        return directory / MANIFEST_NAME
    finally:
        os.close(directory_fd)


def verify_manifest(directory: Path, required: set[str] | None = None) -> None:
    directory_fd = _open_root(directory)
    try:
        try:
            manifest_fd = os.open(
                MANIFEST_NAME,
                os.O_RDONLY | _require_nofollow(),
                dir_fd=directory_fd,
            )
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
        files = _regular_files(directory_fd)
        if set(entries) != files:
            raise EvidenceManifestError("evidence files do not exactly match the manifest")
        missing = (required or set()) - set(entries)
        if missing:
            raise EvidenceManifestError("required evidence missing: " + ", ".join(sorted(missing)))
        for name in sorted(entries):
            if _sha256_at(directory_fd, name) != entries[name]:
                raise EvidenceManifestError("evidence SHA-256 mismatch: " + name)
    finally:
        os.close(directory_fd)


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
