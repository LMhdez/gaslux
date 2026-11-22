"""Bounded local reads and deterministic JSON. No discovery, network or file creation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO


class Refusal(ValueError):
    """Evidence or navigation contract could not be established."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal(f"Duplicate JSON property: {key}")
        result[key] = value
    return result


def parse(raw: bytes) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=lambda s: _invalid(s)
        )
    except (ValueError, RecursionError) as exc:
        raise Refusal(f"Invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise Refusal("Expected a JSON object")
    return value


def _invalid(token: str) -> None:
    raise Refusal(f"Invalid JSON token: {token}")


def basename(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", name) or name.endswith("."):
        raise Refusal("Unsafe evidence basename")
    if name.partition(".")[0].upper() in _DEVICES:
        raise Refusal("Device name refused")
    return name


_DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{prefix}{i}" for prefix in ("COM", "LPT") for i in "0123456789¹²³"
}


def _local(path: Path) -> Path:
    if ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise Refusal("Local paths without traversal required")
    path = path.absolute()
    for part in path.parts[1:]:
        if (
            ":" in part
            or "\\" in part
            or part.endswith((" ", "."))
            or part.partition(".")[0].upper() in _DEVICES
        ):
            raise Refusal("Device, stream or non-canonical path")
    return path


def _open_local(path: Path) -> int:
    if os.name == "posix":
        flags = os.O_RDONLY | os.O_NOFOLLOW
        directory = os.open("/", flags | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
                os.close(directory)
                directory = child
            if hasattr(os, "O_PATH") and Path("/proc/self/fd").is_dir():
                entry = os.open(path.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    if not stat.S_ISREG(os.fstat(entry).st_mode):
                        raise Refusal("Regular file required")
                    return os.open(f"/proc/self/fd/{entry}", os.O_RDONLY)
                finally:
                    os.close(entry)
            meta = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(meta.st_mode):
                raise Refusal("Regular file required")
            return os.open(path.name, flags | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
    if os.name != "nt":
        raise Refusal("Unsupported filesystem")
    # Reject junctions as well as symlinks. Confirm the opened handle still names
    # the requested local file before reading its contents.
    import ctypes
    import msvcrt
    from ctypes import wintypes

    for component in (*reversed(path.parents), path):
        if component.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise Refusal("Reparse point refused")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise Refusal("Regular file required")
    fd = os.open(path, os.O_RDONLY | os.O_BINARY)
    try:
        final = ctypes.create_unicode_buffer(32768)
        api = ctypes.windll.kernel32.GetFinalPathNameByHandleW
        length = api(wintypes.HANDLE(msvcrt.get_osfhandle(fd)), final, len(final), 0)
        if not 0 < length < len(final) or Path(final.value.removeprefix("\\\\?\\")) != path:
            raise Refusal("Opened file escaped its directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def regular(path: Path, limit: int) -> Iterator[BinaryIO]:
    try:
        with os.fdopen(_open_local(_local(path)), "rb") as stream:
            meta = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(meta.st_mode)
                or meta.st_nlink != 1
                or not 0 < meta.st_size <= limit
            ):
                raise Refusal(f"Not a bounded regular file: {path.name}")
            yield stream
            after = os.fstat(stream.fileno())
            if (meta.st_size, meta.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise Refusal("File changed during observation")
    except OSError as exc:
        raise Refusal(f"Cannot safely read {path.name}: {exc.strerror}") from exc


def read(path: Path, limit: int = 1024 * 1024) -> bytes:
    with regular(path, limit) as stream:
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise Refusal("File exceeded size limit")
        return data


def sealed(report: dict) -> dict:
    return {"manifest": report, "sha256": digest(canonical(report))}


def unseal(document: dict) -> dict:
    if set(document) != {"manifest", "sha256"} or not isinstance(document["manifest"], dict):
        raise Refusal("Incomplete manifest envelope")
    if digest(canonical(document["manifest"])) != document["sha256"]:
        raise Refusal("Manifest SHA-256 mismatch")
    return document["manifest"]
