#!/usr/bin/env python3
"""Read-only laboratory media gate; never authorizes installation or writes disks.

Callers MUST separately verify a maintainer-signed catalogue and bind the
os-release evidence to the exact hashed ISO. Neither is implemented here.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

BLOCK_SIZE = 2048
MAX_ISO_BYTES = 16 * 1024**3
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
_KEY = re.compile(r"[A-Z][A-Z0-9_]*\Z")


class ProbeRefusal(ValueError):
    """The diagnostic must stop before returning an apparently usable result."""


def verify_iso_header_and_hash(path: str, expected_size: int, expected_sha256: str) -> dict:
    """Hash a regular local ISO by file descriptor and inspect the ISO9660 header.

    The ISO9660 header is necessary, not sufficient, for a real installer ISO.
    The digest and byte size must come from an independently verified source.
    """
    if type(path) is not str or not path or not Path(path).is_absolute():
        raise ProbeRefusal("ISO path must be an absolute path")
    iso = Path(path)
    if ".." in iso.parts or iso.suffix.lower() != ".iso":
        raise ProbeRefusal("ISO path must be an exact local .iso file")
    if type(expected_size) is not int or not 40 * BLOCK_SIZE <= expected_size <= MAX_ISO_BYTES:
        raise ProbeRefusal("Invalid pinned ISO byte size")
    if type(expected_sha256) is not str or _SHA256.fullmatch(expected_sha256) is None:
        raise ProbeRefusal("Missing or invalid pinned SHA-256")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        with os.fdopen(os.open(iso, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
                raise ProbeRefusal("ISO is not a regular file of the pinned byte size")
            digest = hashlib.sha256()
            while data := stream.read(1024 * 1024):
                digest.update(data)
            stream.seek(16 * BLOCK_SIZE)
            descriptor_found = False
            for _ in range(32):
                descriptor = stream.read(BLOCK_SIZE)
                if len(descriptor) != BLOCK_SIZE:
                    break
                if descriptor[1:6] != b"CD001" or descriptor[6] != 1:
                    raise ProbeRefusal("Invalid ISO9660 volume descriptor")
                if descriptor[0] == 1:
                    descriptor_found = True
                if descriptor[0] == 255:
                    break
            after = os.fstat(stream.fileno())
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as exc:
        raise ProbeRefusal("Cannot open a safe regular ISO file") from exc

    try:
        path_now = iso.lstat()
    except OSError as exc:
        raise ProbeRefusal("ISO was removed during inspection") from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
        or not stat.S_ISREG(path_now.st_mode)
        or path_now.st_dev != before.st_dev
        or path_now.st_ino != before.st_ino
    ):
        raise ProbeRefusal("ISO changed or was replaced during inspection")
    if not descriptor_found:
        raise ProbeRefusal("No ISO9660 primary volume descriptor")
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise ProbeRefusal("ISO SHA-256 does not match the pinned value")
    return {"sizeBytes": before.st_size, "sha256": actual_sha256, "iso9660Header": True}


def read_os_release_evidence(path: str) -> dict[str, str]:
    """Parse untrusted lab evidence; do NOT infer that it came from the ISO."""
    if type(path) is not str or not path or not Path(path).is_absolute():
        raise ProbeRefusal("os-release evidence path must be absolute")
    evidence = Path(path)
    if evidence.is_symlink() or not evidence.is_file() or evidence.stat().st_size > 16384:
        raise ProbeRefusal("Invalid os-release evidence file")
    try:
        raw = evidence.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProbeRefusal("Unreadable os-release evidence") from exc
    values = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not _KEY.fullmatch(key) or key in values:
            raise ProbeRefusal("Malformed or duplicate os-release property")
        if value.startswith(('"', "'")):
            if len(value) < 2 or value[-1] != value[0]:
                raise ProbeRefusal("Malformed quoted os-release value")
            value = value[1:-1]
        if "\x00" in value or len(value) > 512:
            raise ProbeRefusal("Invalid os-release value")
        values[key] = value
    if "ID" not in values or _ID.fullmatch(values["ID"]) is None:
        raise ProbeRefusal("Missing or unsafe os-release identity")
    return values


def diagnostic(
    *,
    iso_path: str,
    expected_size: int,
    expected_sha256: str,
    os_release_path: str,
    expected_os_id: str,
    firmware: str,
    partition_style: str,
    secure_boot_enabled: bool,
    bootloader: str,
    backend: str,
    allowed_modes: dict[str, str],
    require_secure_boot_disabled: bool = False,
) -> dict:
    """Return diagnostic evidence only; never a write/boot/release permit."""
    if type(secure_boot_enabled) is not bool:
        raise ProbeRefusal("Secure Boot must be measured as a boolean")
    if firmware not in {"bios", "uefi"} or partition_style not in {"mbr", "gpt"}:
        raise ProbeRefusal("Unknown firmware or partition style")
    mode = f"{firmware}/{partition_style}"
    if mode not in allowed_modes or bootloader != allowed_modes[mode]:
        raise ProbeRefusal("Unsupported firmware, partition layout or bootloader")
    if require_secure_boot_disabled and secure_boot_enabled:
        raise ProbeRefusal("Secure Boot enabled; refuse before any disk operation")
    if type(expected_os_id) is not str or _ID.fullmatch(expected_os_id) is None:
        raise ProbeRefusal("Invalid expected OS identity")
    media = verify_iso_header_and_hash(iso_path, expected_size, expected_sha256)
    identity = read_os_release_evidence(os_release_path)
    if identity["ID"] != expected_os_id:
        raise ProbeRefusal("Live system identity does not match expected distribution")
    if type(backend) is not str or not backend:
        raise ProbeRefusal("Missing backend identity")
    return {
        "backend": backend,
        "firmwareLayout": mode,
        "bootloader": bootloader,
        "media": media,
        "osReleaseId": identity["ID"],
        "result": "diagnostic-only",
        "isoToLiveIdentityBindingProven": False,
        "signedCatalogVerified": False,
        "installationAuthorized": False,
        "diskWrites": 0,
    }
