#!/usr/bin/env python3
"""Independent SHA-pinned Windows ISO intake for a private test-only Gaslux VM.

Never downloads, activates Windows, writes a target disk, or authorizes a guest.
Media must be obtained through a lawful Microsoft download channel and its
checksum compared with the publisher's reviewed, pinned official hash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

OFFICIAL_PAGE = "https://www.microsoft.com/en-us/software-download/windows10ISO"
# Microsoft's Windows 10 22H2 ISO download verification table (2026-11-22).
MEDIA = {
    "windows10-22h2-pt-pt-x64": (
        "83f83b5a9101f5fa21de4e925abc7693478d84cd5fbf02cb019393048b5bdbbb",
        "Portuguese 64-bit",
    ),
    "windows10-22h2-en-us-x64": (
        "a6f470ca6d331eb353b815c043e327a347f594f37ff525f17764738fe812852e",
        "English 64-bit",
    ),
}
MIN_ISO_BYTES = 2 * 1024**3
MAX_ISO_BYTES = 9 * 1024**3


class MediaRefusal(ValueError):
    pass


def inspect_file(path: Path, *, minimum: int = MIN_ISO_BYTES,
                 maximum: int = MAX_ISO_BYTES) -> dict:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise MediaRefusal("Local ISO pathname must be absolute and normalized")
    if not path.name.lower().endswith(".iso"):
        raise MediaRefusal("Expected an ISO file")
    if path.is_symlink():
        raise MediaRefusal("ISO symlinks are not admitted")
    if type(minimum) is not int or type(maximum) is not int or minimum < 34816 or maximum < minimum:
        raise MediaRefusal("Invalid ISO byte limits")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MediaRefusal("Cannot open private ISO read-only") from exc
    try:
        with os.fdopen(descriptor, "rb") as media:
            before = os.fstat(media.fileno())
            if not stat.S_ISREG(before.st_mode) or not minimum <= before.st_size <= maximum:
                raise MediaRefusal("ISO size/type does not match trusted media envelope")
            media.seek(16 * 2048)
            hdr = media.read(2048)
            if len(hdr) != 2048 or hdr[0] != 1 or hdr[1:6] != b"CD001" or hdr[6] != 1:
                raise MediaRefusal("ISO9660 primary volume descriptor absent")
            media.seek(0)
            h = hashlib.sha256()
            for chunk in iter(lambda: media.read(1024 * 1024), b""):
                h.update(chunk)
            after = os.fstat(media.fileno())
            if (before.st_dev != after.st_dev or before.st_ino != after.st_ino
                    or before.st_size != after.st_size or
                    before.st_mtime_ns != after.st_mtime_ns or
                    before.st_ctime_ns != after.st_ctime_ns):
                raise MediaRefusal("ISO mutated during independent hashing")
    except OSError as exc:
        raise MediaRefusal("Could not fully read private Windows ISO") from exc
    try:
        final = path.lstat()
    except OSError as exc:
        raise MediaRefusal("ISO path disappeared after verification") from exc
    if (not stat.S_ISREG(final.st_mode) or before.st_ino != final.st_ino
            or before.st_dev != final.st_dev or before.st_mtime_ns != final.st_mtime_ns
            or before.st_ctime_ns != final.st_ctime_ns):
        raise MediaRefusal("Windows ISO path replaced after verification")
    return {"size_bytes": before.st_size, "sha256": h.hexdigest(),
            "iso9660_pvd_verified": True}


def intake(iso: Path | None, product: str) -> dict:
    if product not in MEDIA:
        raise MediaRefusal("Windows ISO not in curated official Microsoft hash allowlist")
    expected_hash, language = MEDIA[product]
    report = {
        "schema": "gaslux-windows-media-source-intake-v1",
        "product": product, "language": language,
        "official_source": OFFICIAL_PAGE,
        "expected_official_sha256": expected_hash,
        "status": "BLOCKED_MEDIA",
        "file_verified": False,
        "official_pinned_hash_matched": False,
        "installer_executed": False,
        "windows_guest_booted": False,
        "windows_license_verified": False,
        "guest_writer_admitted": False,
        "dual_boot_verified": False,
        "windows_recovery_verified": False,
    }
    if iso is None:
        return report
    media = inspect_file(iso)
    if media["sha256"] != expected_hash:
        raise MediaRefusal("Windows ISO SHA-256 differs from published official pin")
    report.update({
        "status": "PINNED_WINDOWS_ISO_BYTES_VERIFIED",
        "file_verified": True,
        "official_pinned_hash_matched": True,
        "file_bytes": media["size_bytes"],
        "observed_sha256": media["sha256"],
        "iso9660_pvd_verified": media["iso9660_pvd_verified"],
    })
    return report


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("--iso", type=Path)
    cli.add_argument("--product", choices=tuple(MEDIA), default="windows10-22h2-pt-pt-x64")
    cli.add_argument("--report", type=Path, required=True)
    args = cli.parse_args()
    result = intake(args.iso, args.product)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
