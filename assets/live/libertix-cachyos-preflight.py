#!/usr/bin/env python3
"""Read-only CachyOS Archiso payload preflight for a future Libertix backend.

This tool does NOT install an OS or modify partitions. It does not assert that
CachyOS is a supported Libertix distribution. Full installation must be gated
until an Arch-specific target configurator, bootloader and rollback verifiers
have been implemented and tested.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable


class PreflightError(Exception):
    """An ISO did not satisfy the narrowly scoped CachyOS Archiso contract."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def parse_os_release(content: str) -> dict[str, str]:
    """Parse os-release fields without executing untrusted text in a shell."""
    values: dict[str, str] = {}
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise PreflightError("Malformed os-release line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise PreflightError("Invalid os-release field name")
        value = value.strip()
        if len(value) >= 2 and value[0] in ("'", '"'):
            if value[-1] != value[0]:
                raise PreflightError("Unterminated quoted os-release value")
            value = value[1:-1]
        elif re.search(r"\s", value):
            raise PreflightError("Unquoted whitespace in os-release value")
        if key in values:
            raise PreflightError("Duplicate os-release key")
        values[key] = value
    return values


def _run_unsquashfs(
    runner: Runner, args: list[str], description: str
) -> str:
    try:
        result = runner(
            ["unsquashfs", *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PreflightError(f"Cannot inspect squashfs ({description}): {error}") from error
    if result.returncode != 0:
        raise PreflightError(f"Cannot inspect squashfs ({description}); exit={result.returncode}")
    if len(result.stdout) > 2_000_000:
        raise PreflightError(f"Unreasonably large squashfs output ({description})")
    return result.stdout


def inspect_cachyos_iso_root(iso_root: Path, *, runner: Runner = subprocess.run) -> dict[str, object]:
    """Inspect an already-mounted/extracted ISO directory without writing data."""
    if not iso_root.is_dir():
        raise PreflightError("ISO root must be a readable directory")

    # archiso generates this image, unlike Ubuntu's casper/filesystem.squashfs.
    squashfs = iso_root / "arch" / "x86_64" / "airootfs.sfs"
    if squashfs.is_symlink() or not squashfs.is_file():
        raise PreflightError("Expected regular Archiso image arch/x86_64/airootfs.sfs")

    os_release = parse_os_release(
        _run_unsquashfs(runner, ["-cat", str(squashfs), "etc/os-release"], "os-release")
    )
    # Verified against official CachyOS desktop 260809 ISO. Unlike the
    # previous synthetic fixture, its live squashfs identifies as CachyOS
    # itself, with Arch only in ID_LIKE. Require all identity fields; a
    # generic Arch ISO must never be accepted merely because pacman exists.
    expected = {
        "ID": "cachyos",
        "ID_LIKE": "arch",
        "NAME": "CachyOS Linux",
        "IMAGE_ID": "cachyos",
    }
    if any(os_release.get(key) != value for key, value in expected.items()):
        raise PreflightError("Not the expected CachyOS 260809 Archiso live identity")

    inventory = _run_unsquashfs(
        runner, ["-ll", str(squashfs), "etc/pacman.conf", "usr/bin/pacman"], "capabilities"
    )
    observed = set(re.findall(r"(?:^|\s)squashfs-root/([^\s]+)", inventory, re.MULTILINE))
    capabilities = ("etc/pacman.conf", "usr/bin/pacman")
    missing = [path for path in capabilities if path not in observed]
    if missing:
        raise PreflightError("CachyOS live image lacks required pacman capabilities: " + ", ".join(missing))

    return {
        "distribution": "cachyos",
        "live_os_release_id": "cachyos",
        "live_os_release_id_like": "arch",
        "live_os_image_id": "cachyos",
        "iso_layout": "archiso",
        "rootfs_relative_path": "arch/x86_64/airootfs.sfs",
        "requires_separate_arch_installer_backend": True,
        "online_installer_required": True,
        "libertix_installation_supported": False,
        "mutates_storage": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso_root", type=Path, help="Mounted or extracted CachyOS ISO root directory")
    options = parser.parse_args(argv)
    try:
        outcome = inspect_cachyos_iso_root(options.iso_root)
    except PreflightError as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stdout)
        return 1
    print(json.dumps({"ok": True, **outcome}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
