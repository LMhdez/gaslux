#!/usr/bin/env python3
"""Inventory the pinned Zorin 18.1 ISO installer without invoking it.

Only reads a mounted immutable ISO and SquashFS on GitHub-hosted CI.
This is NOT native installation or authorization to write ESP, BCD or GPT.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

MAX_MANIFEST = 8 * 1024 * 1024
MAX_LISTING = 4 * 1024 * 1024
MAX_LAUNCHER = 32 * 1024
MAX_CANDIDATES = 32
TOKENS = ("zorin", "install", "ubiquity", "subiquity", "calamares",
          "curtin", "bootstrap")
BOOT_TOKENS = ("grub", "shim", "systemd-boot", "efibootmgr")


class InventoryError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise InventoryError(message)


def bounded_read(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum,
                "missing/oversized/nonregular ISO inventory source")
        data = os.read(fd, maximum + 1)
        require(len(data) == info.st_size, "ISO evidence changed during read")
        return data
    finally:
        os.close(fd)


def parse_packages(text: str) -> tuple[list[str], list[str]]:
    installed, boot = set(), set()
    for line in text.splitlines():
        pieces = line.strip().split()
        if len(pieces) < 2:
            continue
        name = pieces[0].lower()
        if re.fullmatch(r"[a-z0-9][a-z0-9+._:-]{0,127}", name) is None:
            continue
        if any(t in name for t in TOKENS):
            installed.add(name)
        if any(t in name for t in BOOT_TOKENS):
            boot.add(name)
    return sorted(installed)[:MAX_CANDIDATES], sorted(boot)[:MAX_CANDIDATES]


def launcher_metadata(path: str, contents: bytes) -> dict[str, object]:
    require(len(contents) <= MAX_LAUNCHER, "oversized installer launcher")
    require(re.fullmatch(
        r"(?:usr/share/applications|var/lib/snapd/desktop/applications)/"
        r"[A-Za-z0-9_.+@-]+\.desktop", path) is not None,
        "untrusted installer launcher path")
    text = contents.decode("utf-8", "replace")
    item: dict[str, object] = {
        "path": path, "sha256": hashlib.sha256(contents).hexdigest(),
    }
    for field in ("Name", "Exec", "TryExec"):
        matches = [line.split("=", 1)[1].strip()
                   for line in text.splitlines() if line.startswith(field + "=")]
        if len(matches) == 1 and len(matches[0]) <= 512:
            item[field.lower()] = matches[0]
    return item


def parse_squashfs_paths(text: str) -> list[str]:
    found = set()
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate.startswith("squashfs-root/"):
            continue
        path = candidate.removeprefix("squashfs-root/")
        if (len(path) < 256
                and not any(seg in ("", ".", "..") for seg in path.split("/"))
                and path.endswith(".desktop")
                and any(token in path.lower() for token in TOKENS)):
            found.add(path)
    return sorted(found)[:MAX_CANDIDATES]


def scanner_call(*args: str, maximum: int = MAX_LISTING) -> str:
    result = subprocess.run(args, check=True, capture_output=True, timeout=180)
    require(len(result.stdout) <= maximum,
            "unbounded SquashFS inventory output")
    return result.stdout.decode("utf-8", "replace")


def collect_inventory(iso: Path, mounted: Path) -> dict[str, object]:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
        and os.environ.get("GASLUX_ZORIN_ISO_INVENTORY_CONSENT")
            == "I_ACCEPT_ZORIN_OFFICIAL_ISO_READONLY_INVENTORY",
        "only opted-in GitHub-hosted read-only ISO inspection is allowed",
    )
    # Use the existing signed-catalog identity check; never invent ISO hashes.
    from windows_zorin_synthetic_cow_root import (
        verify_official_zorin, ZORIN_SHA256, ZORIN_BYTES,
    )
    scratch = Path(os.environ["RUNNER_TEMP"])
    require(
        iso.is_file() and not iso.is_symlink()
        and iso.resolve().is_relative_to(scratch.resolve())
        and mounted.is_dir() and not mounted.is_symlink()
        and mounted.resolve().is_relative_to(scratch.resolve()),
        "ISO and its readonly mount must belong to the hosted runner",
    )
    verify_official_zorin(iso)
    mount_info = scanner_call(
        "findmnt", "-rn", "-M", str(mounted),
        "-o", "FSTYPE,OPTIONS", maximum=4096,
    ).strip().split()
    require(
        len(mount_info) >= 2 and mount_info[0] == "iso9660"
        and "ro" in mount_info[1].split(","),
        "Zorin ISO must be mounted ISO9660 read-only",
    )
    resolver = (
        'set -Eeuo pipefail; '
        'source assets/live/libertix-distribution-common.sh; '
        'source assets/live/libertix-install-runtime-common.sh; '
        'resolve_distribution_rootfs_or_die "$1"'
    )
    squashfs = Path(scanner_call(
        "bash", "-c", resolver, "zorin-inventory", str(mounted),
        maximum=4096,
    ).strip())
    require(
        squashfs.is_file() and not squashfs.is_symlink()
        and squashfs.resolve().is_relative_to(mounted.resolve()),
        "no unique owned Zorin SquashFS inside official ISO",
    )
    manifest_path = mounted / "casper/filesystem.manifest"
    manifest = bounded_read(manifest_path, MAX_MANIFEST) if manifest_path.exists() else b""
    packages, boot_packages = parse_packages(manifest.decode("utf-8", "replace"))
    listing = scanner_call(
        "unsquashfs", "-l", "-processors", "2", str(squashfs),
        "usr/share/applications",
    )
    launchers = []
    for path in parse_squashfs_paths(listing):
        raw = subprocess.run(
            ["unsquashfs", "-cat", "-processors", "2", str(squashfs), path],
            check=True, capture_output=True, timeout=180,
        ).stdout
        launchers.append(launcher_metadata(path, raw))
    snaps = []
    for target in (
        "var/lib/snapd/seed/snaps",
        "var/lib/snapd/desktop/applications",
    ):
        result = subprocess.run(
            ["unsquashfs", "-l", "-processors", "2", str(squashfs), target],
            check=False, capture_output=True, timeout=180,
        )
        if result.returncode == 0:
            require(len(result.stdout) <= MAX_LISTING, "oversized snap inventory")
            snaps.extend(
                line.strip().removeprefix("squashfs-root/")
                for line in result.stdout.decode("utf-8", "replace").splitlines()
                if line.strip().startswith("squashfs-root/")
                and any(token in line.lower() for token in TOKENS)
            )
    return {
        "identity": "pinned-zorin-18.1-core-iso-mounted-readonly",
        "isoSha256": ZORIN_SHA256,
        "isoSizeBytes": ZORIN_BYTES,
        "isoFilesystem": "iso9660",
        "squashfsPath": str(squashfs.relative_to(mounted)),
        "casperManifestSha256":
            hashlib.sha256(manifest).hexdigest() if manifest else None,
        "installerCandidatePackages": packages,
        "bootloaderCandidatePackages": boot_packages,
        "installerCandidateLaunchers": launchers,
        "installerCandidateSnaps": sorted(set(snaps))[:MAX_CANDIDATES],
        "nativeInstallerInvoked": False,
        "installerWriteSetAuthenticated": False,
        "productionBootloaderVerified": False,
        "windowsEspSafeToWrite": False,
        "nativeInstallerIdentificationComplete": False,
        "stable": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--mounted", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    inventory = collect_inventory(args.iso, args.mounted)
    require(
        args.out.parent.is_dir() and not args.out.parent.is_symlink()
        and args.out.parent.resolve()
            == Path(os.environ["GITHUB_WORKSPACE"]).resolve()
                / "windows-x64-tcg-evidence"
        and not args.out.exists() and not args.out.is_symlink(),
        "unsafe or existing ISO inventory output",
    )
    payload = (json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(
        args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    with os.fdopen(fd, "wb") as output:
        output.write(payload)
    print("PASS: Zorin ISO installer candidate inventory; no native install verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
