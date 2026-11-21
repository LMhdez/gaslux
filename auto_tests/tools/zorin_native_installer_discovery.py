#!/usr/bin/env python3
"""Discover executable/package identity in a pinned Zorin 18.1 ISO, read-only.

The existing ISO inventory verifies the complete hash, catalog, ISO9660 ro
mount and GitHub-hosted runner. This adds dpkg package status, ownership and
selected executable hashes; never runs the installer or writes a guest disk.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from zorin_official_iso_installer_inventory import (
    collect_inventory, bounded_read, MAX_MANIFEST,
)

MAX_STATUS = 16 * 1024 * 1024
MAX_SOURCE = 4 * 1024 * 1024
INSTALLERS = ("ubiquity", "calamares", "subiquity", "ubuntu-desktop-bootstrap", "curtin")
BINARIES = {
    "ubiquity": ("usr/bin/ubiquity", "usr/lib/ubiquity/ubiquity"),
    "calamares": ("usr/bin/calamares",),
    "subiquity": ("usr/bin/subiquity",),
    "ubuntu-desktop-bootstrap": ("usr/bin/ubuntu-desktop-bootstrap",),
    "curtin": ("usr/bin/curtin",),
}
PARTITIONERS = ("parted", "libparted2", "python3-parted", "libdebian-installer4")
BOOT = ("grub-common", "grub-efi-amd64-bin", "grub-efi-amd64-signed",
        "grub-pc", "shim-signed", "efibootmgr")
CAPABILITIES = ("existingPartition", "account", "language", "keyboard",
                "timezone", "partitionLibrary", "gptWrites", "formatting",
                "efiTargetSelection", "grubInstall", "windowsBootManager",
                "unattendedInstall", "updates", "rollback")


class NativeDiscoveryError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativeDiscoveryError(reason)


def read_member(rootfs: Path, name: str, limit: int, optional: bool = False):
    """Read a bounded, constant-relative SquashFS member; no extraction."""
    require(bool(re.fullmatch(r"[A-Za-z0-9_.+@/-]{1,240}", name))
            and not name.startswith("/")
            and all(seg not in ("", ".", "..") for seg in name.split("/"))
            and 0 < limit <= MAX_STATUS, "unsafe member path or bound")
    try:
        result = subprocess.run(
            ["unsquashfs", "-cat", "-processors", "2", str(rootfs), name],
            check=False, capture_output=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise NativeDiscoveryError("SquashFS member read failure") from error
    require(len(result.stdout) <= limit and len(result.stderr) <= 65536,
            "oversized SquashFS member output")
    if result.returncode != 0:
        if optional:
            return None
        raise NativeDiscoveryError("mandatory SquashFS member missing")
    return result.stdout


def installed_packages(status: bytes) -> dict:
    require(len(status) <= MAX_STATUS, "oversized dpkg status")
    selected = set(INSTALLERS + PARTITIONERS + BOOT)
    packages = {}
    for block in re.split(r"\n\s*\n", status.decode("utf-8", "strict")):
        fields = {}
        for line in block.splitlines():
            if ": " in line and not line.startswith((" ", "\t")):
                key, value = line.split(": ", 1)
                fields[key] = value
        name = fields.get("Package", "")
        if name not in selected:
            continue
        require(name not in packages, "duplicate package identity")
        if fields.get("Status") == "install ok installed":
            require(bool(fields.get("Version")) and bool(fields.get("Architecture")),
                    "installed package missing version or architecture")
            packages[name] = {
                "version": fields["Version"],
                "architecture": fields["Architecture"],
            }
    return packages


def manifest_versions(data: bytes) -> dict:
    require(len(data) <= MAX_MANIFEST, "oversized casper manifest")
    names = set(INSTALLERS + PARTITIONERS + BOOT)
    found = {}
    for line in data.decode("utf-8", "strict").splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] not in names:
            continue
        require(fields[0] not in found, "duplicate manifest package")
        found[fields[0]] = fields[1]
    return found


def inspect(rootfs: Path, original: dict, manifest: bytes, reader=read_member) -> dict:
    status = reader(rootfs, "var/lib/dpkg/status", MAX_STATUS)
    require(status is not None, "no installed package status")
    installed = installed_packages(status)
    versions = manifest_versions(manifest)
    sources = [
        {"scope": "iso9660", "path": "casper/filesystem.manifest",
         "sha256": hashlib.sha256(manifest).hexdigest()},
        {"scope": "squashfs", "path": "var/lib/dpkg/status",
         "sha256": hashlib.sha256(status).hexdigest()},
    ]
    binaries = []
    identified = []
    for package in INSTALLERS:
        pkg = installed.get(package)
        owned_paths = set()
        if pkg is not None:
            names = reader(rootfs, "var/lib/dpkg/info/" + package + ".list",
                           2 * 1024 * 1024, optional=True)
            if names is not None:
                owned_paths = set(names.decode("utf-8", "strict").splitlines())
                sources.append({"scope": "squashfs",
                                "path": "var/lib/dpkg/info/" + package + ".list",
                                "sha256": hashlib.sha256(names).hexdigest()})
        for binary in BINARIES[package]:
            raw = reader(rootfs, binary, MAX_SOURCE, optional=True)
            if raw is None:
                continue
            valid_owner = (pkg is not None and
                           versions.get(package) == pkg["version"] and
                           "/" + binary in owned_paths)
            binaries.append({"package": package, "path": binary,
                             "sha256": hashlib.sha256(raw).hexdigest(),
                             "sizeBytes": len(raw), "ownerVerified": valid_owner})
            sources.append({"scope": "squashfs", "path": binary,
                            "sha256": hashlib.sha256(raw).hexdigest()})
        launchers = [x for x in original["installerCandidateLaunchers"]
                     if package in x.get("exec", "").lower()]
        if pkg is not None and launchers and any(
            binary["package"] == package and binary["ownerVerified"]
            for binary in binaries
        ):
            identified.append(package)
    candidate = identified[0] if len(identified) == 1 else None
    return {
        "schemaVersion": 1,
        "distribution": "zorin",
        "iso": {"sha256": original["isoSha256"],
                "sizeBytes": original["isoSizeBytes"],
                "rootfsPath": original["squashfsPath"]},
        "discoveryStatus": "IDENTIFIED_STATICALLY" if candidate else "INCONCLUSIVE",
        "staticInstallerCandidate": candidate,
        "packages": {name: record for name, record in installed.items()
                     if name in INSTALLERS},
        "partitionAndBootPackages": {name: record for name, record in installed.items()
                                     if name in PARTITIONERS + BOOT},
        "launchers": original["installerCandidateLaunchers"],
        "snapCandidates": original.get("installerCandidateSnaps", []),
        "executables": binaries,
        "sourceFiles": sources,
        "capabilities": {name: "UNOBSERVED" for name in CAPABILITIES},
        "nativeInstallerInvoked": False,
        "writeSetAuthenticated": False,
        "nativeGrubBootVerified": False,
        "windowsBootManagerSafe": False,
        "authorization": "DENY_NO_WRITER",
        "stable": False,
    }


def discover(iso: Path, mounted: Path) -> dict:
    original = collect_inventory(iso, mounted)
    rootfs = mounted / original["squashfsPath"]
    require(rootfs.is_file() and not rootfs.is_symlink() and
            rootfs.resolve().is_relative_to(mounted.resolve()),
            "unowned rootfs")
    manifest = bounded_read(mounted / "casper/filesystem.manifest", MAX_MANIFEST)
    require(hashlib.sha256(manifest).hexdigest() == original["casperManifestSha256"],
            "manifest changed after original inventory")
    return inspect(rootfs, original, manifest)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--mounted", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(args.out.parent.is_dir() and not args.out.parent.is_symlink() and
            not args.out.exists() and not args.out.is_symlink() and
            args.out.parent.resolve() == Path(os.environ["GITHUB_WORKSPACE"]).resolve()
            / "zorin-native-evidence", "unsafe discovery output")
    data = discover(args.iso, args.mounted)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(data, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print("PASS: pinned Zorin static discovery; installer NOT executed")


if __name__ == "__main__":
    main()
