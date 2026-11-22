#!/usr/bin/env python3
"""Q4OS exact native ISO offline inspector. NEVER signs, boots, or installs."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import q4os_native_live_boot_readiness as readiness

_ALLOWED = frozenset(
    {
        "MEDIA_NOT_AUTHENTICATED",
        "MEDIA_INSPECT_MISSING_LIVE_ROOT",
        "MEDIA_INSPECT_BAD_KERNEL",
        "MEDIA_INSPECT_BAD_IDENTITY",
        "MEDIA_INSPECT_BAD_INSTALLER",
        "MEDIA_INSPECT_BAD_CONFIGURATION",
        "MEDIA_INSPECT_EXTERNAL_FAILURE",
    }
)


class InspectRefusal(Exception):
    """No arbitrary paths, command output or tokens in public reasons."""


def refuse(reason: str) -> None:
    raise InspectRefusal(reason if reason in _ALLOWED else "MEDIA_INSPECT_EXTERNAL_FAILURE")


def _bounded_unsquashfs(image: Path, member: str, max_bytes: int = 65536) -> str:
    """Read one literal small file; never extract the SquashFS tree."""
    allowed_members = {
        "etc/os-release",
        "etc/q4os_version",
        "etc/calamares/settings.conf",
        "etc/calamares/modules/bootloader.conf",
    }
    if member not in allowed_members:
        refuse("MEDIA_INSPECT_BAD_CONFIGURATION")
    try:
        result = subprocess.run(
            ["unsquashfs", "-cat", str(image), member],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=45,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        refuse("MEDIA_INSPECT_EXTERNAL_FAILURE")
    if result.returncode or not 1 <= len(result.stdout) <= max_bytes:
        refuse("MEDIA_INSPECT_BAD_CONFIGURATION")
    try:
        return result.stdout.decode("utf-8", "strict")
    except UnicodeError:
        refuse("MEDIA_INSPECT_BAD_CONFIGURATION")


def _unique_yaml(text: str) -> dict:
    try:
        import yaml

        class UniqueLoader(yaml.SafeLoader):
            pass

        def unique_mapping(loader, node):
            values = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node)
                if not isinstance(key, str) or key in values:
                    refuse("MEDIA_INSPECT_BAD_CONFIGURATION")
                values[key] = loader.construct_object(value_node)
            return values

        UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
        doc = yaml.load(text, Loader=UniqueLoader)
        if not isinstance(doc, dict):
            refuse("MEDIA_INSPECT_BAD_CONFIGURATION")
        return doc
    except InspectRefusal:
        raise
    except Exception:
        # No arbitrary YAML exception text may enter the published report.
        refuse("MEDIA_INSPECT_BAD_CONFIGURATION")


def validate_native_fields(
    os_release: str,
    version: str,
    settings_yaml: str,
    bootloader_yaml: str,
    kernel_names: list[str],
    initrd_names: list[str],
) -> dict:
    """Cross-check expected Q4OS-specific marker, not Debian ID alone."""
    if not (
        re.search(r'(?m)^ID="?debian"?\s*$', os_release)
        and re.search(r'(?m)^VERSION_ID="?13"?\s*$', os_release)
        and re.fullmatch(r"6\.10-deb13u[0-9]+", version.strip())
    ):
        refuse("MEDIA_INSPECT_BAD_IDENTITY")
    if not kernel_names or not initrd_names:
        refuse("MEDIA_INSPECT_BAD_KERNEL")
    if any(
        "/" in name or len(name) > 128 or not name.startswith("vmlinuz") for name in kernel_names
    ) or any(
        "/" in name or len(name) > 128 or not name.startswith(("initrd", "initramfs"))
        for name in initrd_names
    ):
        refuse("MEDIA_INSPECT_BAD_KERNEL")
    settings = _unique_yaml(settings_yaml)
    bootloader = _unique_yaml(bootloader_yaml)
    if not isinstance(settings.get("sequence"), list):
        refuse("MEDIA_INSPECT_BAD_INSTALLER")
    if type(bootloader.get("installEFIFallback")) is not bool:
        refuse("MEDIA_INSPECT_BAD_CONFIGURATION")
    return {
        "debianOsReleaseId": "debian",
        "debianVersionId": "13",
        "q4osVersion": version.strip(),
        "nativeInstaller": "Calamares",
        "calamaresSequenceVerified": True,
        "installEFIFallback": bootloader["installEFIFallback"],
        "kernelEntries": sorted(set(kernel_names)),
        "initrdEntries": sorted(set(initrd_names)),
    }


def inspect_mounted_native_iso(iso_root: Path) -> dict:
    """Require an actual read-only ISO mount, not a synthetic text fixture."""
    if not iso_root.is_absolute() or not os.path.ismount(iso_root):
        refuse("MEDIA_INSPECT_EXTERNAL_FAILURE")
    try:
        mount = subprocess.run(
            ["findmnt", "-n", "-o", "FSTYPE,OPTIONS", "--target", str(iso_root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=True,
        )
        options = mount.stdout.decode("ascii", "strict").strip()
    except (OSError, subprocess.SubprocessError, UnicodeError):
        refuse("MEDIA_INSPECT_EXTERNAL_FAILURE")
    if "iso9660" not in options.split() or not all(
        option in options for option in ("ro", "nosuid", "nodev", "noexec")
    ):
        refuse("MEDIA_INSPECT_EXTERNAL_FAILURE")
    live = iso_root / "live"
    squash = live / "filesystem.squashfs"
    try:
        meta = squash.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_size < 1_000_000:
            refuse("MEDIA_INSPECT_MISSING_LIVE_ROOT")
        kernels = sorted(
            p.name
            for p in live.iterdir()
            if p.name.startswith("vmlinuz") and (p.is_file() or p.is_symlink())
        )
        initrds = sorted(
            p.name
            for p in live.iterdir()
            if p.name.startswith(("initrd", "initramfs")) and (p.is_file() or p.is_symlink())
        )
        return validate_native_fields(
            _bounded_unsquashfs(squash, "etc/os-release"),
            _bounded_unsquashfs(squash, "etc/q4os_version"),
            _bounded_unsquashfs(squash, "etc/calamares/settings.conf"),
            _bounded_unsquashfs(squash, "etc/calamares/modules/bootloader.conf"),
            kernels,
            initrds,
        )
    except InspectRefusal:
        raise
    except (OSError, ValueError):
        refuse("MEDIA_INSPECT_EXTERNAL_FAILURE")


def report_for_inspection(iso: Path, mounted_root: Path) -> dict:
    """Byte identity ≠ upstream signing ≠ boot authority."""
    measured = readiness.measure_official_iso(iso)
    native = inspect_mounted_native_iso(mounted_root)
    # Any path reopened by an external ISO/SquashFS reader is *not* a
    # long-lived FD-bound QEMU proof; remeasure after all inspections.
    second = readiness.measure_official_iso(iso)
    if measured != second:
        refuse("MEDIA_NOT_AUTHENTICATED")
    return {
        "schemaVersion": 1,
        "purpose": "Q4OS_OFFLINE_ISO_PROVENANCE_READBACK",
        "decision": "DENY",
        "release": "6.10-r2",
        "architecture": "x86_64",
        "media": {"filename": readiness.ISO_NAME, **measured},
        "inspection": native,
        "publisherSignatureVerified": False,
        "publisherSigningKeyTrusted": False,
        "gasluxCatalogSignatureVerified": False,
        "isoFdBoundToQemu": False,
        "guestBooted": False,
        "installationAuthorized": False,
        "candidateCatalogFieldsUnsigned": {
            "id": "q4os",
            "name": "Q4OS Andromeda 6.10 x64 r2 (EXPERIMENTAL)",
            "isoInstaller": readiness.ISO_SOURCE,
            "isoInstallerFileName": readiness.ISO_NAME,
            "isoInstallerSha256": readiness.UPSTREAM_SHA256,
            "isoInstallerSizeBytes": measured["sizeBytes"],
            "backend": "q4os-native",
            "experimental": True,
            "signed": False,
            "productionEligible": False,
        },
        "blockers": [
            "UPSTREAM_ISO_SIGNATURE_NOT_VERIFIED",
            "PUBLISHER_RELEASE_SIGNING_KEY_NOT_TRUSTED",
            "SIGNED_GASLUX_EXPERIMENTAL_CATALOG_MISSING",
            "SAFETY_REAUDIT_PENDING",
            "ISO_TO_QEMU_FD_NOT_ATTESTED",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Q4OS read-only ISO inspection, no QEMU")
    parser.add_argument("--iso", required=True, type=Path)
    parser.add_argument("--mounted-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = report_for_inspection(args.iso, args.mounted_root)
    except (InspectRefusal, readiness.MediaRefusal) as exc:
        reason = str(exc)
        if reason not in _ALLOWED and reason not in readiness.REASONS:
            reason = "MEDIA_INSPECT_EXTERNAL_FAILURE"
        print(json.dumps({"decision": "DENY", "reasonCode": reason}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
