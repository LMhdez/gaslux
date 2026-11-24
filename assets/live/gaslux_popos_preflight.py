#!/usr/bin/env python3
"""Pop!_OS System76 candidate diagnostics. No disk/boot operations are allowed."""

from __future__ import annotations

from gaslux_lab_media_probe import ProbeRefusal, diagnostic

FIRMWARE_BOOTLOADERS = {"bios/mbr": "grub", "uefi/gpt": "systemd-boot"}
IMAGE_VARIANTS = frozenset({"generic", "nvidia"})


def probe_popos(
    *,
    iso_path: str,
    iso_size: int,
    iso_sha256: str,
    os_release_path: str,
    image_variant: str,
    firmware: str,
    partition_style: str,
    secure_boot_enabled: bool,
    bootloader: str,
    full_disk_encryption: bool,
    windows_shared_disk: bool,
) -> dict:
    """Inspect a candidate, never authorize an installation.

    The `os-release` snapshot must later be cryptographically associated with
    the verified ISO; this diagnostic does not establish that binding.
    """
    if image_variant not in IMAGE_VARIANTS or type(image_variant) is not str:
        raise ProbeRefusal("Unrecognized Pop!_OS ISO variant")
    if type(full_disk_encryption) is not bool or type(windows_shared_disk) is not bool:
        raise ProbeRefusal("Encryption and Windows disk-sharing status must be boolean")
    if full_disk_encryption and windows_shared_disk:
        raise ProbeRefusal("Pop!_OS full-disk encryption on shared Windows disk is unsupported")
    result = diagnostic(
        iso_path=iso_path,
        expected_size=iso_size,
        expected_sha256=iso_sha256,
        os_release_path=os_release_path,
        expected_os_id="pop",
        firmware=firmware,
        partition_style=partition_style,
        secure_boot_enabled=secure_boot_enabled,
        bootloader=bootloader,
        backend="system76",
        allowed_modes=FIRMWARE_BOOTLOADERS,
        require_secure_boot_disabled=True,
    )
    result["imageVariant"] = image_variant
    result["windowsSharedDisk"] = windows_shared_disk
    result["fullDiskEncryptionRequested"] = full_disk_encryption
    result["nativeInstallerAgentVerified"] = False
    return result

def assess_popos_lifecycle(evidence: dict) -> dict:
    gates = ('source-authenticity', 'windows-preflight', 'install', 'linux-first-boot', 'windows-return', 'linux-update-reboot', 'uninstall-windows-integrity', 'fault-injection-rollback')
    missingGates = sorted([name for name in gates if evidence.get(name) is not True])
    return {'backend': 'popos', 'missingGates': missingGates, 'installationAuthorized': False, 'releaseEligible': False}
