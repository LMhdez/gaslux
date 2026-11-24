#!/usr/bin/env python3
"""Bazzite Fedora Atomic diagnostic; never starts Anaconda or touches storage."""

from __future__ import annotations

from gaslux_lab_media_probe import ProbeRefusal, diagnostic, read_os_release_evidence

ATOMIC_BOOTLOADERS = {"uefi/gpt": "grub"}
POTENTIAL_OS_RELEASE_IDS = frozenset({"fedora", "bazzite"})


def probe_bazzite(
    *,
    iso_path: str,
    iso_size: int,
    iso_sha256: str,
    os_release_path: str,
    firmware: str,
    partition_style: str,
    secure_boot_enabled: bool,
    bootloader: str,
    ram_mib: int,
    target_disk_gib: int,
    target_root_fs: str,
    installer_kind: str,
) -> dict:
    """Fail closed before image I/O on BIOS/MBR, encryption and resource issues.

    Bazzite may identify as Fedora in os-release; do not conflate this with
    a signed image identity. The separate Atomic installer must prove its
    edition, bootc/OSTree deployment and boot chain before any release.
    """
    if firmware != "uefi" or partition_style != "gpt":
        raise ProbeRefusal("Bazzite requires UEFI/GPT; BIOS/MBR is unsupported")
    if type(secure_boot_enabled) is not bool:
        raise ProbeRefusal("Secure Boot state must be measured")
    if secure_boot_enabled:
        raise ProbeRefusal("Unattended MOK key enrollment is not supported")
    if (
        type(ram_mib) is not int
        or ram_mib < 8192
        or type(target_disk_gib) is not int
        or target_disk_gib < 50
    ):
        raise ProbeRefusal("Bazzite laboratory RAM or disk minimum not met")
    if target_root_fs != "btrfs" or installer_kind != "fedora-atomic-native":
        raise ProbeRefusal("Bazzite needs native Atomic installation with a Btrfs root")

    identity = read_os_release_evidence(os_release_path)
    if identity["ID"] not in POTENTIAL_OS_RELEASE_IDS or "Bazzite" not in identity.get(
        "PRETTY_NAME", ""
    ):
        raise ProbeRefusal("Unverified Fedora/Bazzite identity")
    result = diagnostic(
        iso_path=iso_path,
        expected_size=iso_size,
        expected_sha256=iso_sha256,
        os_release_path=os_release_path,
        expected_os_id=identity["ID"],
        firmware=firmware,
        partition_style=partition_style,
        secure_boot_enabled=secure_boot_enabled,
        bootloader=bootloader,
        backend="fedora-atomic",
        allowed_modes=ATOMIC_BOOTLOADERS,
    )
    result["atomicDeploymentVerified"] = False
    result["nativeInstallerVerified"] = False
    result["manualKeyEnrollmentSupported"] = False
    return result


def assess_bazzite_lifecycle(evidence: dict) -> dict:
    gates = (
        "source-authenticity",
        "windows-preflight",
        "install",
        "linux-first-boot",
        "windows-return",
        "linux-update-reboot",
        "uninstall-windows-integrity",
        "fault-injection-rollback",
    )
    missingGates = sorted([name for name in gates if evidence.get(name) is not True])
    return {
        "backend": "bazzite",
        "missingGates": missingGates,
        "installationAuthorized": False,
        "releaseEligible": False,
    }
