"""Read-only capability assertions shared by experimental live backend validators.

A capability object is not an authorization. Only a verified, signed v2
catalogue may supply it. Legacy installation plans remain restricted to
Mint/Zorin by the independent plan validators.
"""

from __future__ import annotations


class CapabilityError(ValueError):
    """The signed metadata describes an unsupported installation backend."""


def validate_capabilities(distribution_id: str, os_release_id: str, cap: object) -> bool:
    """Validate v1 capability semantics, returning whether dispatch is released."""
    expected_keys = {
        "version",
        "backend",
        "source",
        "firmwareLayouts",
        "secureBoot",
        "bootloader",
        "status",
        "minimumRamMiB",
        "minimumDiskGiB",
    }
    profiles = {
        ("mint", "linuxmint"): ("debian-squashfs", "casper-squashfs", "ms-shim", "grub", "grub"),
        ("zorin", "zorin"): ("debian-squashfs", "casper-squashfs", "ms-shim", "grub", "grub"),
        ("cachyos", "cachyos"): ("archiso-cachyos", "archiso", "unsupported", "grub", "grub"),
        ("popos", "pop"): ("system76", "pop-live", "unsupported", "grub", "systemd-boot"),
        ("q4os", "q4os"): ("q4os-native", "q4os-native-iso", "unsupported", "grub", "grub"),
        ("bazzite", "bazzite"): (
            "fedora-atomic",
            "fedora-atomic-iso",
            "manual-enrollment",
            "none",
            "grub",
        ),
    }
    expected = profiles.get((distribution_id, os_release_id))
    if (
        not isinstance(cap, dict)
        or set(cap) != expected_keys
        or cap["version"] != 1
        or not expected
    ):
        raise CapabilityError("unknown identity or invalid capability shape")
    boot = cap["bootloader"]
    if not isinstance(boot, dict) or set(boot) != {"bios", "uefi"}:
        raise CapabilityError("invalid bootloader declaration")
    if (cap["backend"], cap["source"], cap["secureBoot"], boot["bios"], boot["uefi"]) != expected:
        raise CapabilityError("backend, source or bootloader mismatch")
    layouts = cap["firmwareLayouts"]
    if (
        not isinstance(layouts, list)
        or not 1 <= len(layouts) <= 2
        or any(x not in {"bios/mbr", "uefi/gpt"} for x in layouts)
        or len(layouts) != len(set(layouts))
        or ("bios/mbr" in layouts and boot["bios"] == "none")
        or ("uefi/gpt" in layouts and boot["uefi"] == "none")
        or (distribution_id == "bazzite" and layouts != ["uefi/gpt"])
        or (distribution_id in {"mint", "zorin"} and layouts != ["bios/mbr", "uefi/gpt"])
    ):
        raise CapabilityError("unsupported firmware/partition combination")
    if cap["status"] not in {"released", "lab-only", "unavailable"}:
        raise CapabilityError("invalid status")
    for key, minimum in (("minimumRamMiB", 1024), ("minimumDiskGiB", 20)):
        value = cap[key]
        if type(value) is not int or value < minimum:
            raise CapabilityError(f"invalid {key}")
    if distribution_id == "bazzite" and cap["minimumDiskGiB"] < 50:
        raise CapabilityError("Bazzite requires at least 50 GiB metadata")
    if cap["status"] == "released" and distribution_id not in {"mint", "zorin"}:
        raise CapabilityError("experimental backend cannot be released")
    return cap["status"] == "released"


def assess_mint_lifecycle(evidence: dict) -> dict:
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
        "backend": "mint",
        "missingGates": missingGates,
        "installationAuthorized": False,
        "releaseEligible": False,
    }
