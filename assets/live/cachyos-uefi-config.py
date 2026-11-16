#!/usr/bin/env python3
"""Render CachyOS UEFI boot configuration without writing to disk.

This is a pure-data laboratory component. It is NOT used by the production
Libertix installer and does NOT register EFI NVRAM entries or modify partitions.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

_UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
_VFAT_UUID = re.compile(r"^[0-9A-F]{4}-[0-9A-F]{4}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9_-]{12,100}$")
_GFX = re.compile(r"^[0-9]{3,5}x[0-9]{3,5}$")
_REQUIRED = frozenset({
    "version", "firmware", "secureBootEnabled", "runId", "rootUuid",
    "espUuid", "windowsBootUuid", "linuxLabel", "grubResolution",
})


class PlanError(ValueError):
    """Invalid or unsafe lab boot configuration input."""


def _strict_string(data: dict[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    value = data[key]
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PlanError("invalid " + key)
    return value


def render(plan: dict[str, Any]) -> dict[str, str]:
    """Validate an already verified lab transaction and generate text only."""
    if not isinstance(plan, dict) or set(plan) != _REQUIRED:
        raise PlanError("unexpected or missing plan fields")
    if type(plan["version"]) is not int or plan["version"] != 1:
        raise PlanError("invalid plan version")
    if plan["firmware"] != "uefi" or plan["secureBootEnabled"] is not False:
        raise PlanError("CachyOS stage only permits UEFI with Secure Boot disabled")

    run_id = _strict_string(plan, "runId", _RUN_ID)
    root_uuid = _strict_string(plan, "rootUuid", _UUID)
    esp_uuid = _strict_string(plan, "espUuid", _VFAT_UUID)
    windows_boot_uuid = _strict_string(plan, "windowsBootUuid", _VFAT_UUID)
    label = _strict_string(
        plan, "linuxLabel", re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,64}$")
    )
    resolution = _strict_string(plan, "grubResolution", _GFX)
    if esp_uuid != windows_boot_uuid:
        # Initial support requires a shared, verified Windows ESP. Do not guess
        # a second ESP or chainload from a different volume.
        raise PlanError("Windows Boot Manager and Linux must share the recorded ESP")
    fstab = (
        "# Gaslux CachyOS UEFI lab; transaction " + run_id + "\n"
        + "UUID=" + root_uuid + " / ext4 defaults 0 1\n"
        + "UUID=" + esp_uuid + " /boot/efi vfat umask=0077 0 2\n"
    )
    defaults = (
        "# Gaslux CachyOS UEFI lab; transaction " + run_id + "\n"
        + "GRUB_TIMEOUT_STYLE=menu\n"
        + "GRUB_TIMEOUT=10\n"
        + "GRUB_DISABLE_OS_PROBER=true\n"
        + "GRUB_GFXMODE=" + resolution + ",auto\n"
    )
    # Fixed, non-interpolated GRUB identifiers; no data is permitted to inject
    # special GRUB syntax, shell substitutions, or newline characters.
    windows_entry = (
        "# Gaslux CachyOS UEFI lab; transaction " + run_id + "\n"
        + 'menuentry "Windows Boot Manager" --class windows --id gaslux-windows {\n'
        + "    insmod part_gpt\n"
        + "    insmod fat\n"
        + "    search --no-floppy --fs-uuid --set=root " + windows_boot_uuid + "\n"
        + "    chainloader /EFI/Microsoft/Boot/bootmgfw.efi\n"
        + "}\n"
    )
    return {
        "fstab": fstab,
        "grubDefaults": defaults,
        "windowsGrubEntry": windows_entry,
        "bootloaderId": "Gaslux-CachyOS",
        "linuxDisplayName": label,
        "releaseSafe": "false",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan_file", help="JSON plan from an independently validated lab transaction")
    options = parser.parse_args(argv)
    try:
        with open(options.plan_file, encoding="utf-8") as stream:
            plan = json.load(stream)
        result = render(plan)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
