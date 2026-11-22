#!/usr/bin/env python3
"""Offline, deny-only Pop/Windows EFI consistency.

Untrusted claims, NO boot attestation or disk writes.
"""

from __future__ import annotations

import re

GUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
ENTRY = re.compile(r"[0-9a-fA-F]{4}\Z")
MS_PREFIX = "EFI/Microsoft/"
WIN_LOADER = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
POP_LOADER = "\\EFI\\systemd\\systemd-bootx64.efi"


class BootGateRefusal(ValueError):
    """EFI inventory incomplete or inconsistent."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise BootGateRefusal("POP_EFI_REFUSED: " + reason)


def _guid(value: object) -> bool:
    return type(value) is str and GUID.fullmatch(value) is not None


def _validate(state: dict) -> None:
    need(
        type(state) is dict
        and set(state)
        == {
            "windowsEspPartuuid",
            "popEspPartuuid",
            "microsoftFiles",
            "bootEntries",
            "bootOrder",
            "bootNext",
        },
        "incomplete EFI/firmware snapshot",
    )
    need(
        _guid(state["windowsEspPartuuid"]) and _guid(state["popEspPartuuid"]),
        "invalid ESP PARTUUID",
    )
    files = state["microsoftFiles"]
    need(type(files) is dict and 0 < len(files) <= 50000, "EFI/Microsoft inventory missing")
    need(
        all(
            type(p) is str
            and p.startswith(MS_PREFIX)
            and ".." not in p.split("/")
            and "\\" not in p
            and "//" not in p
            and "\x00" not in p
            and type(h) is str
            and SHA.fullmatch(h) is not None
            for p, h in files.items()
        ),
        "malformed Microsoft file inventory",
    )
    need(
        {MS_PREFIX + "Boot/BCD", MS_PREFIX + "Boot/bootmgfw.efi"} <= set(files)
        and len({p.casefold() for p in files}) == len(files),
        "Windows BCD/loader missing or Microsoft path collision",
    )
    entries = state["bootEntries"]
    need(type(entries) is dict and 1 <= len(entries) <= 64, "invalid Boot#### inventory")
    for key, entry in entries.items():
        need(
            type(key) is str
            and ENTRY.fullmatch(key) is not None
            and type(entry) is dict
            and set(entry) == {"espPartuuid", "loaderPath"}
            and _guid(entry["espPartuuid"])
            and type(entry["loaderPath"]) is str
            and entry["loaderPath"].startswith("\\EFI\\")
            and ".." not in entry["loaderPath"]
            and "\x00" not in entry["loaderPath"],
            "malformed Boot#### entry",
        )
    order = state["bootOrder"]
    need(
        type(order) is list
        and len(order) == len(set(order))
        and len(order) <= len(entries)
        and all(type(k) is str and k in entries for k in order),
        "BootOrder missing/foreign/duplicated entry",
    )
    need(
        state["bootNext"] is None
        or (type(state["bootNext"]) is str and state["bootNext"] in entries),
        "BootNext references unknown entry",
    )


def assess_efi_boot_chain(before: dict, after: dict, *, topology: str) -> dict:
    """Require both explicit firmware entries; never assume systemd-boot discovers Windows."""
    need(topology in ("shared", "separate"), "unsupported ESP topology")
    _validate(before)
    _validate(after)
    win, pop = after["windowsEspPartuuid"], after["popEspPartuuid"]
    need(
        win == before["windowsEspPartuuid"] and pop == before["popEspPartuuid"],
        "ESP PARTUUID drift",
    )
    need((win == pop) == (topology == "shared"), "ESP topology mismatch")
    need(
        before["microsoftFiles"] == after["microsoftFiles"],
        "EFI/Microsoft added, deleted, or changed",
    )

    def matching(state: dict, partuuid: str, loader: str) -> set[str]:
        return {
            key
            for key, item in state["bootEntries"].items()
            if item["espPartuuid"] == partuuid
            and item["loaderPath"].casefold() == loader.casefold()
        }

    old_windows = matching(before, win, WIN_LOADER)
    new_windows = matching(after, win, WIN_LOADER)
    new_pop = matching(after, pop, POP_LOADER)
    need(
        len(old_windows) == 1 and old_windows == new_windows,
        "Windows firmware entry absent or replaced",
    )
    windows_id = next(iter(old_windows))
    need(
        before["bootEntries"][windows_id] == after["bootEntries"][windows_id],
        "Windows Boot#### changed",
    )
    need(len(new_pop) == 1 and windows_id not in new_pop, "Pop firmware entry absent")
    pop_id = next(iter(new_pop))
    need(
        windows_id in before["bootOrder"]
        and windows_id in after["bootOrder"]
        and pop_id in after["bootOrder"],
        "BootOrder does not preserve both loaders",
    )
    need(before["bootNext"] == after["bootNext"], "BootNext changed")
    return {
        "topology": topology,
        "windowsEntryId": windows_id,
        "popEntryId": pop_id,
        "microsoftFileCount": len(after["microsoftFiles"]),
        "offlineConsistencyChecksPassed": True,
        "externalMeasurementsAuthenticated": False,
        "systemdBootWindowsAutodiscoveryAssumed": False,
        "windowsBootProven": False,
        "popBootProven": False,
        "dualBootProven": False,
        "rollbackVerified": False,
        "distinstExecutionAuthorized": False,
        "productionInstallationAuthorized": False,
    }
