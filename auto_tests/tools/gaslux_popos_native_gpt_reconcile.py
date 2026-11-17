#!/usr/bin/env python3
"""Read-only GPT reconciliation for a disposable, Linux-only Pop!_OS VM.

Installed-system boot is accepted only when the guest's root PARTUUID agrees
with a separate host inspection of the installed image. Never authorizes
Windows-shared disk operations, installation or production deployment.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
import uuid
from pathlib import Path

from gaslux_popos_gpt_ownership import (
    DISK_SIZE,
    ROOT_FIRST,
    ROOT_LAST,
    SECTOR_SIZE,
    GptRefusal,
    _header,
    _root_entry,
)

ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").bytes_le.hex()
ROOT_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le.hex()
EMPTY_ENTRY = "00" * 128


def capture_linux_only(image: Path) -> dict:
    """Inspect both GPT copies, with CRC checks, on an isolated QEMU file."""
    if (
        image.name != "pop-target.raw"
        or re.fullmatch(r"gaslux-pop-native-full-[A-Za-z0-9]+", image.parent.name) is None
        or image.is_symlink()
        or image.parent.is_symlink()
    ):
        raise GptRefusal("Not an isolated, named Pop native QEMU disk image")
    st = image.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size != DISK_SIZE:
        raise GptRefusal("Unexpected isolated Pop disk image type or capacity")
    with image.open("rb") as disk:
        mbr = disk.read(SECTOR_SIZE)
        primary, entries = _header(disk, 1)
        backup, backup_entries = _header(disk, DISK_SIZE // SECTOR_SIZE - 1)
    if len(mbr) != SECTOR_SIZE or mbr[510:512] != b"\x55\xaa" or mbr[450] != 0xEE:
        raise GptRefusal("Invalid protective MBR")
    last_lba = DISK_SIZE // SECTOR_SIZE - 1
    if (
        primary["current"] != 1
        or primary["alternate"] != last_lba
        or primary["entriesLba"] != 2
        or backup["current"] != last_lba
        or backup["alternate"] != 1
        or backup["entriesLba"] != last_lba - 32
        or primary["diskGuid"] == "00" * 16
        or primary["diskGuid"] != backup["diskGuid"]
        or primary["firstUsable"] != backup["firstUsable"]
        or primary["lastUsable"] != backup["lastUsable"]
        or entries != backup_entries
    ):
        raise GptRefusal("Primary and backup GPT topology or disk identity disagree")
    return {
        "mbrSha256": hashlib.sha256(mbr).hexdigest(),
        "primary": primary,
        "backup": backup,
        "entries": [entries[n : n + 128].hex() for n in range(0, len(entries), 128)],
    }


def _validate_owned_entries(rows: list[str], *, installed: bool) -> dict:
    if type(rows) is not list or len(rows) != 128:
        raise GptRefusal("Unexpected GPT partition count")
    if any(row != EMPTY_ENTRY for row in rows[2:]):
        raise GptRefusal("Unexpected foreign partition in Linux-only target")
    esp = _root_entry(rows[0])
    root = _root_entry(rows[1])
    if (
        esp["type"] != ESP_TYPE
        or esp["first"] != 2048
        or esp["last"] != ROOT_FIRST - 1
        or esp["name"] != "GASLUX-OWNED-ESP"
        or esp["attrs"] != 0
        or esp["guid"] == "00000000-0000-0000-0000-000000000000"
    ):
        raise GptRefusal("Owned VM ESP identity or geometry mismatch")
    allowed_root_last = (ROOT_LAST, ROOT_LAST - 1) if installed else (ROOT_LAST,)
    allowed_root_names = ("GASLUX-OWNED-ROOT", "") if installed else ("GASLUX-OWNED-ROOT",)
    if (
        root["type"] != ROOT_TYPE
        or root["first"] != ROOT_FIRST
        or root["last"] not in allowed_root_last
        or root["attrs"] != 0
        or root["name"] not in allowed_root_names
        or root["guid"] == "00000000-0000-0000-0000-000000000000"
    ):
        raise GptRefusal("Owned VM Linux root identity or geometry mismatch")
    return root


def reconcile_linux_only(before: dict, after: dict) -> dict:
    """Allow only observed native mutations of the transaction-owned root."""
    expected = {"mbrSha256", "primary", "backup", "entries"}
    if (
        type(before) is not dict
        or type(after) is not dict
        or set(before) != expected
        or set(after) != expected
    ):
        raise GptRefusal("Unexpected GPT evidence structure")
    if before["mbrSha256"] != after["mbrSha256"]:
        raise GptRefusal("Protective MBR changed")
    if before["primary"] != after["primary"] or before["backup"] != after["backup"]:
        raise GptRefusal("GPT disk identity, geometry or array location changed")
    original, installed = before["entries"], after["entries"]
    prior_root = _validate_owned_entries(original, installed=False)
    final_root = _validate_owned_entries(installed, installed=True)
    if original[0] != installed[0] or original[2:] != installed[2:]:
        raise GptRefusal("Native installer changed non-root GPT entries")
    return {
        "ownedEspGptEntryIdentical": True,
        "otherGptEntriesIdentical": True,
        "protectiveMbrIdentical": True,
        "diskGuidAndGeometryIdentical": True,
        "rootPartuuidBefore": prior_root["guid"],
        "rootPartuuidAfter": final_root["guid"],
        "rootLastLbaBefore": prior_root["last"],
        "rootLastLbaAfter": final_root["last"],
        "requiresPostInstallPlanReconciliation": prior_root != final_root,
        "productionInstallationAuthorized": False,
        "windowsDualBootProven": False,
    }


def main(args: list[str]) -> int:
    if len(args) == 3 and args[0] == "capture":
        image, dest = map(Path, args[1:])
        if dest.parent != image.parent or dest.name not in (
            "owned-gpt-before.json",
            "owned-gpt-after.json",
        ):
            raise GptRefusal("Refuse GPT evidence outside the VM temporary directory")
        dest.write_text(
            json.dumps(capture_linux_only(image), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0
    if len(args) == 3 and args[0] == "verify":
        old, new = map(Path, args[1:])
        if old.parent != new.parent or (old.name, new.name) != (
            "owned-gpt-before.json",
            "owned-gpt-after.json",
        ):
            raise GptRefusal("Unexpected GPT evidence filenames")
        proof = reconcile_linux_only(
            json.loads(old.read_text(encoding="utf-8")),
            json.loads(new.read_text(encoding="utf-8")),
        )
        print("GASLUX_POP_NATIVE_LINUXONLY_GPT_VERIFIED=1")
        print(json.dumps(proof, sort_keys=True))
        return 0
    raise GptRefusal("Usage: capture pop-target.raw owned-gpt-*.json | verify before after")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (GptRefusal, OSError, TypeError, ValueError, KeyError, UnicodeError) as error:
        print(f"GASLUX_POP_NATIVE_GPT_REFUSAL: {error}", file=sys.stderr)
        sys.exit(1)
