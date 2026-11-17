#!/usr/bin/env python3
"""Host-side, read-only protection proof for mock Windows volumes in QEMU.

Requires two independent, whole-partition SHA-256 snapshots + strict GPT
ownership invariants before/after native System76 installation and first boot.
These are MOCK volumes, never real Windows, and never production authorization.
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
    SECTOR_SIZE,
    GptRefusal,
    _header,
    _root_entry,
)

ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").bytes_le.hex()
NTFS_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le.hex()
ROOT_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le.hex()
BLANK = "00" * 128
# Sector offsets and sizes verified both in host setup and in live guest.
WINDOWS_ESP_START, WINDOWS_ESP_END = 2048, 526335
WINDOWS_NTFS_START, WINDOWS_NTFS_END = 526336, 4720639
POP_ESP_START, POP_ESP_END = 4720640, 6817791
POP_ROOT_START, POP_ROOT_END = 6817792, 61343743


def _partition_sha256(disk, start: int, end: int) -> str:
    disk.seek(start * SECTOR_SIZE)
    remaining = (end - start + 1) * SECTOR_SIZE
    result = hashlib.sha256()
    while remaining:
        block = disk.read(min(4 * 1024 * 1024, remaining))
        if not block:
            raise GptRefusal("Truncated protected mock Windows volume")
        result.update(block)
        remaining -= len(block)
    return result.hexdigest()


def capture_mock_windows(image: Path) -> dict:
    if (
        image.name != "pop-target.raw"
        or re.fullmatch(r"gaslux-pop-native-mock-[A-Za-z0-9]+", image.parent.name) is None
        or image.is_symlink()
        or image.parent.is_symlink()
    ):
        raise GptRefusal("Not an isolated mock Windows QEMU target file")
    st = image.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size != DISK_SIZE:
        raise GptRefusal("Unexpected mock Windows target type/size")
    with image.open("rb") as disk:
        mbr = disk.read(SECTOR_SIZE)
        primary, entries = _header(disk, 1)
        backup, backup_entries = _header(disk, DISK_SIZE // SECTOR_SIZE - 1)
        windows_esp_hash = _partition_sha256(disk, WINDOWS_ESP_START, WINDOWS_ESP_END)
        windows_ntfs_hash = _partition_sha256(disk, WINDOWS_NTFS_START, WINDOWS_NTFS_END)
    last_lba = DISK_SIZE // SECTOR_SIZE - 1
    if (
        len(mbr) != SECTOR_SIZE
        or mbr[510:512] != b"\\x55\\xaa"
        or mbr[450] != 0xEE
        or primary["current"] != 1
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
        raise GptRefusal("Invalid protective MBR or disagreeing GPT mirrors")
    return {
        "mbrSha256": hashlib.sha256(mbr).hexdigest(),
        "primary": primary,
        "backup": backup,
        "entries": [entries[n : n + 128].hex() for n in range(0, len(entries), 128)],
        "mockWindowsEspSha256": windows_esp_hash,
        "mockWindowsNtfsSha256": windows_ntfs_hash,
    }


def _validate_entries(rows: list[str], *, installed: bool) -> dict:
    if type(rows) is not list or len(rows) != 128 or any(row != BLANK for row in rows[4:]):
        raise GptRefusal("Unexpected GPT entry count or foreign partitions")
    specs = (
        (ESP_TYPE, WINDOWS_ESP_START, WINDOWS_ESP_END, "MOCK-WINDOWS-ESP"),
        (NTFS_TYPE, WINDOWS_NTFS_START, WINDOWS_NTFS_END, "MOCK-WINDOWS-NTFS"),
        (ESP_TYPE, POP_ESP_START, POP_ESP_END, "GASLUX-OWNED-ESP"),
    )
    for index, (kind, first, last, name) in enumerate(specs):
        row = _root_entry(rows[index])
        if (
            row["type"] != kind
            or row["first"] != first
            or row["last"] != last
            or row["name"] != name
            or row["attrs"] != 0
            or row["guid"] == "00000000-0000-0000-0000-000000000000"
        ):
            raise GptRefusal(f"Unexpected mock Windows/owned ESP partition {index + 1}")
    root = _root_entry(rows[3])
    if (
        root["type"] != ROOT_TYPE
        or root["first"] != POP_ROOT_START
        or root["last"] not in ((POP_ROOT_END, POP_ROOT_END - 1) if installed else (POP_ROOT_END,))
        or root["name"] not in (("GASLUX-OWNED-ROOT", "") if installed else ("GASLUX-OWNED-ROOT",))
        or root["attrs"] != 0
        or root["guid"] == "00000000-0000-0000-0000-000000000000"
    ):
        raise GptRefusal("Unowned native Pop root mutation")
    return root


def reconcile_mock_windows(before: dict, after: dict) -> dict:
    required = {
        "mbrSha256", "primary", "backup", "entries",
        "mockWindowsEspSha256", "mockWindowsNtfsSha256",
    }
    if type(before) is not dict or type(after) is not dict or set(before) != required or set(after) != required:
        raise GptRefusal("Unexpected evidence format")
    if before["mbrSha256"] != after["mbrSha256"]:
        raise GptRefusal("Protective MBR changed")
    if before["primary"] != after["primary"] or before["backup"] != after["backup"]:
        raise GptRefusal("GPT header, disk GUID or array topology changed")
    old_root = _validate_entries(before["entries"], installed=False)
    new_root = _validate_entries(after["entries"], installed=True)
    if before["entries"][:3] != after["entries"][:3] or before["entries"][4:] != after["entries"][4:]:
        raise GptRefusal("Mock Windows or owned ESP GPT entry changed")
    for key in ("mockWindowsEspSha256", "mockWindowsNtfsSha256"):
        if not re.fullmatch(r"[a-f0-9]{64}", before[key]) or before[key] != after[key]:
            raise GptRefusal(f"Protected mock Windows bytes changed: {key}")
    return {
        "mockWindowsEspBytesIdentical": True,
        "mockWindowsNtfsBytesIdentical": True,
        "mockWindowsGptEntriesIdentical": True,
        "ownedPopEspGptEntryIdentical": True,
        "protectiveMbrIdentical": True,
        "rootPartuuidBefore": old_root["guid"],
        "rootPartuuidAfter": new_root["guid"],
        "requiresPostInstallPlanReconciliation": old_root != new_root,
        "productionInstallationAuthorized": False,
        "windowsDualBootProven": False,
    }


def main(args: list[str]) -> int:
    if len(args) == 3 and args[0] == "capture":
        image, output = map(Path, args[1:])
        if output.parent != image.parent or output.name not in {
            "owned-gpt-before.json", "owned-gpt-after.json", "owned-gpt-postboot.json",
        }:
            raise GptRefusal("Mock volume snapshots must remain in VM temp directory")
        output.write_text(json.dumps(capture_mock_windows(image), sort_keys=True) + "\\n", encoding="utf-8")
        return 0
    if len(args) == 3 and args[0] == "verify":
        old, new = map(Path, args[1:])
        if old.parent != new.parent or old.name != "owned-gpt-before.json" or new.name not in {
            "owned-gpt-after.json", "owned-gpt-postboot.json",
        }:
            raise GptRefusal("Unexpected mock Windows proof files")
        proof = reconcile_mock_windows(
            json.loads(old.read_text(encoding="utf-8")),
            json.loads(new.read_text(encoding="utf-8")),
        )
        print("GASLUX_POP_NATIVE_MOCK_WINDOWS_GPT_VERIFIED=1")
        print(json.dumps(proof, sort_keys=True))
        return 0
    raise GptRefusal("Usage: capture image evidence.json | verify before.json after.json")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (GptRefusal, OSError, TypeError, ValueError, KeyError, UnicodeError) as error:
        print(f"GASLUX_POP_MOCK_WINDOWS_GPT_REFUSAL: {error}", file=sys.stderr)
        sys.exit(1)
