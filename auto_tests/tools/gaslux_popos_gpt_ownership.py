#!/usr/bin/env python3
"""VM-only GPT ownership auditor for a disposable mock-Windows/Pop target.

Read-only parser: validates GPT CRCs, both partition arrays and byte-identity
of every non-owned partition entry. Does not authorize production disk writes.
"""

from __future__ import annotations

import hashlib
import json
import stat
import struct
import sys
import uuid
import zlib
from pathlib import Path

SECTOR_SIZE = 512
DISK_SIZE = 32 * 1024**3
HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
ROOT_INDEX = 2
ROOT_FIRST = 2099200
ROOT_LAST = 60819455


class GptRefusal(ValueError):
    """Unsafe or unverified GPT modification in the disposable lab."""


def _header(disk, lba: int) -> tuple[dict, bytes]:
    disk.seek(lba * SECTOR_SIZE)
    sector = disk.read(SECTOR_SIZE)
    if len(sector) != SECTOR_SIZE:
        raise GptRefusal("Truncated GPT header")
    (
        signature,
        revision,
        size,
        checksum,
        reserved,
        current,
        alternate,
        first,
        last,
        disk_guid,
        entries_lba,
        count,
        entry_size,
        entries_crc,
    ) = HEADER.unpack_from(sector)
    if (
        signature != b"EFI PART"
        or revision != 0x00010000
        or size != 92
        or reserved != 0
        or entry_size != 128
        or count != 128
    ):
        raise GptRefusal("Unexpected GPT format or unsupported entry count")
    test = bytearray(sector[:size])
    struct.pack_into("<I", test, 16, 0)
    if zlib.crc32(test) != checksum:
        raise GptRefusal("Invalid GPT header CRC")
    if not (2 <= entries_lba <= DISK_SIZE // SECTOR_SIZE - 33):
        raise GptRefusal("GPT partition array outside disk")
    disk.seek(entries_lba * SECTOR_SIZE)
    entries = disk.read(count * entry_size)
    if len(entries) != count * entry_size or zlib.crc32(entries) != entries_crc:
        raise GptRefusal("Invalid GPT partition array CRC")
    fields = {
        "revision": revision,
        "size": size,
        "current": current,
        "alternate": alternate,
        "firstUsable": first,
        "lastUsable": last,
        "diskGuid": disk_guid.hex(),
        "entriesLba": entries_lba,
        "entryCount": count,
        "entrySize": entry_size,
    }
    return fields, entries


def snapshot(path: Path) -> dict:
    if (
        path.name != "pop-target.raw"
        or not path.parent.name.startswith("gaslux-candidate-live-")
        or path.is_symlink()
    ):
        raise GptRefusal("Only a named disposable QEMU image may be read")
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or path.stat().st_size != DISK_SIZE:
        raise GptRefusal("Incorrect synthetic disk type or size")
    with path.open("rb") as disk:
        mbr = disk.read(SECTOR_SIZE)
        primary, primary_entries = _header(disk, 1)
        backup, backup_entries = _header(disk, DISK_SIZE // SECTOR_SIZE - 1)
    if (
        primary["current"] != 1
        or backup["current"] != DISK_SIZE // SECTOR_SIZE - 1
        or primary["alternate"] != backup["current"]
        or backup["alternate"] != primary["current"]
        or primary["diskGuid"] != backup["diskGuid"]
        or primary["firstUsable"] != backup["firstUsable"]
        or primary["lastUsable"] != backup["lastUsable"]
        or primary_entries != backup_entries
    ):
        raise GptRefusal("GPT primary/backup disagree")
    return {
        "mbrSha256": hashlib.sha256(mbr).hexdigest(),
        "primary": primary,
        "backup": backup,
        "entries": [
            primary_entries[index : index + 128].hex()
            for index in range(0, len(primary_entries), 128)
        ],
    }


def _root_entry(value: str) -> dict:
    entry = bytes.fromhex(value)
    if len(entry) != 128:
        raise GptRefusal("Invalid owned root partition entry")
    kind, partition_guid, first, last, attrs = struct.unpack_from("<16s16sQQQ", entry)
    return {
        "type": kind.hex(),
        "guid": str(uuid.UUID(bytes_le=partition_guid)),
        "first": first,
        "last": last,
        "attrs": attrs,
        "name": entry[56:128].decode("utf-16-le").split("\x00", 1)[0],
    }


def validate_delta(before: dict, after: dict) -> dict:
    if set(before) != {"mbrSha256", "primary", "backup", "entries"} or set(after) != set(before):
        raise GptRefusal("Missing or extra GPT evidence fields")
    if before["mbrSha256"] != after["mbrSha256"]:
        raise GptRefusal("Protective Windows MBR changed")
    for key in ("primary", "backup"):
        if before[key] != after[key]:
            raise GptRefusal("GPT disk identity, geometry or header topology changed")
    old_entries, new_entries = before["entries"], after["entries"]
    if len(old_entries) != 128 or len(new_entries) != 128:
        raise GptRefusal("Unexpected GPT entry count")
    for index, (old, new) in enumerate(zip(old_entries, new_entries, strict=True)):
        if index != ROOT_INDEX and old != new:
            raise GptRefusal(f"Foreign GPT entry {index + 1} changed")
    old_root = _root_entry(old_entries[ROOT_INDEX])
    new_root = _root_entry(new_entries[ROOT_INDEX])
    if (
        old_root["first"] != ROOT_FIRST
        or old_root["last"] != ROOT_LAST
        or new_root["first"] != ROOT_FIRST
        or new_root["last"] not in (ROOT_LAST, ROOT_LAST - 1)
        or old_root["name"] != "GASLUX-OWNED-ROOT"
        or new_root["name"] not in ("GASLUX-OWNED-ROOT", "")
        or new_root["type"] != old_root["type"]
        or new_root["attrs"] != old_root["attrs"]
        or new_root["guid"] == "00000000-0000-0000-0000-000000000000"
    ):
        raise GptRefusal("Owned root GPT change exceeds strict lab allowance")
    return {
        "foreignEntriesByteIdentical": True,
        "protectiveMbrIdentical": True,
        "diskGuidAndGeometryIdentical": True,
        "rootPartuuidBefore": old_root["guid"],
        "rootPartuuidAfter": new_root["guid"],
        "rootEndSectorBefore": old_root["last"],
        "rootEndSectorAfter": new_root["last"],
        "requiresPostCommitPlanRevalidation": old_root != new_root,
        "productionInstallationAuthorized": False,
    }


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "capture":
        image, output = map(Path, sys.argv[2:])
        if output.parent != image.parent or output.suffix != ".json":
            raise GptRefusal("Snapshot must stay in the temporary VM directory")
        result = snapshot(image)
        output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "verify":
        before, after = (
            json.loads(Path(name).read_text(encoding="utf-8")) for name in sys.argv[2:]
        )
        proof = validate_delta(before, after)
        print("GASLUX_POP_VM_PROTECTED_GPT_ENTRIES_IDENTICAL=1")
        print(json.dumps(proof, sort_keys=True))
        return 0
    raise GptRefusal("Usage: capture image snapshot.json | verify before.json after.json")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (GptRefusal, ValueError, KeyError, OSError, UnicodeError, TypeError) as exc:
        print(f"GASLUX_POP_GPT_VM_REFUSAL: {exc}", file=sys.stderr)
        sys.exit(1)
