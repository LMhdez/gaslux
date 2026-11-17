#!/usr/bin/env python3
"""Independent primary/backup GPT CRC and ownership gate for Windows+Pop COW lab.

The bounded QEMU image-window method and strict header checks reuse the
validated experimental approach from Gaslux PR #122 (Windows/CachyOS).
This variant accepts exactly four original Windows partitions, then exactly
those same four plus one owned *unformatted* Pop root, without changing ESP.
No real disk, production authorization or Windows boot is inferred.
"""
from __future__ import annotations

import binascii
import hashlib
import json
import re
import struct
import subprocess
import tempfile
import uuid
from pathlib import Path

from windows_x64_installed_gpt_ro_audit import BASIC, ESP, MSR, RECOVERY, DiskAuditError, require

SECTOR = 512
WINDOW_SECTORS = 2048
WINDOW_BYTES = SECTOR * WINDOW_SECTORS
TOTAL_BYTES = 128 * 1024**3
WINDOWS_TYPES = (ESP, MSR, BASIC, RECOVERY)
LINUX_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
PARTITION_ENTRY_BYTES = 128
ROOT_LABEL = "GASLUX-LAB-POP-ROOT"


def _header(window: bytes, offset: int, current: int, alternate: int) -> bytes:
    require(len(window) == WINDOW_BYTES, "missing bounded GPT window")
    raw = window[offset : offset + SECTOR]
    require(
        len(raw) == SECTOR
        and raw[:8] == b"EFI PART"
        and struct.unpack_from("<I", raw, 8)[0] == 0x10000,
        "missing or unsupported GPT header",
    )
    size, checksum, reserved = struct.unpack_from("<III", raw, 12)
    require(size == 92 and reserved == 0, "unsupported GPT header format")
    block = bytearray(raw[:size])
    block[16:20] = b"\0" * 4
    require(
        binascii.crc32(block) & 0xFFFFFFFF == checksum,
        "GPT header CRC mismatch",
    )
    this_lba, other_lba, first_usable, last_usable = struct.unpack_from(
        "<QQQQ", raw, 24,
    )
    total = TOTAL_BYTES // SECTOR
    require(
        this_lba == current
        and other_lba == alternate
        and first_usable == 34
        and last_usable == total - 34
        and raw[56:72] != b"\0" * 16,
        "GPT identity or geometry mismatch",
    )
    return raw


def _array(header: bytes, front: bytes, back: bytes) -> bytes:
    total = TOTAL_BYTES // SECTOR
    lba = struct.unpack_from("<Q", header, 72)[0]
    count, size, crc = struct.unpack_from("<III", header, 80)
    require(count == 128 and size == PARTITION_ENTRY_BYTES,
            "unrecognized GPT entry array")
    if lba == 2:
        array = front[2 * SECTOR : 34 * SECTOR]
    elif lba == total - 33:
        array = back[WINDOW_BYTES - 33 * SECTOR : WINDOW_BYTES - SECTOR]
    else:
        raise DiskAuditError("unexpected GPT entry array position")
    require(
        len(array) == 128 * PARTITION_ENTRY_BYTES
        and binascii.crc32(array) & 0xFFFFFFFF == crc,
        "GPT entry array CRC mismatch",
    )
    return array


def parse_windows_pop_gpt(front: bytes, back: bytes, *, expected_count: int) -> dict:
    """Validate complete GPT mirrors and exact 4-Windows/5-COW-root roles."""
    require(expected_count in (4, 5), "invalid expected GPT stage count")
    total = TOTAL_BYTES // SECTOR
    require(len(front) == WINDOW_BYTES and len(back) == WINDOW_BYTES,
            "truncated GPT windows")
    mbr = front[:SECTOR]
    require(mbr[510:512] == b"\x55\xaa", "invalid protective MBR")
    parts_mbr = [mbr[446 + i * 16 : 462 + i * 16] for i in range(4)]
    start, count = struct.unpack_from("<II", parts_mbr[0], 8)
    protective = (
        parts_mbr[0][0] == 0
        and parts_mbr[0][4] == 0xEE
        and start == 1
        and count == min(total - 1, 0xFFFFFFFF)
        and all(not any(x) for x in parts_mbr[1:])
    )
    if not protective:
        # Only 4 harmless MBR partition-table descriptors, never sector data
        # or Windows bytes. Observe actual Microsoft Setup geometry before
        # deciding whether any narrower compatibility allowance is warranted.
        diagnostic = [
            {
                "slot": i + 1,
                "status": entry[0],
                "type": entry[4],
                "firstLba": struct.unpack_from("<I", entry, 8)[0],
                "sectorCount": struct.unpack_from("<I", entry, 12)[0],
                "nonzero": bool(any(entry)),
            }
            for i, entry in enumerate(parts_mbr)
        ]
        print(
            "GASLUX_POP_PROTECTIVE_MBR_DIAGNOSTIC="
            + json.dumps({"expectedSectorCount": min(total - 1, 0xFFFFFFFF),
                          "slots": diagnostic}, sort_keys=True),
            flush=True,
        )
        raise DiskAuditError("hybrid/nonprotective MBR or foreign partitions")
    p = _header(front, SECTOR, 1, total - 1)
    b = _header(back, WINDOW_BYTES - SECTOR, total - 1, 1)
    require(
        p[56:72] == b[56:72]
        and p[40:56] == b[40:56]
        and p[80:92] == b[80:92],
        "primary and backup GPT identity/geometry mismatch",
    )
    entries = _array(p, front, back)
    require(entries == _array(b, front, back), "GPT entry arrays disagree")
    rows = [entries[n*PARTITION_ENTRY_BYTES : (n+1)*PARTITION_ENTRY_BYTES]
            for n in range(128)]
    require(all(not any(row) for row in rows[expected_count:]),
            "foreign GPT entry after selected Windows/Pop roles")
    if expected_count == 4:
        require(not any(rows[4]), "unexpected fifth partition before Linux stage")
    names: list[str] = []
    found: list[dict] = []
    unique: set[bytes] = set()
    previous_end = 33
    for index, row in enumerate(rows[:expected_count], 1):
        kind = str(uuid.UUID(bytes_le=row[:16]))
        expected_type = WINDOWS_TYPES[index - 1] if index <= 4 else LINUX_TYPE
        unique_id = row[16:32]
        start_lba, end_lba, attrs = struct.unpack_from("<QQQ", row, 32)
        require(
            kind == expected_type
            and unique_id != b"\0" * 16
            and unique_id not in unique
            and start_lba > previous_end
            and start_lba >= 2048
            and start_lba % 2048 == 0
            and start_lba <= end_lba < total - 34,
            "unexpected GPT partition type, GUID or geometry",
        )
        unique.add(unique_id)
        previous_end = end_lba
        name = row[56:128].decode("utf-16-le").split("\0", 1)[0]
        names.append(name)
        if index == 5:
            require(name == ROOT_LABEL and attrs == 0,
                    "foreign Linux root name or GPT attributes")
        found.append({
            "number": index,
            "type": kind,
            "guid": str(uuid.UUID(bytes_le=unique_id)),
            "startLba": start_lba,
            "endLba": end_lba,
            "attrs": attrs,
        })
    return {
        "diskGuid": str(uuid.UUID(bytes_le=p[56:72])),
        "windowsEntryHex": [row.hex() for row in rows[:4]],
        "windowsPartitions": found[:4],
        "linuxRoot": found[4] if expected_count == 5 else None,
        "mbrSha256": hashlib.sha256(mbr).hexdigest(),
        "firstUsableLba": struct.unpack_from("<Q", p, 40)[0],
        "lastUsableLba": struct.unpack_from("<Q", p, 48)[0],
        "primaryAndBackupCrcVerified": True,
        "productionInstallationAuthorized": False,
    }


def capture_owned_qcow2(image: Path, *, expected_count: int) -> dict:
    """Read only a bounded first and last MiB from a caller-validated COW file."""
    require(
        image.is_absolute()
        and image.is_file()
        and not image.is_symlink()
        and image.name in ("only-disposable-windows-target.qcow2",
                           "gaslux-pop-stage.qcow2")
        and re.fullmatch(r"gaslux-win-x64-[a-z0-9_]+", image.parent.name, re.I)
        is not None
        and not image.parent.is_symlink(),
        "untrusted GPT QCOW2 pathname",
    )
    info = json.loads(subprocess.check_output(
        ["qemu-img", "info", "--output=json", str(image)], timeout=30,
    ))
    require(
        info.get("format") == "qcow2"
        and info.get("virtual-size") == TOTAL_BYTES
        and not info.get("encrypted", False),
        "unexpected GPT QCOW2 format or virtual size",
    )
    with tempfile.TemporaryDirectory(
        prefix="gaslux-pop-gpt-readonly-", dir=image.parent,
    ) as temp:
        samples = []
        for filename, start in (
            ("front", 0), ("back", TOTAL_BYTES // SECTOR - WINDOW_SECTORS)
        ):
            dest = Path(temp) / (filename + ".raw")
            args = ["qemu-img", "dd", "-f", "qcow2", "-O", "raw", f"bs={SECTOR}"]
            if start == 0:
                args.append(f"count={WINDOW_SECTORS}")
            args.extend((f"skip={start}", f"if={image}", f"of={dest}"))
            subprocess.run(args, check=True, capture_output=True, timeout=70)
            require(dest.is_file() and dest.stat().st_size == WINDOW_BYTES,
                    "incorrect bounded QEMU GPT extraction")
            samples.append(dest.read_bytes())
    return parse_windows_pop_gpt(*samples, expected_count=expected_count)


def reconcile_windows_and_root(before: dict, after: dict, plan: dict) -> None:
    require(
        before["primaryAndBackupCrcVerified"]
        and after["primaryAndBackupCrcVerified"]
        and before["linuxRoot"] is None
        and after["linuxRoot"] is not None,
        "GPT stage snapshot omitted or invalid",
    )
    for key in (
        "diskGuid", "windowsEntryHex", "windowsPartitions",
        "mbrSha256", "firstUsableLba", "lastUsableLba",
    ):
        require(before[key] == after[key], f"foreign GPT identity changed: {key}")
    linux = after["linuxRoot"]
    require(
        linux["number"] == 5
        and linux["type"] == LINUX_TYPE
        and linux["startLba"] == plan["startSector"]
        and linux["endLba"] == plan["endSector"]
        and (linux["endLba"] - linux["startLba"] + 1) * SECTOR == plan["sizeBytes"]
        and linux["attrs"] == 0,
        "Linux stage GPT root does not match approved plan",
    )
