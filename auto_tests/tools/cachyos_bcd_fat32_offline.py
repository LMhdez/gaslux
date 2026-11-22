#!/usr/bin/env python3
"""Read-only FAT32 ESP BCD file-to-disk extent mapper.

Pure bytes-to-metadata transformation; never mounts, edits, repairs or writes.
An image and its caller-supplied GPT geometry are NOT provenance authentication.
Fails closed on FAT divergence, ambiguous names, bad chains and truncated input.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any

SECTOR = 512
MAX_ESP_BYTES = 512 * 1024 * 1024
MAX_BCD_BYTES = 2 * 1024 * 1024
BCD_PATH = ("EFI", "Microsoft", "Boot", "BCD")


class Fat32MapError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Fat32MapError(reason)


def _u16(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<H", raw, offset)[0]


def _u32(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<I", raw, offset)[0]


def _short_name(raw: bytes) -> str:
    require(len(raw) == 11 and all(32 <= x < 127 for x in raw),
            "non-ASCII or invalid short directory alias")
    return (raw[:8].decode("ascii").rstrip() +
            (("." + raw[8:11].decode("ascii").rstrip())
             if raw[8:11].strip() else ""))


def _lfn_checksum(name11: bytes) -> int:
    result = 0
    for value in name11:
        result = (((result & 1) << 7) | (result >> 1)) + value
        result &= 255
    return result


def _decode_long_name(entries: list[bytes], alias: bytes) -> str | None:
    if not entries:
        return None
    n = len(entries)
    require(1 <= n <= 20 and entries[0][0] == (0x40 | n),
            "invalid VFAT long-name header or sequence length")
    parts: dict[int, list[int]] = {}
    for expected, entry in zip(range(n, 0, -1), entries):
        require(len(entry) == 32 and entry[11] == 0x0F
                and entry[0] == (expected | (0x40 if expected == n else 0))
                and entry[12] == 0 and _u16(entry, 26) == 0
                and entry[13] == _lfn_checksum(alias),
                "broken VFAT sequence, type or checksum")
        fields = [entry[1:11], entry[14:26], entry[28:32]]
        chars = [v for field in fields
                 for v in struct.unpack("<" + "H" * (len(field) // 2), field)]
        parts[expected] = chars
    units = [v for i in range(1, n + 1) for v in parts[i]]
    if 0 in units:
        pos = units.index(0)
        require(all(v == 0xFFFF for v in units[pos + 1:]),
                "invalid VFAT filler after terminator")
        units = units[:pos]
    else:
        require(all(v != 0xFFFF for v in units), "invalid VFAT missing terminator")
    require(bool(units) and len(units) <= 255, "empty or oversized VFAT name")
    try:
        result = b"".join(v.to_bytes(2, "little") for v in units).decode("utf-16le")
    except UnicodeDecodeError as error:
        raise Fat32MapError("malformed VFAT Unicode name") from error
    require(result not in (".", "..") and "/" not in result and "\\" not in result,
            "unsafe VFAT component")
    return result


def map_bcd_fat32(
    volume: bytes, *, esp_start_lba: int, esp_end_lba: int,
    disk_bytes: int, sector_size: int = SECTOR,
) -> dict[str, Any]:
    """Resolve EFI/Microsoft/Boot/BCD data extents from a complete ESP image.

    All offsets are absolute virtual *guest-disk* bytes, not QCOW2 file offsets.
    The caller must independently authenticate GPT/ESP identity and image origin.
    Returns no file contents, directory names beyond the requested path or keys.
    """
    require(type(volume) is bytes and SECTOR * 80 <= len(volume) <= MAX_ESP_BYTES
            and type(sector_size) is int and sector_size == SECTOR,
            "FAT32 ESP capture missing, oversized or unsupported sector size")
    require(all(type(x) is int and x >= 0 for x in
                (esp_start_lba, esp_end_lba, disk_bytes))
            and esp_end_lba >= esp_start_lba
            and disk_bytes % SECTOR == 0
            and (esp_end_lba + 1) * SECTOR <= disk_bytes
            and len(volume) == (esp_end_lba - esp_start_lba + 1) * SECTOR,
            "ESP image length does not match authenticated GPT sector geometry")
    boot = volume[:SECTOR]
    require(boot[:1] in (b"\xeb", b"\xe9")
            and boot[510:512] == b"\x55\xaa"
            and _u16(boot, 11) == SECTOR,
            "invalid FAT32 boot sector/BPB signature")
    spc, reserved, fats = boot[13], _u16(boot, 14), boot[16]
    fat_sectors, root_cluster = _u32(boot, 36), _u32(boot, 44)
    total = _u32(boot, 32)
    ext_flags, fsinfo, backup = _u16(boot, 40), _u16(boot, 48), _u16(boot, 50)
    require(spc in (1, 2, 4, 8, 16, 32, 64, 128)
            and reserved >= 8 and fats == 2 and fat_sectors > 0
            and _u16(boot, 17) == 0 and _u16(boot, 19) == 0
            and _u16(boot, 22) == 0 and _u16(boot, 42) == 0
            and ext_flags == 0 and total == len(volume) // SECTOR
            and 0 < fsinfo < reserved
            and 0 < backup < reserved
            and backup + fsinfo < reserved
            and len({0, fsinfo, backup, backup + fsinfo}) == 4,
            "unsupported or inconsistent mirrored FAT32 BPB")
    first_data_sector = reserved + fats * fat_sectors
    require(first_data_sector < total, "FAT32 data region outside ESP")
    clusters = (total - first_data_sector) // spc
    require(65525 <= clusters < 0x0FFFFFEF
            and fat_sectors * SECTOR >= (clusters + 2) * 4
            and 2 <= root_cluster <= clusters + 1,
            "not a valid FAT32 data cluster count/FAT capacity")
    backup_boot = volume[backup * SECTOR:(backup + 1) * SECTOR]
    require(boot == backup_boot, "primary/backup FAT32 BPB differ")
    main_fsinfo = volume[fsinfo * SECTOR:(fsinfo + 1) * SECTOR]
    backup_fsinfo = volume[(backup + fsinfo) * SECTOR:
                           (backup + fsinfo + 1) * SECTOR]
    require(main_fsinfo == backup_fsinfo
            and _u32(main_fsinfo, 0) == 0x41615252
            and _u32(main_fsinfo, 484) == 0x61417272
            and _u32(main_fsinfo, 508) == 0xAA550000
            and (_u32(main_fsinfo, 488) == 0xFFFFFFFF
                 or _u32(main_fsinfo, 488) <= clusters)
            and (_u32(main_fsinfo, 492) == 0xFFFFFFFF
                 or 2 <= _u32(main_fsinfo, 492) <= clusters + 1),
            "FAT32 FSInfo or backup inconsistent")
    fat_len = fat_sectors * SECTOR
    fat_a = volume[reserved * SECTOR:reserved * SECTOR + fat_len]
    fat_b = volume[(reserved + fat_sectors) * SECTOR:
                   (reserved + 2 * fat_sectors) * SECTOR]
    require(fat_a == fat_b, "FAT copies differ; refusing physical BCD map")
    require((_u32(fat_a, 0) & 0x0FFFFFF8) == 0x0FFFFFF8
            and (_u32(fat_a, 4) & 0x0FFFFFF8) == 0x0FFFFFF8,
            "invalid FAT32 reserved entries")

    cluster_bytes = spc * SECTOR

    def chain(first: int) -> list[int]:
        result: list[int] = []
        seen: set[int] = set()
        current = first
        while True:
            require(2 <= current <= clusters + 1 and current not in seen,
                    "FAT cluster cycle or out-of-bounds reference")
            seen.add(current)
            result.append(current)
            require(len(result) <= clusters, "FAT traversal exceeds volume")
            nxt = _u32(fat_a, current * 4) & 0x0FFFFFFF
            if 0x0FFFFFF8 <= nxt <= 0x0FFFFFFF:
                return result
            require(2 <= nxt <= clusters + 1
                    and nxt != 0x0FFFFFF7
                    and not (0x0FFFFFF0 <= nxt <= 0x0FFFFFF6),
                    "FAT chain points to unallocated, bad or reserved cluster")
            current = nxt

    def cluster_sector(c: int) -> int:
        return first_data_sector + (c - 2) * spc

    dir_clusters: list[int] = []

    def directory_entries(first: int) -> list[tuple[str, int, int, bool]]:
        result: list[tuple[str, int, int, bool]] = []
        pending: list[bytes] = []
        complete = False
        for c in chain(first):
            dir_clusters.append(c)
            start = cluster_sector(c) * SECTOR
            block = volume[start:start + cluster_bytes]
            for pos in range(0, cluster_bytes, 32):
                item = block[pos:pos + 32]
                if item[0] == 0:
                    require(not pending, "dangling VFAT entries")
                    complete = True
                    break
                if item[0] == 0xE5:
                    pending.clear()
                    continue
                if item[11] == 0x0F:
                    pending.append(item)
                    continue
                alias = item[:11]
                long_name = _decode_long_name(pending, alias)
                pending.clear()
                if item[11] & 0x08:
                    continue  # volume label
                require(not (item[11] & 0xC0), "invalid directory attributes")
                sfn = _short_name(alias)
                name = long_name or sfn
                first_data_cluster = (_u16(item, 20) << 16) | _u16(item, 26)
                size = _u32(item, 28)
                is_dir = bool(item[11] & 0x10)
                require(2 <= first_data_cluster <= clusters + 1,
                        "nonempty directory entry has bad first cluster")
                result.append((name, first_data_cluster, size, is_dir))
                if long_name and sfn.casefold() == name.casefold():
                    # Same entry is not an ambiguous duplicate.
                    pass
            if complete:
                break
        require(not pending, "dangling VFAT sequence at directory end")
        return result

    parent = root_cluster
    file_first = file_bytes = None
    for index, component in enumerate(BCD_PATH):
        matches = [entry for entry in directory_entries(parent)
                   if entry[0].casefold() == component.casefold()]
        require(len(matches) == 1, "missing or ambiguous BCD path component")
        _, value, size, is_dir = matches[0]
        if index < len(BCD_PATH) - 1:
            require(is_dir, "BCD path traverses a non-directory")
            parent = value
        else:
            require(not is_dir and 4096 <= size <= MAX_BCD_BYTES,
                    "BCD file is not a bounded regular file")
            file_first, file_bytes = value, size

    assert file_first is not None and file_bytes is not None
    file_chain = chain(file_first)
    required_clusters = (file_bytes + cluster_bytes - 1) // cluster_bytes
    require(len(file_chain) == required_clusters,
            "BCD FAT chain is truncated or overallocated")
    base = esp_start_lba * SECTOR
    data_extents: list[dict[str, int]] = []
    remaining = file_bytes
    for index, c in enumerate(file_chain):
        offset = base + cluster_sector(c) * SECTOR
        length = min(remaining, cluster_bytes)
        require(base <= offset and offset + length <= base + len(volume)
                and offset + length <= disk_bytes,
                "BCD file cluster falls outside the authenticated ESP")
        data_extents.append({
            "fileOffset": index * cluster_bytes,
            "diskOffset": offset,
            "length": length,
            "cluster": c,
        })
        remaining -= length
    require(remaining == 0 and not (set(dir_clusters) & set(file_chain)),
            "directory or file clusters are shared")

    metadata: list[dict[str, Any]] = []
    for name, sector, count in (
        ("FAT32_BOOT", 0, 1),
        ("FAT32_FSINFO", fsinfo, 1),
        ("FAT32_BACKUP_BOOT", backup, 1),
        ("FAT32_BACKUP_FSINFO", backup + fsinfo, 1),
        ("FAT32_FAT_0", reserved, fat_sectors),
        ("FAT32_FAT_1", reserved + fat_sectors, fat_sectors),
    ):
        metadata.append({
            "kind": name, "diskOffset": base + sector * SECTOR,
            "length": count * SECTOR,
        })
    for c in sorted(set(dir_clusters)):
        metadata.append({
            "kind": "FAT32_DIRECTORY",
            "diskOffset": base + cluster_sector(c) * SECTOR,
            "length": cluster_bytes,
        })
    return {
        "status": "FAT32_STRUCTURAL_MAP_ONLY",
        "imageProvenanceAuthenticated": False,
        "writable": False,
        "espImageSha256": hashlib.sha256(volume).hexdigest(),
        "espStartLba": esp_start_lba,
        "espEndLba": esp_end_lba,
        "sectorBytes": SECTOR,
        "diskBytes": disk_bytes,
        "bcdSizeBytes": file_bytes,
        "clusterBytes": cluster_bytes,
        "bcdDataExtents": data_extents,
        "fat32MetadataExtents": metadata,
        "bcdFragmented": any(b != a + 1
                             for a, b in zip(file_chain, file_chain[1:])),
    }


def historical_mapping_unavailable() -> dict[str, Any]:
    """The Actions #44900941635 artifact has no authenticated raw ESP/BPB."""
    return {
        "status": "BCD_PHYSICAL_MAPPING_UNAVAILABLE",
        "reason": "no authenticated ESP FAT32 image or cluster map in original evidence",
        "approvedMutation": False,
        "processAttributionProven": False,
    }
