#!/usr/bin/env python3
"""Fail-closed, read-only GPT image identity evidence for an authenticated plan.

This is NOT a write gate integration. An installer must authenticate expected
plan ownership, physical/guest mapping and transaction independently.
Only immutable regular-file images are accepted, never block devices.
"""
from __future__ import annotations

import fcntl
import os
import stat
import struct
import uuid
import zlib
from pathlib import Path


class DiskIdentityError(ValueError):
    """Disk evidence missing, inconsistent or different from its expected state."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise DiskIdentityError(reason)


def exact_read(fd: int, offset: int, length: int) -> bytes:
    value = os.pread(fd, length, offset)
    require(len(value) == length, "incomplete disk evidence")
    return value


def guid(value: bytes) -> str:
    return str(uuid.UUID(bytes_le=value))


def read_header(fd: int, sector: int, lba: int, sectors: int) -> dict:
    value = exact_read(fd, lba * sector, sector)
    require(value[:8] == b"EFI PART", "invalid GPT signature")
    revision, size, crc, reserved = struct.unpack_from("<IIII", value, 8)
    require(revision == 0x10000 and 92 <= size <= sector and reserved == 0,
            "unsupported GPT header")
    raw = bytearray(value[:size])
    raw[16:20] = b"\x00" * 4
    require(zlib.crc32(raw) == crc, "invalid GPT header CRC")
    current, alternate, first, last = struct.unpack_from("<QQQQ", value, 24)
    array_lba, count, entry_size, array_crc = struct.unpack_from("<QIII", value, 72)
    require(current == lba and alternate < sectors and first <= last < sectors,
            "invalid GPT LBA bounds")
    require(1 <= count <= 4096 and 128 <= entry_size <= 1024 and entry_size % 8 == 0,
            "unsupported GPT entries")
    size_bytes = count * entry_size
    require(array_lba >= 2 and array_lba * sector + size_bytes <= sectors * sector,
            "GPT partition array outside disk")
    entries = exact_read(fd, array_lba * sector, size_bytes)
    require(zlib.crc32(entries) == array_crc, "invalid GPT entries CRC")
    return dict(current=current, alternate=alternate, first=first, last=last,
                disk_guid=guid(value[56:72]), array_lba=array_lba,
                count=count, entry_size=entry_size, entries=entries,
                header_bytes=value)


def inspect_gpt_fd(fd: int, *, logical_sector_size: int) -> dict:
    """Inspect a caller-pinned, read-only regular-file FD; never resolve its path.

    The caller owns fd and must authenticate its provenance separately.
    A private dup pins the open file description and is closed on all paths;
    pread does not change the caller's file offset. GPT regions are checked
    twice and file metadata must remain stable through this inspection. Neither
    check freezes future writes: this function NEVER authorizes disk mutation.
    """
    sector = logical_sector_size
    require(type(sector) is int and sector in (512, 4096), "invalid sector size")
    require(type(fd) is int and fd >= 0, "invalid disk descriptor")
    try:
        pinned_fd = os.dup(fd)
    except OSError as error:
        raise DiskIdentityError("invalid disk descriptor") from error
    try:
        require((fcntl.fcntl(pinned_fd, fcntl.F_GETFL) & os.O_ACCMODE) == os.O_RDONLY,
                "disk descriptor must be read-only")
        initial = os.fstat(pinned_fd)
        require(stat.S_ISREG(initial.st_mode), "block devices are unsupported")
        require(initial.st_size >= 68 * sector and initial.st_size % sector == 0,
                "invalid disk size")
        sectors = initial.st_size // sector
        mbr = exact_read(pinned_fd, 0, 512)
        require(mbr[510:] == b"\x55\xaa", "invalid protective MBR")
        slots = [mbr[446 + i * 16:462 + i * 16] for i in range(4)]
        require(slots[0][4] == 0xee and all(not any(s) for s in slots[1:]),
                "hybrid or missing protective MBR")
        require(struct.unpack_from("<I", slots[0], 8)[0] == 1,
                "invalid protective partition start")
        primary = read_header(pinned_fd, sector, 1, sectors)
        backup = read_header(pinned_fd, sector, sectors - 1, sectors)
        require(primary["alternate"] == sectors - 1 and backup["alternate"] == 1,
                "GPT header locations disagree")
        for key in ("disk_guid", "first", "last", "count", "entry_size", "entries"):
            require(primary[key] == backup[key], "primary/backup GPT disagreement")
        require(primary["array_lba"] * sector + len(primary["entries"]) <=
                primary["first"] * sector, "primary entries overlap usable disk")
        require(backup["array_lba"] > backup["last"] and
                backup["array_lba"] * sector + len(backup["entries"]) <=
                (sectors - 1) * sector, "backup entries outside reserved area")
        partitions = []
        for i in range(primary["count"]):
            data = primary["entries"][i * primary["entry_size"]:
                                      (i + 1) * primary["entry_size"]]
            if data[:16] == bytes(16):
                require(not any(data), "malformed unused GPT slot")
                continue
            start, end, attributes = struct.unpack_from("<QQQ", data, 32)
            require(primary["first"] <= start <= end <= primary["last"],
                    "partition outside usable disk")
            require(any(data[16:32]), "zero partition GUID")
            partitions.append(dict(number=i + 1, typeGuid=guid(data[:16]),
                                   partGuid=guid(data[16:32]),
                                   offsetBytes=start * sector,
                                   sizeBytes=(end - start + 1) * sector,
                                   attributes=attributes))
        sorted_parts = sorted(partitions, key=lambda p: p["offsetBytes"])
        require(all(a["offsetBytes"] + a["sizeBytes"] <= b["offsetBytes"]
                    for a, b in zip(sorted_parts, sorted_parts[1:])),
                "overlapping partitions")
        require(len({p["partGuid"] for p in partitions}) == len(partitions),
                "duplicate partition GUID")
        observed = dict(partitionStyle="GPT",
                        partitionTableId="gpt:" + primary["disk_guid"],
                        sizeBytes=initial.st_size, logicalSectorSizeBytes=sector,
                        partitions=partitions)
        # A path can be renamed/replaced while the descriptor remains pinned.
        # Reject in-place changes to the GPT/PMBR regions during this read.
        require(exact_read(pinned_fd, 0, 512) == mbr,
                "protective MBR changed during inspection")
        for header in (primary, backup):
            require(exact_read(pinned_fd, header["current"] * sector, sector)
                    == header["header_bytes"], "GPT header changed during inspection")
            require(exact_read(pinned_fd, header["array_lba"] * sector,
                               len(header["entries"])) == header["entries"],
                    "GPT entries changed during inspection")
        final = os.fstat(pinned_fd)
        immutable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(initial, key) == getattr(final, key)
                    for key in immutable_fields), "disk image changed during inspection")
        return observed
    except OSError as error:
        raise DiskIdentityError("disk evidence could not be read") from error
    finally:
        os.close(pinned_fd)


def inspect_gpt_image(path: str | Path, *, logical_sector_size: int) -> dict:
    """Compatibility wrapper: open once, then use the canonical FD-based reader."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        return inspect_gpt_fd(fd, logical_sector_size=logical_sector_size)
    finally:
        os.close(fd)


def assert_snapshot_matches(expected: dict, observed: dict) -> None:
    """Exact comparison. expected must come from independently authenticated plan."""
    keys = {"partitionStyle", "partitionTableId", "sizeBytes",
            "logicalSectorSizeBytes", "partitions"}
    pk = {"number", "typeGuid", "partGuid", "offsetBytes", "sizeBytes", "attributes"}
    for disk in (expected, observed):
        require(type(disk) is dict and set(disk) == keys, "incomplete disk snapshot")
        require(disk["partitionStyle"] == "GPT", "unsupported partition style")
        require(type(disk["partitionTableId"]) is str and
                disk["partitionTableId"].startswith("gpt:") and
                len(disk["partitionTableId"]) == 40, "invalid GPT disk ID")
        require(type(disk["sizeBytes"]) is int and disk["sizeBytes"] > 0 and
                type(disk["logicalSectorSizeBytes"]) is int and
                disk["logicalSectorSizeBytes"] in (512, 4096), "invalid geometry")
        require(type(disk["partitions"]) is list, "partition inventory absent")
        sector = disk["logicalSectorSizeBytes"]
        require(disk["sizeBytes"] % sector == 0, "unaligned disk geometry")
        try:
            disk_guid = str(uuid.UUID(disk["partitionTableId"][4:]))
        except (ValueError, AttributeError) as error:
            raise DiskIdentityError("malformed GPT disk ID") from error
        require(disk["partitionTableId"] == "gpt:" + disk_guid and
                disk_guid != str(uuid.UUID(int=0)), "noncanonical GPT disk ID")
        numbers = set()
        guids = set()
        spans = []
        for part in disk["partitions"]:
            require(type(part) is dict and set(part) == pk, "incomplete partition")
            require(all(type(part[k]) is int for k in
                        ("number", "offsetBytes", "sizeBytes", "attributes")) and
                    part["number"] > 0 and part["offsetBytes"] > 0 and
                    part["sizeBytes"] > 0 and 0 <= part["attributes"] < 2**64,
                    "invalid partition geometry")
            require(part["offsetBytes"] % sector == 0 and
                    part["sizeBytes"] % sector == 0 and
                    part["offsetBytes"] + part["sizeBytes"] <= disk["sizeBytes"],
                    "partition outside aligned disk bounds")
            for key in ("typeGuid", "partGuid"):
                require(type(part[key]) is str, "invalid partition GUID")
                try:
                    parsed = str(uuid.UUID(part[key]))
                except (ValueError, AttributeError) as error:
                    raise DiskIdentityError("malformed partition GUID") from error
                require(part[key] == parsed and parsed != str(uuid.UUID(int=0)),
                        "noncanonical or zero partition GUID")
            require(part["number"] not in numbers, "duplicate partition slot")
            require(part["partGuid"] not in guids, "duplicate partition GUID")
            numbers.add(part["number"])
            guids.add(part["partGuid"])
            spans.append((part["offsetBytes"], part["offsetBytes"] + part["sizeBytes"]))
        spans.sort()
        require(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])),
                "overlapping partitions")
    require(expected == observed, "disk identity or partition geometry changed")
