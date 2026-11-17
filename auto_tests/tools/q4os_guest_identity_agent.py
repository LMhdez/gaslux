#!/usr/bin/env python3
"""Disposable Q4OS QEMU guest probe. Opens the target block device read-only."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import struct
import sys
import time
import uuid
import zlib
from pathlib import Path
from typing import Any

PORT_NAME = "org.gaslux.q4os.identity"
CHALLENGE_MAGIC = b"GQ4OS-CHALLENGE-V1"
REPORT_MAGIC = b"GQ4OS-REPORT-V1\n"
HELLO = b"GQ4OS-HELLO-V1\n"
MAC_DOMAIN = b"GASLUX-Q4OS-GUEST-REPORT-V1\n"
ESP_TYPE_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
RUN_RE = re.compile(r"[A-Za-z0-9_-]{12,100}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
SECRET_RE = re.compile(r"[0-9a-f]{64}\Z")


class GuestProbeError(RuntimeError):
    """The guest could not prove the exact read-only target identity."""


def derive_virtio_serial(run_id: str, nonce: str) -> str:
    if not RUN_RE.fullmatch(run_id) or not NONCE_RE.fullmatch(nonce):
        raise GuestProbeError("Invalid run ID or nonce")
    material = (run_id + "\0" + nonce).encode("ascii")
    return "GQ4OS-" + hashlib.sha256(material).hexdigest()[:14].upper()


def _pread_exact(fd: int, size: int, offset: int) -> bytes:
    data = os.pread(fd, size, offset)
    if len(data) != size:
        raise GuestProbeError("Truncated guest disk metadata")
    return data


def _validate_header(
    raw: bytes,
    *,
    sector_bytes: int,
    disk_sectors: int,
    current_lba: int,
    backup_lba: int,
    entries_lba: int,
) -> tuple[str, int]:
    if raw[:8] != b"EFI PART":
        raise GuestProbeError("Missing GPT header signature")
    revision, header_size, stored_crc = struct.unpack_from("<III", raw, 8)
    if revision != 0x00010000 or header_size != 92:
        raise GuestProbeError("Unsupported GPT header version or size")
    header = bytearray(raw[:header_size])
    header[16:20] = bytes(4)
    if zlib.crc32(header) != stored_crc:
        raise GuestProbeError("GPT header CRC mismatch")
    current, backup, first_usable, last_usable = struct.unpack_from("<QQQQ", raw, 24)
    if (current, backup) != (current_lba, backup_lba):
        raise GuestProbeError("GPT primary/backup LBA mismatch")
    if first_usable != 34 or last_usable != disk_sectors - 34:
        raise GuestProbeError("Unexpected GPT usable-sector bounds")
    table_lba = struct.unpack_from("<Q", raw, 72)[0]
    count, entry_size, table_crc = struct.unpack_from("<III", raw, 80)
    if table_lba != entries_lba or count != 128 or entry_size != 128:
        raise GuestProbeError("Unexpected GPT partition-table geometry")
    disk_guid = str(uuid.UUID(bytes_le=raw[56:72]))
    if disk_guid == str(uuid.UUID(int=0)):
        raise GuestProbeError("Empty GPT disk GUID")
    if sector_bytes != 512:
        raise GuestProbeError("Unsupported logical sector size")
    return disk_guid, table_crc


def inspect_gpt_fd(fd: int, *, disk_size_bytes: int, sector_bytes: int) -> dict[str, Any]:
    if sector_bytes != 512 or disk_size_bytes <= 0 or disk_size_bytes % sector_bytes:
        raise GuestProbeError("Unsupported guest disk geometry")
    disk_sectors = disk_size_bytes // sector_bytes
    if disk_sectors < 4096:
        raise GuestProbeError("Guest disk is too small for the expected GPT layout")

    mbr = _pread_exact(fd, sector_bytes, 0)
    if mbr[510:512] != b"\x55\xaa":
        raise GuestProbeError("Protective MBR signature missing")
    mbr_entries = [mbr[446 + 16 * i : 446 + 16 * (i + 1)] for i in range(4)]
    first = mbr_entries[0]
    start_lba, sector_count = struct.unpack_from("<II", first, 8)
    if first[0] != 0 or first[4] != 0xEE:
        raise GuestProbeError("Guest disk is not a protective-MBR GPT disk")
    if start_lba != 1 or sector_count != disk_sectors - 1:
        raise GuestProbeError("Protective MBR geometry mismatch")
    if any(entry != bytes(16) for entry in mbr_entries[1:]):
        raise GuestProbeError("Hybrid or foreign MBR entry detected")

    primary_raw = _pread_exact(fd, sector_bytes, sector_bytes)
    backup_raw = _pread_exact(fd, sector_bytes, (disk_sectors - 1) * sector_bytes)
    primary_guid, primary_table_crc = _validate_header(
        primary_raw,
        sector_bytes=sector_bytes,
        disk_sectors=disk_sectors,
        current_lba=1,
        backup_lba=disk_sectors - 1,
        entries_lba=2,
    )
    backup_guid, backup_table_crc = _validate_header(
        backup_raw,
        sector_bytes=sector_bytes,
        disk_sectors=disk_sectors,
        current_lba=disk_sectors - 1,
        backup_lba=1,
        entries_lba=disk_sectors - 33,
    )
    if primary_guid != backup_guid or primary_table_crc != backup_table_crc:
        raise GuestProbeError("Primary/backup GPT identity differs")

    table_size = 128 * 128
    primary_table = _pread_exact(fd, table_size, 2 * sector_bytes)
    backup_table = _pread_exact(fd, table_size, (disk_sectors - 33) * sector_bytes)
    if primary_table != backup_table:
        raise GuestProbeError("Primary/backup GPT tables differ")
    if zlib.crc32(primary_table) != primary_table_crc:
        raise GuestProbeError("GPT partition-table CRC mismatch")

    partitions: list[dict[str, Any]] = []
    for index in range(128):
        entry = primary_table[index * 128 : (index + 1) * 128]
        type_bytes = entry[:16]
        if type_bytes == bytes(16):
            continue
        type_guid = str(uuid.UUID(bytes_le=type_bytes))
        part_guid = str(uuid.UUID(bytes_le=entry[16:32]))
        start_lba, end_lba = struct.unpack_from("<QQ", entry, 32)
        name = entry[56:128].decode("utf-16le").rstrip("\x00")
        if part_guid == str(uuid.UUID(int=0)) or start_lba > end_lba:
            raise GuestProbeError("Malformed GPT partition entry")
        if start_lba < 34 or end_lba > disk_sectors - 34:
            raise GuestProbeError("GPT partition exceeds usable disk bounds")
        partitions.append(
            {
                "number": index + 1,
                "startLba": start_lba,
                "endLba": end_lba,
                "typeGuid": type_guid,
                "partGuid": part_guid,
                "label": name,
            }
        )

    if len(partitions) != 1:
        raise GuestProbeError("Expected exactly one transaction-owned ESP")
    esp = partitions[0]
    if esp["typeGuid"] != ESP_TYPE_GUID:
        raise GuestProbeError("Guest partition is not an EFI System Partition")

    boot_sector = _pread_exact(fd, sector_bytes, esp["startLba"] * sector_bytes)
    bytes_per_sector = struct.unpack_from("<H", boot_sector, 11)[0]
    fat16_size = struct.unpack_from("<H", boot_sector, 22)[0]
    fat32_size = struct.unpack_from("<I", boot_sector, 36)[0]
    if (
        boot_sector[510:512] != b"\x55\xaa"
        or bytes_per_sector != sector_bytes
        or fat16_size != 0
        or fat32_size == 0
        or boot_sector[82:90] != b"FAT32   "
    ):
        raise GuestProbeError("ESP does not contain a valid FAT32 boot sector")
    esp["filesystem"] = "vfat"
    return {"diskGuid": primary_guid, "partitions": partitions}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise GuestProbeError(f"Cannot read guest identity attribute: {path}") from exc


def inspect_guest_target(
    *,
    expected_serial: str,
    sys_block_root: Path = Path("/sys/block"),
    dev_root: Path = Path("/dev"),
) -> dict[str, Any]:
    matches = []
    for serial_path in sorted(sys_block_root.glob("*/serial")):
        if _read_text(serial_path) == expected_serial:
            matches.append(serial_path.parent.name)
    if len(matches) != 1:
        raise GuestProbeError("Expected exactly one block device with the bound virtio serial")

    name = matches[0]
    sys_disk = sys_block_root / name
    if _read_text(sys_disk / "ro") != "1":
        raise GuestProbeError("QEMU guest block device is not kernel read-only")
    sectors = int(_read_text(sys_disk / "size"), 10)
    logical = int(_read_text(sys_disk / "queue" / "logical_block_size"), 10)
    physical = int(_read_text(sys_disk / "queue" / "physical_block_size"), 10)
    if logical != 512 or physical not in (512, 4096):
        raise GuestProbeError("Unsupported guest sector geometry")
    size_bytes = sectors * 512
    device = dev_root / name
    try:
        mode = device.stat().st_mode
    except OSError as exc:
        raise GuestProbeError("Bound virtio block device node is missing") from exc
    if not stat.S_ISBLK(mode):
        raise GuestProbeError("Bound guest target is not a block device")

    fd = os.open(device, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        gpt = inspect_gpt_fd(fd, disk_size_bytes=size_bytes, sector_bytes=logical)
    finally:
        os.close(fd)
    return {
        "device": str(device),
        "serial": expected_serial,
        "sizeBytes": size_bytes,
        "logicalSectorBytes": logical,
        "physicalSectorBytes": physical,
        "diskGuid": gpt["diskGuid"],
        "partitions": gpt["partitions"],
        "blockDeviceReadOnly": True,
        "readOnlyProbe": True,
        "writeAttempted": False,
    }


def _read_line(fd: int, limit: int) -> bytes:
    value = bytearray()
    while len(value) <= limit:
        byte = os.read(fd, 1)
        if not byte:
            raise GuestProbeError("Virtio-serial channel closed before a complete line")
        if byte == b"\n":
            return bytes(value)
        value.extend(byte)
    raise GuestProbeError("Virtio-serial line exceeds protocol limit")


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise GuestProbeError("Virtio-serial write failed")
        view = view[written:]


def find_virtio_port(
    *,
    sys_ports_root: Path = Path("/sys/class/virtio-ports"),
    dev_root: Path = Path("/dev"),
    timeout_seconds: int = 30,
) -> Path:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for entry in sorted(sys_ports_root.glob("*")):
            if _read_text(entry / "name") == PORT_NAME:
                device = dev_root / entry.name
                try:
                    if stat.S_ISCHR(device.stat().st_mode):
                        return device
                except OSError:
                    pass
        time.sleep(0.1)
    raise GuestProbeError("Named Gaslux virtio-serial port did not appear")


def serve_one_report(
    *,
    sys_block_root: Path = Path("/sys/block"),
    dev_root: Path = Path("/dev"),
    sys_ports_root: Path = Path("/sys/class/virtio-ports"),
) -> dict[str, Any]:
    port = find_virtio_port(sys_ports_root=sys_ports_root, dev_root=dev_root)
    fd = os.open(port, os.O_RDWR | getattr(os, "O_NOCTTY", 0))
    try:
        _write_all(fd, HELLO)
        challenge = _read_line(fd, 512)
        fields = challenge.split(b":")
        if len(fields) != 4 or fields[0] != CHALLENGE_MAGIC:
            raise GuestProbeError("Invalid host challenge frame")
        try:
            run_id, nonce, secret = (part.decode("ascii") for part in fields[1:])
        except UnicodeDecodeError as exc:
            raise GuestProbeError("Host challenge is not ASCII") from exc
        if not RUN_RE.fullmatch(run_id) or not NONCE_RE.fullmatch(nonce):
            raise GuestProbeError("Invalid run ID or nonce in host challenge")
        if not SECRET_RE.fullmatch(secret):
            raise GuestProbeError("Invalid one-time challenge key")
        serial = derive_virtio_serial(run_id, nonce)
        report = {
            "schemaVersion": 1,
            "runId": run_id,
            "nonce": nonce,
            **inspect_guest_target(
                expected_serial=serial,
                sys_block_root=sys_block_root,
                dev_root=dev_root,
            ),
        }
        raw_report = json.dumps(
            report, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        mac = hmac.new(
            secret.encode("ascii"), MAC_DOMAIN + raw_report, hashlib.sha256
        ).hexdigest().encode("ascii")
        _write_all(fd, REPORT_MAGIC + raw_report + b"\n" + mac + b"\n")
        print("GASLUX_Q4OS_GUEST_PROBE=PASS", flush=True)
        print("GASLUX_Q4OS_GUEST_SERIAL=" + serial, flush=True)
        print("GASLUX_Q4OS_GUEST_BLOCK_READ_ONLY=true", flush=True)
        print("GASLUX_Q4OS_GUEST_WRITE_ATTEMPTED=false", flush=True)
        return report
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-poweroff", action="store_true")
    args = parser.parse_args()
    try:
        serve_one_report()
    except (GuestProbeError, OSError, ValueError) as exc:
        print(f"GASLUX_Q4OS_GUEST_PROBE_REFUSED={exc}", file=sys.stderr, flush=True)
        return 1
    if not args.no_poweroff:
        os.execv("/bin/busybox", ["busybox", "poweroff", "-f"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
