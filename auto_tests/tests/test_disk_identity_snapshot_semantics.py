"""Reject malformed authenticated GPT inventory shapes before equality checks.

These negative fixtures exercise a read-only boundary; they are not boot or
rollback evidence, and never authorize storage writes.
"""

import importlib.util
import struct
import uuid
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "gaslux_gpt_snapshot_semantics", ROOT / "assets/live/libertix_disk_identity_gate.py"
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

DISK = "12345678-1234-1234-1234-123456789abc"
TYPE = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
PART = "87654321-4321-4321-4321-cba987654321"


def snapshot():
    return {
        "partitionStyle": "GPT",
        "partitionTableId": "gpt:" + DISK,
        "sizeBytes": 4096 * 512,
        "logicalSectorSizeBytes": 512,
        "partitions": [
            {
                "number": 1,
                "typeGuid": TYPE,
                "partGuid": PART,
                "offsetBytes": 64 * 512,
                "sizeBytes": 960 * 512,
                "attributes": 0,
            }
        ],
    }


def test_valid_snapshot_self_comparison():
    value = snapshot()
    gate.assert_snapshot_matches(value, value)


@pytest.mark.parametrize(
    "disk_id",
    [
        "gpt:" + "0" * 36,
        "gpt:" + "z" * 36,
        "gpt:" + DISK.upper(),
    ],
)
def test_invalid_disk_guid_rejected_even_when_snapshots_equal(disk_id):
    value = snapshot()
    value["partitionTableId"] = disk_id
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


@pytest.mark.parametrize(
    "field, invalid",
    [
        ("partGuid", str(uuid.UUID(int=0))),
        ("typeGuid", str(uuid.UUID(int=0))),
        ("partGuid", "z" * 36),
        ("typeGuid", TYPE.upper()),
    ],
)
def test_invalid_partition_guid_rejected(field, invalid):
    value = snapshot()
    value["partitions"][0][field] = invalid
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_guid",
        "overlap",
        "outside",
        "misaligned",
        "negative_attributes",
        "oversized_attributes",
        "unaligned_disk",
    ],
)
def test_invalid_geometry_rejected_even_when_snapshots_equal(mutation):
    value = snapshot()
    part = value["partitions"][0]
    if mutation == "unaligned_disk":
        value["sizeBytes"] += 1
    elif mutation == "outside":
        part["offsetBytes"] = value["sizeBytes"]
    elif mutation == "misaligned":
        part["offsetBytes"] += 1
    elif mutation == "negative_attributes":
        part["attributes"] = -1
    elif mutation == "oversized_attributes":
        part["attributes"] = 2**64
    else:
        other = dict(part)
        other["number"] = 2
        other["offsetBytes"] = part["offsetBytes"] + part["sizeBytes"]
        other["partGuid"] = "00000000-0000-4000-8000-000000000001"
        if mutation == "duplicate_guid":
            other["partGuid"] = part["partGuid"]
        else:
            other["offsetBytes"] -= 512
        value["partitions"].append(other)
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


@pytest.mark.parametrize("sector", [512, 4096])
@pytest.mark.parametrize("lba", [1, 2, 4094, 4095])
def test_reserved_gpt_lba_rejected_for_identical_snapshots(sector, lba):
    """RED: metadata LBAs must never be accepted as partition payload."""
    value = snapshot()
    value["logicalSectorSizeBytes"] = sector
    value["sizeBytes"] = 4096 * sector
    value["partitions"][0]["offsetBytes"] = lba * sector
    value["partitions"][0]["sizeBytes"] = sector
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


def test_positive_four_kib_sector_snapshot_is_accepted():
    value = snapshot()
    value["logicalSectorSizeBytes"] = 4096
    value["sizeBytes"] = 4096 * 4096
    value["partitions"][0]["offsetBytes"] = 64 * 4096
    value["partitions"][0]["sizeBytes"] = 960 * 4096
    gate.assert_snapshot_matches(value, value)


def test_duplicate_slot_with_distinct_guid_rejected():
    value = snapshot()
    other = dict(value["partitions"][0])
    other["partGuid"] = "00000000-0000-4000-8000-000000000002"
    other["offsetBytes"] += other["sizeBytes"]
    value["partitions"].append(other)
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


def test_large_slot_number_never_emitted_by_gpt_reader():
    value = snapshot()
    value["partitions"][0]["number"] = 4097
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


def test_too_small_disk_never_emitted_by_gpt_reader():
    value = snapshot()
    value["sizeBytes"] = 67 * 512
    value["partitions"][0]["sizeBytes"] = 512
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


def test_four_kib_sectors_from_actual_fd_gpt_reader(tmp_path):
    """Exercise the real CRC-checked GPT reader, not only hand-built dictionaries."""
    sector = 4096
    sectors = 4096
    image = bytearray(sector * sectors)
    image[446 + 4] = 0xEE
    struct.pack_into("<II", image, 446 + 8, 1, sectors - 1)
    image[510:512] = b"\x55\xaa"
    entries = bytearray(128 * 128)
    entries[:16] = uuid.UUID(TYPE).bytes_le
    entries[16:32] = uuid.UUID(PART).bytes_le
    struct.pack_into("<QQQ", entries, 32, 64, 1023, 0)
    entries_crc = zlib.crc32(entries)
    for lba in (2, sectors - 5):
        image[lba * sector : lba * sector + len(entries)] = entries

    def header(current, alternate, array_lba):
        raw = bytearray(sector)
        raw[:8] = b"EFI PART"
        struct.pack_into("<IIII", raw, 8, 0x10000, 92, 0, 0)
        struct.pack_into("<QQQQ", raw, 24, current, alternate, 34, sectors - 6)
        raw[56:72] = uuid.UUID(DISK).bytes_le
        struct.pack_into("<QIII", raw, 72, array_lba, 128, 128, entries_crc)
        struct.pack_into("<I", raw, 16, zlib.crc32(raw[:92]))
        return raw

    image[sector : 2 * sector] = header(1, sectors - 1, 2)
    image[(sectors - 1) * sector :] = header(sectors - 1, 1, sectors - 5)
    path = tmp_path / "synthetic-4k-gpt.img"
    path.write_bytes(image)
    actual = gate.inspect_gpt_image(path, logical_sector_size=sector)
    assert actual["logicalSectorSizeBytes"] == sector
    assert actual["partitions"][0]["offsetBytes"] == 64 * sector
    gate.assert_snapshot_matches(actual, actual)
