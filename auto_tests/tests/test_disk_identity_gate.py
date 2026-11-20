"""Adversarial tests for the isolated, read-only GPT image identity gate."""
import importlib.util
import struct
import uuid
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
module_path = ROOT / "assets/live/libertix_disk_identity_gate.py"
spec = importlib.util.spec_from_file_location("libertix_disk_identity_gate_test", module_path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SECTOR = 512
DISK_ID = uuid.UUID("12345678-1234-1234-1234-123456789abc")
TYPE_ID = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
PART_ID = uuid.UUID("87654321-4321-4321-4321-cba987654321")


def make_image(path, *, corrupt_backup=False, corrupt_entries=False):
    sectors = 4096
    data = bytearray(sectors * SECTOR)
    data[446 + 4] = 0xee
    struct.pack_into("<II", data, 446 + 8, 1, sectors - 1)
    data[510:512] = b"\x55\xaa"
    entries = bytearray(128 * 128)
    entries[:16] = TYPE_ID.bytes_le
    entries[16:32] = PART_ID.bytes_le
    struct.pack_into("<QQQ", entries, 32, 64, 1023, 0)
    array_crc = zlib.crc32(entries)
    data[2 * SECTOR:2 * SECTOR + len(entries)] = entries
    data[(sectors - 33) * SECTOR:(sectors - 33) * SECTOR + len(entries)] = entries

    def header(current, alternate, array_lba):
        raw = bytearray(SECTOR)
        raw[:8] = b"EFI PART"
        struct.pack_into("<IIII", raw, 8, 0x10000, 92, 0, 0)
        struct.pack_into("<QQQQ", raw, 24, current, alternate, 34, sectors - 34)
        raw[56:72] = DISK_ID.bytes_le
        struct.pack_into("<QIII", raw, 72, array_lba, 128, 128, array_crc)
        struct.pack_into("<I", raw, 16, zlib.crc32(raw[:92]))
        return raw

    data[SECTOR:2 * SECTOR] = header(1, sectors - 1, 2)
    data[(sectors - 1) * SECTOR:] = header(sectors - 1, 1, sectors - 33)
    if corrupt_backup:
        data[(sectors - 1) * SECTOR + 56] ^= 1
    if corrupt_entries:
        data[2 * SECTOR + 16] ^= 1
    path.write_bytes(data)


@pytest.fixture
def snapshot(tmp_path):
    image = tmp_path / "disk.img"
    make_image(image)
    return image, gate.inspect_gpt_image(image, logical_sector_size=SECTOR)


def test_identical_gpt_passes(snapshot):
    path, expected = snapshot
    gate.assert_snapshot_matches(
        expected, gate.inspect_gpt_image(path, logical_sector_size=SECTOR)
    )


@pytest.mark.parametrize("change", [
    {"partitionTableId": "gpt:00000000-0000-0000-0000-000000000000"},
    {"sizeBytes": 1},
    {"logicalSectorSizeBytes": 4096},
    {"partitions": []},
])
def test_changed_disk_identity_rejected(snapshot, change):
    _, expected = snapshot
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(expected, {**expected, **change})


@pytest.mark.parametrize("mutation", ["offset", "partGuid", "missing", "duplicate"])
def test_partition_identity_rejected(snapshot, mutation):
    _, expected = snapshot
    observed = {**expected, "partitions": [p.copy() for p in expected["partitions"]]}
    if mutation == "offset":
        observed["partitions"][0]["offsetBytes"] += 512
    elif mutation == "partGuid":
        observed["partitions"][0]["partGuid"] = str(uuid.uuid4())
    elif mutation == "missing":
        observed["partitions"][0].pop("partGuid")
    else:
        observed["partitions"].append(observed["partitions"][0].copy())
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(expected, observed)


@pytest.mark.parametrize("corruption", ["corrupt_backup", "corrupt_entries"])
def test_corrupt_gpt_is_rejected(tmp_path, corruption):
    image = tmp_path / "corrupted.img"
    make_image(image, **{corruption: True})
    with pytest.raises(gate.DiskIdentityError):
        gate.inspect_gpt_image(image, logical_sector_size=SECTOR)


def test_mbr_rejected_without_validated_ebr_chain(snapshot):
    _, expected = snapshot
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(expected, {**expected, "partitionStyle": "MBR"})
