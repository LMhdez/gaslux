"""Reject malformed authenticated GPT inventory shapes before equality checks.

These negative fixtures exercise a read-only boundary; they are not boot or
rollback evidence, and never authorize storage writes.
"""
import importlib.util
from pathlib import Path
import uuid

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
        "partitions": [{
            "number": 1, "typeGuid": TYPE, "partGuid": PART,
            "offsetBytes": 64 * 512, "sizeBytes": 960 * 512, "attributes": 0,
        }],
    }


def test_valid_snapshot_self_comparison():
    value = snapshot()
    gate.assert_snapshot_matches(value, value)


@pytest.mark.parametrize("disk_id", [
    "gpt:" + "0" * 36,
    "gpt:" + "z" * 36,
    "gpt:" + DISK.upper(),
])
def test_invalid_disk_guid_rejected_even_when_snapshots_equal(disk_id):
    value = snapshot()
    value["partitionTableId"] = disk_id
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


@pytest.mark.parametrize("field, invalid", [
    ("partGuid", str(uuid.UUID(int=0))),
    ("typeGuid", str(uuid.UUID(int=0))),
    ("partGuid", "z" * 36),
    ("typeGuid", TYPE.upper()),
])
def test_invalid_partition_guid_rejected(field, invalid):
    value = snapshot()
    value["partitions"][0][field] = invalid
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(value, value)


@pytest.mark.parametrize("mutation", [
    "duplicate_guid", "overlap", "outside", "misaligned", "negative_attributes",
    "oversized_attributes", "unaligned_disk",
])
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
