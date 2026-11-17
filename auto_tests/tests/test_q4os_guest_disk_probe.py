"""Pure guest identity negative tests; no block devices or disk writes."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
from gaslux_q4os_guest_disk_probe import (  # noqa: E402
    canonical_guest_json,
    expected_virtio_serial,
    validate_guest_disk_report,
)
from gaslux_q4os_vm_target_plan import Q4osPlanRefusal  # noqa: E402

PLAN = {
    "runId": "q4os-ci-example-12345678",
    "nonce": "0123456789abcdef" * 2,
    "diskSizeBytes": 32 * 1024**3,
    "sectorBytes": 512,
    "diskGuid": "a1234567-1111-4111-8111-abcdefabcdef",
    "espStartLba": 2048,
    "espEndLba": 1050623,
    "espGuid": "12345678-1234-4123-8123-123456789abc",
    "espName": "GASLUX-LAB-ESP",
}


def report():
    return {
        "schemaVersion": 1,
        "runId": PLAN["runId"],
        "nonce": PLAN["nonce"],
        "device": "/dev/vda",
        "serial": expected_virtio_serial(PLAN),
        "sizeBytes": PLAN["diskSizeBytes"],
        "logicalSectorBytes": 512,
        "physicalSectorBytes": 512,
        "diskGuid": PLAN["diskGuid"],
        "partitions": [
            {
                "number": 1,
                "startLba": 2048,
                "endLba": 1050623,
                "typeGuid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                "partGuid": PLAN["espGuid"],
                "label": PLAN["espName"],
                "filesystem": "vfat",
            }
        ],
        "readOnlyProbe": True,
        "writeAttempted": False,
    }


def verify(item=None, raw=None):
    payload = canonical_guest_json(report() if item is None else item) if raw is None else raw
    return validate_guest_disk_report(
        payload, plan=PLAN, expected_serial=expected_virtio_serial(PLAN)
    )


def test_valid_observation_is_identity_only():
    result = verify()
    assert result["guestDiskIdentityVerified"] is True
    assert result["guestReportSha256"] == hashlib.sha256(canonical_guest_json(report())).hexdigest()
    for flag in (
        "installationAuthorized",
        "diskWritesAuthorized",
        "calamaresJobsAuthorized",
        "windowsEspWritesAuthorized",
        "rollbackVerified",
    ):
        assert result[flag] is False


@pytest.mark.parametrize(
    "key,value",
    [
        ("serial", "GQ4OS-WRONG"),
        ("sizeBytes", 1),
        ("logicalSectorBytes", 4096),
        ("diskGuid", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        ("runId", "replayed-run-123456"),
        ("nonce", "f" * 32),
        ("readOnlyProbe", False),
        ("writeAttempted", True),
        ("device", "/dev/sda"),
    ],
)
def test_guest_identity_mismatch_refused(key, value):
    item = report()
    item[key] = value
    with pytest.raises(Q4osPlanRefusal):
        verify(item)


@pytest.mark.parametrize(
    "field,value",
    [
        ("startLba", 2049),
        ("endLba", 1050622),
        ("typeGuid", "0fc63daf-8483-4772-8e79-3d69d8477de4"),
        ("partGuid", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        ("label", "EFI-WINDOWS"),
        ("filesystem", "ntfs"),
    ],
)
def test_esp_mismatch_refused(field, value):
    item = report()
    item["partitions"][0][field] = value
    with pytest.raises(Q4osPlanRefusal):
        verify(item)


def test_extra_partition_duplicate_key_and_oversize_refused():
    item = report()
    item["partitions"].append(dict(item["partitions"][0], number=2))
    with pytest.raises(Q4osPlanRefusal):
        verify(item)
    raw = canonical_guest_json(report()).rstrip()[:-1] + b',"writeAttempted":true}\n'
    with pytest.raises(Q4osPlanRefusal, match="Duplicate"):
        verify(raw=raw)
    with pytest.raises(Q4osPlanRefusal, match="size limit"):
        verify(raw=b" " * 16385)


def test_serial_changes_with_run_nonce():
    other = dict(PLAN, nonce="f" * 32)
    serial = expected_virtio_serial(other)
    assert serial != expected_virtio_serial(PLAN)
    assert len(serial.encode("ascii")) == 20
