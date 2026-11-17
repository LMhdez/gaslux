"""QEMU guest identity parser, transport and recovery-checkpoint contracts."""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import sys
import uuid
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))

from gaslux_q4os_guest_disk_probe import canonical_guest_json, expected_virtio_serial  # noqa: E402
from gaslux_q4os_qemu_identity_lab import (  # noqa: E402
    MAC_DOMAIN,
    Q4osQemuLabRefusal,
    sparse_content_sha256,
    verify_authenticated_report,
)
from gaslux_q4os_vm_target_plan import Q4osPlanRefusal  # noqa: E402
from q4os_guest_identity_agent import (  # noqa: E402
    ESP_TYPE_GUID,
    GuestProbeError,
    derive_virtio_serial,
    inspect_gpt_fd,
)

PLAN = {
    "runId": "q4os-ci-example-12345678",
    "nonce": "0123456789abcdef0123456789abcdef",
    "diskSizeBytes": 32 * 1024**3,
    "sectorBytes": 512,
    "diskGuid": "a1234567-1111-4111-8111-abcdefabcdef",
    "espStartLba": 2048,
    "espEndLba": 1050623,
    "espGuid": "12345678-1234-4123-8123-123456789abc",
    "espName": "GASLUX-LAB-ESP",
}


def guest_report() -> dict:
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
                "typeGuid": ESP_TYPE_GUID,
                "partGuid": PLAN["espGuid"],
                "label": PLAN["espName"],
                "filesystem": "vfat",
            }
        ],
        "blockDeviceReadOnly": True,
        "readOnlyProbe": True,
        "writeAttempted": False,
    }


def _header(
    *,
    current_lba: int,
    backup_lba: int,
    entries_lba: int,
    disk_guid: uuid.UUID,
    table_crc: int,
    disk_sectors: int,
) -> bytes:
    value = bytearray(512)
    value[:8] = b"EFI PART"
    struct.pack_into("<I", value, 8, 0x00010000)
    struct.pack_into("<I", value, 12, 92)
    struct.pack_into("<QQQQ", value, 24, current_lba, backup_lba, 34, disk_sectors - 34)
    value[56:72] = disk_guid.bytes_le
    struct.pack_into("<Q", value, 72, entries_lba)
    struct.pack_into("<III", value, 80, 128, 128, table_crc)
    struct.pack_into("<I", value, 16, zlib.crc32(value[:92]))
    return bytes(value)


def make_gpt_image(
    path: Path,
    *,
    corrupt_header: bool = False,
    corrupt_table: bool = False,
    hybrid_mbr: bool = False,
    extra_partition: bool = False,
    wrong_type: bool = False,
    bad_fat32: bool = False,
) -> tuple[int, int]:
    sectors = 32768
    disk_guid = uuid.UUID(PLAN["diskGuid"])
    part_guid = uuid.UUID(PLAN["espGuid"])
    table = bytearray(128 * 128)
    entry = bytearray(128)
    type_guid = (
        uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
        if wrong_type
        else uuid.UUID(ESP_TYPE_GUID)
    )
    entry[:16] = type_guid.bytes_le
    entry[16:32] = part_guid.bytes_le
    struct.pack_into("<QQQ", entry, 32, 2048, 8191, 0)
    label = PLAN["espName"].encode("utf-16le")
    entry[56 : 56 + len(label)] = label
    table[:128] = entry
    if extra_partition:
        second = bytearray(entry)
        second[16:32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQ", second, 32, 8192, 12287)
        table[128:256] = second
    table_crc = zlib.crc32(table)

    with path.open("wb") as disk:
        disk.truncate(sectors * 512)
        mbr = bytearray(512)
        mbr_entry = bytearray(16)
        mbr_entry[4] = 0x07 if hybrid_mbr else 0xEE
        struct.pack_into("<II", mbr_entry, 8, 1, sectors - 1)
        mbr[446:462] = mbr_entry
        mbr[510:512] = b"\x55\xaa"
        disk.seek(0)
        disk.write(mbr)
        disk.seek(2 * 512)
        disk.write(table)
        disk.seek((sectors - 33) * 512)
        disk.write(table)
        disk.seek(512)
        primary = _header(
            current_lba=1,
            backup_lba=sectors - 1,
            entries_lba=2,
            disk_guid=disk_guid,
            table_crc=table_crc,
            disk_sectors=sectors,
        )
        if corrupt_header:
            primary = primary[:24] + bytes([primary[24] ^ 1]) + primary[25:]
        disk.write(primary)
        disk.seek((sectors - 1) * 512)
        disk.write(
            _header(
                current_lba=sectors - 1,
                backup_lba=1,
                entries_lba=sectors - 33,
                disk_guid=disk_guid,
                table_crc=table_crc,
                disk_sectors=sectors,
            )
        )
        boot = bytearray(512)
        struct.pack_into("<H", boot, 11, 512)
        boot[13] = 1
        struct.pack_into("<H", boot, 14, 32)
        boot[16] = 2
        struct.pack_into("<H", boot, 22, 0)
        struct.pack_into("<I", boot, 36, 128)
        boot[82:90] = b"FAT32   " if not bad_fat32 else b"NTFS    "
        boot[510:512] = b"\x55\xaa"
        disk.seek(2048 * 512)
        disk.write(boot)
    if corrupt_table:
        with path.open("r+b") as disk:
            disk.seek(2 * 512 + 100)
            byte = disk.read(1)
            disk.seek(2 * 512 + 100)
            disk.write(bytes([byte[0] ^ 1]))
    return sectors * 512, sectors


def test_virtio_serial_is_exactly_twenty_bytes_and_matches_host_contract():
    guest = derive_virtio_serial(PLAN["runId"], PLAN["nonce"])
    host = expected_virtio_serial(PLAN)
    assert guest == host
    assert len(guest.encode("ascii")) == 20


def test_guest_gpt_probe_reads_primary_backup_and_fat32(tmp_path: Path):
    image = tmp_path / "disk.raw"
    size, _ = make_gpt_image(image)
    fd = os.open(image, os.O_RDONLY)
    try:
        result = inspect_gpt_fd(fd, disk_size_bytes=size, sector_bytes=512)
    finally:
        os.close(fd)
    assert result["diskGuid"] == PLAN["diskGuid"]
    assert result["partitions"] == [
        {
            "number": 1,
            "startLba": 2048,
            "endLba": 8191,
            "typeGuid": ESP_TYPE_GUID,
            "partGuid": PLAN["espGuid"],
            "label": PLAN["espName"],
            "filesystem": "vfat",
        }
    ]


@pytest.mark.parametrize(
    "options",
    [
        {"corrupt_header": True},
        {"corrupt_table": True},
        {"hybrid_mbr": True},
        {"extra_partition": True},
        {"wrong_type": True},
        {"bad_fat32": True},
    ],
)
def test_guest_gpt_probe_refuses_foreign_or_corrupt_layout(tmp_path: Path, options: dict):
    image = tmp_path / "bad-disk.raw"
    size, _ = make_gpt_image(image, **options)
    fd = os.open(image, os.O_RDONLY)
    try:
        with pytest.raises(GuestProbeError):
            inspect_gpt_fd(fd, disk_size_bytes=size, sector_bytes=512)
    finally:
        os.close(fd)


def test_guest_gpt_probe_refuses_unsupported_sector_size(tmp_path: Path):
    image = tmp_path / "disk.raw"
    size, _ = make_gpt_image(image)
    fd = os.open(image, os.O_RDONLY)
    try:
        with pytest.raises(GuestProbeError, match="geometry"):
            inspect_gpt_fd(fd, disk_size_bytes=size, sector_bytes=4096)
    finally:
        os.close(fd)


def test_hmac_authenticated_report_binds_plan_and_keeps_all_write_flags_false():
    secret = "ab" * 32
    raw = canonical_guest_json(guest_report())
    mac = hmac.new(secret.encode("ascii"), MAC_DOMAIN + raw, hashlib.sha256).hexdigest()
    result = verify_authenticated_report(raw, mac, challenge_secret=secret, plan=PLAN)
    assert result["guestDiskIdentityVerified"] is True
    assert result["transportAuthenticated"] is True
    assert result["blockDeviceReadOnly"] is True
    assert result["guestAttestation"] is False
    for flag in (
        "installationAuthorized",
        "diskWritesAuthorized",
        "calamaresJobsAuthorized",
        "windowsEspWritesAuthorized",
        "rollbackVerified",
    ):
        assert result[flag] is False


def test_hmac_mismatch_refused():
    secret = "cd" * 32
    raw = canonical_guest_json(guest_report())
    with pytest.raises(Q4osQemuLabRefusal, match="HMAC mismatch"):
        verify_authenticated_report(raw, "0" * 64, challenge_secret=secret, plan=PLAN)


@pytest.mark.parametrize("key", ["blockDeviceReadOnly", "readOnlyProbe", "writeAttempted"])
def test_authenticated_report_refuses_any_write_or_nonreadonly_claim(key: str):
    secret = "ef" * 32
    item = guest_report()
    item[key] = not item[key]
    raw = canonical_guest_json(item)
    mac = hmac.new(secret.encode("ascii"), MAC_DOMAIN + raw, hashlib.sha256).hexdigest()
    with pytest.raises(Q4osPlanRefusal):
        verify_authenticated_report(raw, mac, challenge_secret=secret, plan=PLAN)


def test_authenticated_report_refuses_replayed_or_wrong_disk_identity():
    secret = "11" * 32
    item = guest_report()
    item["nonce"] = "f" * 32
    raw = canonical_guest_json(item)
    mac = hmac.new(secret.encode("ascii"), MAC_DOMAIN + raw, hashlib.sha256).hexdigest()
    with pytest.raises(Q4osPlanRefusal):
        verify_authenticated_report(raw, mac, challenge_secret=secret, plan=PLAN)


def test_authenticated_report_refuses_oversized_payload_and_bad_secret():
    raw = canonical_guest_json(guest_report())
    with pytest.raises(Q4osQemuLabRefusal, match="length"):
        verify_authenticated_report(
            raw + b" " * 17000,
            "0" * 64,
            challenge_secret="ab" * 32,
            plan=PLAN,
        )
    with pytest.raises(Q4osQemuLabRefusal, match="secret"):
        verify_authenticated_report(raw, "0" * 64, challenge_secret="not-a-secret", plan=PLAN)


def test_sparse_checkpoint_digest_detects_allocated_data_change(tmp_path: Path):
    image = tmp_path / "sparse.raw"
    with image.open("wb") as stream:
        stream.truncate(8 * 1024 * 1024)
        stream.seek(1024 * 1024)
        stream.write(b"baseline")
    before = sparse_content_sha256(image)
    with image.open("r+b") as stream:
        stream.seek(1024 * 1024)
        stream.write(b"mutated!")
    assert sparse_content_sha256(image) != before


def test_sparse_checkpoint_digest_binds_file_size(tmp_path: Path):
    first = tmp_path / "first.raw"
    second = tmp_path / "second.raw"
    first.write_bytes(b"same")
    second.write_bytes(b"same-more")
    assert sparse_content_sha256(first) != sparse_content_sha256(second)
