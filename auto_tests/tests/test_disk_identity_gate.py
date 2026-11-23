"""Adversarial tests for the isolated, read-only GPT image identity gate."""
import importlib.util
import os
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


def make_image(path, *, corrupt_backup=False, corrupt_entries=False, part_id=PART_ID):
    sectors = 4096
    data = bytearray(sectors * SECTOR)
    data[446 + 4] = 0xee
    struct.pack_into("<II", data, 446 + 8, 1, sectors - 1)
    data[510:512] = b"\x55\xaa"
    entries = bytearray(128 * 128)
    entries[:16] = TYPE_ID.bytes_le
    entries[16:32] = part_id.bytes_le
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


@pytest.mark.parametrize("claimed_sectors", [0, 1, 4094, 4096, 0xffffffff])
def test_pmbr_extent_must_match_disk_geometry(snapshot, claimed_sectors):
    path, _ = snapshot
    original = path.read_bytes()
    mutated = bytearray(original)
    struct.pack_into("<I", mutated, 446 + 12, claimed_sectors)
    path.write_bytes(mutated)
    before = path.read_bytes()
    with pytest.raises(gate.DiskIdentityError, match="protective MBR extent"):
        gate.inspect_gpt_image(path, logical_sector_size=SECTOR)
    assert path.read_bytes() == before


def test_mbr_rejected_without_validated_ebr_chain(snapshot):
    _, expected = snapshot
    with pytest.raises(gate.DiskIdentityError):
        gate.assert_snapshot_matches(expected, {**expected, "partitionStyle": "MBR"})


def test_fd_pins_inode_despite_pathname_replacement(snapshot, tmp_path):
    path, expected = snapshot
    replacement = tmp_path / "replacement.img"
    make_image(replacement, part_id=uuid.UUID("12341234-1111-2222-3333-444455556666"))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.replace(replacement, path)
        observed = gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
        gate.assert_snapshot_matches(expected, observed)
        with pytest.raises(gate.DiskIdentityError):
            gate.assert_snapshot_matches(
                expected, gate.inspect_gpt_image(path, logical_sector_size=SECTOR)
            )
    finally:
        os.close(fd)


def test_fd_reader_never_reopens_a_path(snapshot, monkeypatch):
    path, expected = snapshot
    fd = os.open(path, os.O_RDONLY)
    try:
        def forbidden(*args, **kwargs):
            raise AssertionError("path opened after the caller pinned fd")
        with monkeypatch.context() as patch:
            patch.setattr(gate.os, "open", forbidden)
            actual = gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
        gate.assert_snapshot_matches(expected, actual)
    finally:
        os.close(fd)


def test_fd_preserves_caller_offset_and_ownership(snapshot):
    path, expected = snapshot
    fd = os.open(path, os.O_RDONLY)
    try:
        os.lseek(fd, 17, os.SEEK_SET)
        gate.assert_snapshot_matches(expected, gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR))
        assert os.lseek(fd, 0, os.SEEK_CUR) == 17
        assert os.fstat(fd).st_size == expected["sizeBytes"]
    finally:
        os.close(fd)


@pytest.mark.parametrize("fd_kind", ["write", "readwrite", "directory", "character", "closed", "bool"])
def test_fd_rejects_untrusted_descriptors(snapshot, tmp_path, fd_kind):
    path, _ = snapshot
    if fd_kind == "bool":
        with pytest.raises(gate.DiskIdentityError):
            gate.inspect_gpt_fd(True, logical_sector_size=SECTOR)
        return
    if fd_kind == "closed":
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
        with pytest.raises(gate.DiskIdentityError):
            gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
        return
    target, mode = {
        "write": (path, os.O_WRONLY),
        "readwrite": (path, os.O_RDWR),
        "directory": (tmp_path, os.O_RDONLY),
        "character": ("/dev/null", os.O_RDONLY),
    }[fd_kind]
    fd = os.open(target, mode)
    try:
        with pytest.raises(gate.DiskIdentityError):
            gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
    finally:
        os.close(fd)


def test_fd_rejects_in_place_mbr_mutation_during_read(snapshot, monkeypatch):
    path, _ = snapshot
    original = gate.read_header
    mutated = False

    def concurrent_change(fd, sector, lba, sectors):
        nonlocal mutated
        result = original(fd, sector, lba, sectors)
        if lba == sectors - 1 and not mutated:
            mutated = True
            with path.open("r+b") as writer:
                writer.seek(0)
                writer.write(b"X")
                writer.flush()
                os.fsync(writer.fileno())
        return result

    fd = os.open(path, os.O_RDONLY)
    try:
        monkeypatch.setattr(gate, "read_header", concurrent_change)
        with pytest.raises(gate.DiskIdentityError, match="changed during inspection"):
            gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
    finally:
        os.close(fd)


def test_fd_rejects_unrelated_content_mutation_during_read(snapshot, monkeypatch):
    path, _ = snapshot
    original = gate.read_header

    def concurrent_change(fd, sector, lba, sectors):
        result = original(fd, sector, lba, sectors)
        if lba == sectors - 1:
            with path.open("r+b") as writer:
                writer.seek(700 * sector)
                writer.write(b"X")
                writer.flush()
                os.fsync(writer.fileno())
        return result

    fd = os.open(path, os.O_RDONLY)
    try:
        monkeypatch.setattr(gate, "read_header", concurrent_change)
        with pytest.raises(gate.DiskIdentityError, match="changed during inspection"):
            gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
    finally:
        os.close(fd)


def test_fd_refuses_pathname_swap_during_gpt_read(snapshot, tmp_path, monkeypatch):
    path, _ = snapshot
    other = tmp_path / "replacement-during-read.img"
    make_image(other, part_id=uuid.UUID("12341234-1111-2222-3333-444455556666"))
    original = gate.read_header
    swapped = False

    def replace_after_primary(fd, sector, lba, sectors):
        nonlocal swapped
        result = original(fd, sector, lba, sectors)
        if lba == 1 and not swapped:
            swapped = True
            os.replace(other, path)
        return result

    fd = os.open(path, os.O_RDONLY)
    try:
        monkeypatch.setattr(gate, "read_header", replace_after_primary)
        # The descriptor is pinned, but unlinking its original name changes ctime.
        # Conservatively refuse instead of certifying an ambiguous snapshot.
        with pytest.raises(gate.DiskIdentityError, match="changed during inspection"):
            gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
        assert swapped
    finally:
        os.close(fd)


def test_fd_rejects_gpt_entries_mutated_after_initial_crc(snapshot, monkeypatch):
    path, _ = snapshot
    original = gate.read_header

    def mutate_after_backup(fd, sector, lba, sectors):
        result = original(fd, sector, lba, sectors)
        if lba == sectors - 1:
            with path.open("r+b") as writer:
                writer.seek(2 * sector + 16)
                writer.write(b"X")
                writer.flush()
                os.fsync(writer.fileno())
        return result

    fd = os.open(path, os.O_RDONLY)
    try:
        monkeypatch.setattr(gate, "read_header", mutate_after_backup)
        with pytest.raises(gate.DiskIdentityError, match="changed during inspection"):
            gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
    finally:
        os.close(fd)
