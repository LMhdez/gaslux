"""Synthetic, disposable Windows GPT read-only Q4OS safety contracts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import uuid
import zlib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / "assets/live").exists():
    ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "assets/live") if (ROOT / "assets/live").exists() else str(ROOT))
from gaslux_q4os_windows_boundary import (  # noqa: E402
    ESP,
    LINUX,
    MSR,
    WINRE,
    WINDOWS_DATA,
    Q4osWindowsBoundaryRefusal,
    inspect_private_raw_vm_disk,
    propose_read_only_native_target,
    verify_read_only_checkpoint,
    verify_windows_preservation,
)

SECTOR = 512
SECTORS = 131072
UUIDS = [str(uuid.UUID(int=i + 1)) for i in range(5)]
PARTS = [
    (ESP, UUIDS[0], 2048, 6143, "Windows ESP"),
    (MSR, UUIDS[1], 6144, 8191, "Microsoft reserved"),
    (WINDOWS_DATA, UUIDS[2], 8192, 49151, "Windows 10"),
    (WINRE, UUIDS[3], 49152, 53247, "Windows Recovery"),
    (str(uuid.UUID(int=666)), UUIDS[4], 53248, 55295, "OEM tools"),
]


def _header(lba: int, peer: int, part_lba: int, disk_guid: uuid.UUID, crc: int) -> bytes:
    header = bytearray(SECTOR)
    header[:8] = b"EFI PART"
    struct.pack_into("<IIII", header, 8, 0x10000, 92, 0, 0)
    struct.pack_into("<QQQQ", header, 24, lba, peer, 34, SECTORS - 34)
    header[56:72] = disk_guid.bytes_le
    struct.pack_into("<QIII", header, 72, part_lba, 128, 128, crc)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]) & 0xFFFFFFFF)
    return bytes(header)


def make_image(path: Path, parts=PARTS):
    with path.open("xb") as out:
        out.truncate(SECTORS * SECTOR)
    table = bytearray(128 * 128)
    for idx, (kind, guid, first, last, name) in enumerate(parts):
        start = idx * 128
        table[start : start + 16] = uuid.UUID(kind).bytes_le
        table[start + 16 : start + 32] = uuid.UUID(guid).bytes_le
        struct.pack_into("<QQQ", table, start + 32, first, last, 0)
        table[start + 56 : start + 56 + len(name) * 2] = name.encode("utf-16-le")
    crc = zlib.crc32(table) & 0xFFFFFFFF
    mbr = bytearray(SECTOR)
    mbr[446 + 4] = 0xEE
    struct.pack_into("<II", mbr, 446 + 8, 1, SECTORS - 1)
    mbr[510:512] = b"\x55\xaa"
    with path.open("r+b") as out:
        out.write(mbr)
        out.seek(SECTOR)
        out.write(_header(1, SECTORS - 1, 2, uuid.UUID(int=42), crc))
        out.seek(2 * SECTOR)
        out.write(table)
        out.seek((SECTORS - 33) * SECTOR)
        out.write(table)
        out.seek((SECTORS - 1) * SECTOR)
        out.write(_header(SECTORS - 1, 1, SECTORS - 33, uuid.UUID(int=42), crc))
        for kind, _id, first, _last, _name in parts:
            boot = bytearray(SECTOR)
            if kind == ESP:
                boot[82:90] = b"FAT32   "
                boot[510:512] = b"\x55\xaa"
            elif kind in (WINDOWS_DATA, WINRE):
                boot[3:11] = b"NTFS    "
            out.seek(first * SECTOR)
            out.write(boot)


@pytest.fixture
def lab(tmp_path):
    space = tmp_path / "private"
    space.mkdir(mode=0o700)
    disk = space / "windows-target.raw"
    make_image(disk)
    return space, disk


def _report(lab):
    return inspect_private_raw_vm_disk(*lab, sector_bytes=512)


def _candidate(current, **changes):
    args = dict(before=current, reread=current.copy(), start_lba=57344, end_lba=65535,
                calamares={"distribution": "q4os", "version": "6.10-deb13u1",
                            "nativeCalamaresConfigVerified": True,
                            "upstreamInstallsEfiFallback": True},
                hooks={"unownedEfiDebianWriteRiskObserved": True,
                       "forcedGrubInstallRiskObserved": True},
                checkpoint={"checkpointComparedToFullDisk": True,
                            "observedStateSha256": current["observedStateSha256"],
                            "checkpointRestoredAndBooted": False,
                            "checkpointSha256": "a" * 64})
    args.update(changes)
    return propose_read_only_native_target(**args)


def test_gpt_esp_winre_oem_readonly_evidence_and_blocked_plan(lab):
    before = _report(lab)
    assert len(before["partitions"]) == 5
    assert len(before["protectedPartitionSha256"]) == 4
    assert before["gptPrimarySha256"] != before["gptBackupSha256"]
    proposal = _candidate(before)
    assert proposal["proposedRootFilesystem"] == "ext4"
    assert proposal["windowsEspFallbackWriteBlocked"] is True
    assert proposal["efiDebianHookWriteBlocked"] is True
    assert all(proposal[key] is False for key in
               ("installationAuthorized", "calamaresJobsAuthorized", "diskWritesAuthorized",
                "windowsEspWritesAuthorized", "rollbackVerified"))
    assert verify_windows_preservation(before, _report(lab))["protectedContentPreserved"] is True


@pytest.mark.parametrize("offset", [510, 512, 1024, (SECTORS - 1) * 512, (SECTORS - 33) * 512])
def test_corruption_of_mbr_or_gpt_refuses(lab, offset):
    _, disk = lab
    with disk.open("r+b") as out:
        out.seek(offset)
        value = out.read(1)
        out.seek(offset)
        out.write(bytes([value[0] ^ 0x7F]))
    with pytest.raises(Q4osWindowsBoundaryRefusal):
        _report(lab)


def test_unlisted_or_missing_recovery_partition_refuses(lab):
    workspace, disk = lab
    disk.unlink()
    make_image(disk, PARTS[:3])
    with pytest.raises(Q4osWindowsBoundaryRefusal, match="WinRE"):
        _report((workspace, disk))


@pytest.mark.parametrize("where", ["esp", "winre", "oem"])
def test_preservation_detects_byte_change_without_gpt_change(lab, where):
    before = _report(lab)
    index = {"esp": 0, "winre": 3, "oem": 4}[where]
    with lab[1].open("r+b") as out:
        out.seek((PARTS[index][2] + 1) * SECTOR)
        out.write(b"UNAUTHORIZED")
    after = _report(lab)
    with pytest.raises(Q4osWindowsBoundaryRefusal, match="Protected partition"):
        verify_windows_preservation(before, after)


@pytest.mark.parametrize("first,last", [(8192, 8800), (2048, 2200), (53248, 54000),
                                         (57344, 57344), (57345, 65535),
                                         (130048, 131071)])
def test_target_extent_overlap_misalignment_and_metadata_refuses(lab, first, last):
    with pytest.raises(Q4osWindowsBoundaryRefusal):
        _candidate(_report(lab), start_lba=first, end_lba=last)


@pytest.mark.parametrize("change", [
    {"firmware_layout": "bios/mbr"},
    {"checkpoint": {}},
    {"checkpoint": {"checkpointComparedToFullDisk": True, "checkpointRestoredAndBooted": True}},
    {"calamares": {"distribution": "q4os", "version": "6.10-deb13u1",
                   "nativeCalamaresConfigVerified": True, "upstreamInstallsEfiFallback": False}},
    {"hooks": {"unownedEfiDebianWriteRiskObserved": False,
               "forcedGrubInstallRiskObserved": True}},
])
def test_refuse_unauthenticated_checkpoint_firmware_and_changed_calamares(lab, change):
    with pytest.raises(Q4osWindowsBoundaryRefusal):
        _candidate(_report(lab), **change)


def test_reread_mutated_disk_refuses(lab):
    original = _report(lab)
    drift = original.copy()
    drift["diskGuid"] = str(uuid.uuid4())
    with pytest.raises(Q4osWindowsBoundaryRefusal, match="drift"):
        _candidate(original, reread=drift)


def test_private_workspace_and_hardlink_refused(lab):
    workspace, disk = lab
    linked = workspace / "alias"
    os.link(disk, linked)
    with pytest.raises(Q4osWindowsBoundaryRefusal, match="Nonexclusive"):
        _report(lab)
    linked.unlink()
    workspace.chmod(0o755)
    with pytest.raises(Q4osWindowsBoundaryRefusal, match="Private"):
        _report(lab)


def test_qcow2_magic_and_sector_mismatch_refused(lab):
    with pytest.raises(Q4osWindowsBoundaryRefusal):
        inspect_private_raw_vm_disk(*lab, sector_bytes=4096)
    with lab[1].open("r+b") as out:
        out.seek(0)
        out.write(b"QFI\xfb")
    with pytest.raises(Q4osWindowsBoundaryRefusal, match="QCOW2"):
        _report(lab)


def test_checkpoint_requires_real_qemu_hash_and_full_compare(lab):
    workspace, disk = lab
    if shutil.which("qemu-img") is None:
        pytest.skip("qemu-img unavailable locally; GitHub Actions installs qemu-utils")
    folder = workspace / "checkpoints"
    folder.mkdir(mode=0o700)
    snapshot = folder / "recovery.qcow2"
    subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(disk), str(snapshot)],
                   check=True, capture_output=True)
    with snapshot.open("rb") as input_file:
        actual_hash = hashlib.file_digest(input_file, "sha256").hexdigest()
    report = verify_read_only_checkpoint(workspace, disk, snapshot, sector_bytes=512,
                                         expected_snapshot_sha256=actual_hash)
    assert report["checkpointComparedToFullDisk"] is True
    assert report["rollbackVerified"] is False
    restored = workspace / "restored-disposable.raw"
    subprocess.run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", str(snapshot),
                    str(restored)], check=True, capture_output=True)
    subprocess.run(["qemu-img", "compare", "-f", "raw", "-F", "raw", str(disk),
                    str(restored)], check=True, capture_output=True)
    with disk.open("rb") as original_file, restored.open("rb") as restored_file:
        assert hashlib.file_digest(original_file, "sha256").digest() == hashlib.file_digest(
            restored_file, "sha256"
        ).digest()
    proof_dir = os.getenv("GASLUX_Q4OS_WINDOWS_BOUNDARY_EVIDENCE")
    if proof_dir:
        evidence_path = Path(proof_dir)
        evidence_path.mkdir(parents=True, exist_ok=True)
        (evidence_path / "checkpoint-verified.json").write_text(
            json.dumps({"fixtureOnly": True, "qemuImgFullComparePassed": True,
                        "snapshotSha256": actual_hash, "readOnlyVerification": report,
                        "restoredWholeRawByteMatch": True, "guestBooted": False,
                        "windowsBootVerified": False, "calamaresExecuted": False,
                        "rollbackVerifiedOnRealWindows": False}, indent=2, sort_keys=True) + "\n"
        )
    with pytest.raises(Q4osWindowsBoundaryRefusal, match="SHA-256"):
        verify_read_only_checkpoint(workspace, disk, snapshot, sector_bytes=512,
                                    expected_snapshot_sha256="f" * 64)
    with disk.open("r+b") as f:
        f.seek(70000 * 512)
        f.write(b"UNPLANNED")
    with pytest.raises(Q4osWindowsBoundaryRefusal, match="QEMU checkpoint"):
        verify_read_only_checkpoint(workspace, disk, snapshot, sector_bytes=512,
                                    expected_snapshot_sha256=actual_hash)


def test_proposal_matches_json_schema(lab):
    schema_path = ROOT / "schemas/gaslux-q4os-windows-boundary.schema.json"
    if not schema_path.exists():
        schema_path = ROOT / "gaslux-q4os-windows-boundary.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    proposal = _candidate(_report(lab))
    Draft202012Validator(schema).validate(proposal)
    bad = proposal | {"installationAuthorized": True}
    with pytest.raises(Exception):
        Draft202012Validator(schema).validate(bad)
