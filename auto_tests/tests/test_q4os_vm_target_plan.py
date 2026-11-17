"""Synthetic sparse GPT read-only contract tests; never touch a physical block device."""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import uuid
import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))

from gaslux_q4os_vm_target_plan import (  # noqa: E402
    DISK_BYTES,
    DISK_SECTORS,
    ESP_END,
    ESP_START,
    GPT_ESP_GUID,
    OFFICIAL_ISO_SHA256,
    ROOT_END,
    ROOT_START,
    Q4osPlanRefusal,
    canonical_json,
    inspect_owned_vm_disk,
    propose_read_only_plan,
    verify_signed_read_only_plan,
)

RUN_ID = "q4os-ci-example-12345678"
NONCE = "0123456789abcdef" * 2


def _gpt_header(*, current, alternate, entries_lba, entry_crc, disk_guid):
    raw = bytearray(512)
    raw[:8] = b"EFI PART"
    struct.pack_into("<I", raw, 8, 0x00010000)
    struct.pack_into("<I", raw, 12, 92)
    struct.pack_into("<Q", raw, 24, current)
    struct.pack_into("<Q", raw, 32, alternate)
    struct.pack_into("<Q", raw, 40, 34)
    struct.pack_into("<Q", raw, 48, DISK_SECTORS - 34)
    raw[56:72] = disk_guid.bytes_le
    struct.pack_into("<Q", raw, 72, entries_lba)
    struct.pack_into("<I", raw, 80, 128)
    struct.pack_into("<I", raw, 84, 128)
    struct.pack_into("<I", raw, 88, entry_crc)
    struct.pack_into("<I", raw, 16, zlib.crc32(raw[:92]))
    return raw


def _create_synthetic_q4os_disk(workspace, *, extra=False, esp_name="GASLUX-LAB-ESP"):
    """Construct proper primary/backup GPT CRCs and FAT32 VBR in a sparse file."""
    disk = workspace / "efi-disk.img"
    with disk.open("xb") as fp:
        fp.truncate(DISK_BYTES)
        mbr = bytearray(512)
        mbr[446 + 4] = 0xEE
        struct.pack_into("<II", mbr, 446 + 8, 1, 0xFFFFFFFF)
        mbr[510:512] = b"\x55\xaa"
        fp.seek(0)
        fp.write(mbr)

        table = bytearray(128 * 128)
        table[:16] = GPT_ESP_GUID.bytes_le
        table[16:32] = uuid.UUID("12345678-1234-4123-8123-123456789abc").bytes_le
        struct.pack_into("<Q", table, 32, ESP_START)
        struct.pack_into("<Q", table, 40, ESP_END)
        name = esp_name.encode("utf-16-le")
        table[56 : 56 + len(name)] = name
        if extra:
            table[128:144] = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le
            table[144:160] = uuid.UUID("12345678-1234-4123-8123-123456789abd").bytes_le
            struct.pack_into("<Q", table, 128 + 32, ROOT_START)
            struct.pack_into("<Q", table, 128 + 40, ROOT_END)
        crc = zlib.crc32(table)
        disk_guid = uuid.UUID("a1234567-1111-4111-8111-abcdefabcdef")
        primary = _gpt_header(
            current=1, alternate=DISK_SECTORS - 1, entries_lba=2,
            entry_crc=crc, disk_guid=disk_guid,
        )
        backup = _gpt_header(
            current=DISK_SECTORS - 1, alternate=1, entries_lba=DISK_SECTORS - 33,
            entry_crc=crc, disk_guid=disk_guid,
        )
        fp.seek(512)
        fp.write(primary)
        fp.write(table)
        fp.seek((DISK_SECTORS - 33) * 512)
        fp.write(table)
        fp.write(backup)
        vbr = bytearray(512)
        struct.pack_into("<H", vbr, 11, 512)
        vbr[82:90] = b"FAT32   "
        vbr[510:512] = b"\x55\xaa"
        fp.seek(ESP_START * 512)
        fp.write(vbr)
    return disk


@pytest.fixture
def vm(tmp_path):
    disk = _create_synthetic_q4os_disk(tmp_path)
    evidence = inspect_owned_vm_disk(tmp_path, disk)
    return tmp_path, disk, evidence


@pytest.fixture
def signed(vm):
    workspace, disk, evidence = vm
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = propose_read_only_plan(evidence, run_id=RUN_ID, nonce=NONCE)

    def verify(*, plan=None, raw=None, sig=None, key=None, fingerprint=None, nonce=NONCE,
               run_id=RUN_ID, independent=None):
        if raw is None:
            raw = canonical_json(payload if plan is None else plan)
        if sig is None:
            sig = private.sign(b"GASLUX-Q4OS-VM-READONLY-TARGET-V1\n" + raw)
        return verify_signed_read_only_plan(
            raw, sig, public if key is None else key,
            trusted_public_key_sha256=(hashlib.sha256(public).hexdigest()
                                       if fingerprint is None else fingerprint),
            independently_expected_run_id=run_id,
            independently_expected_nonce=nonce,
            evidence=evidence if independent is None else independent,
        )

    return workspace, disk, evidence, payload, private, public, verify


def test_valid_signed_proposal_never_authorizes_writes(signed):
    _, _, evidence, payload, _, _, verify = signed
    result = verify()
    assert result["signatureVerified"] is True
    assert result["gptMetadataVerified"] is True
    assert result["rootExtentProposed"] is True
    assert result["installationAuthorized"] is False
    assert result["windowsEspWritesAuthorized"] is False
    assert result["diskWritesAuthorized"] is False
    assert result["rollbackVerified"] is False
    assert payload["isoSha256"] == OFFICIAL_ISO_SHA256
    assert payload["rootStartLba"] == ESP_END + 1
    assert payload["rootEndLba"] <= DISK_SECTORS - 34
    assert evidence["diskGuid"] == payload["diskGuid"]


@pytest.mark.parametrize("key,value", [
    ("distributionId", "popos"), ("backend", "system76"),
    ("firmwareLayout", "bios/mbr"), ("isoSha256", "f" * 64),
    ("installationAuthorized", True), ("guestOnly", False),
    ("windowsEspWritesAuthorized", True), ("calamaresJobsAuthorized", True),
    ("operation", "install"), ("rootEndLba", True),
    ("espEndLba", ESP_END + 1), ("rootStartLba", ESP_END),
    ("diskGuid", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
    ("gptPrimarySha256", "f" * 64), ("rootFilesystem", "btrfs"),
])
def test_even_re_signed_unsafe_manifest_is_rejected(signed, key, value):
    _, _, _, payload, _, _, verify = signed
    altered = dict(payload, **{key: value})
    with pytest.raises(Q4osPlanRefusal):
        verify(plan=altered)


def test_signature_tampering_domain_and_trust_anchor(signed):
    _, _, _, payload, private, _, verify = signed
    raw = canonical_json(payload)
    with pytest.raises(Q4osPlanRefusal, match="signature"):
        verify(raw=raw, sig=private.sign(b"WRONG-PROTOCOL\n" + raw))
    with pytest.raises(Q4osPlanRefusal, match="fingerprint"):
        verify(fingerprint="f" * 64)
    with pytest.raises(Q4osPlanRefusal, match="signature"):
        verify(sig=b"1" * 64)


def test_duplicate_properties_noncanonical_and_extra_property_refused(signed):
    _, _, _, payload, _, _, verify = signed
    raw = canonical_json(payload)
    bad = raw[:-2] + b',"nonce":"' + NONCE.encode() + b'"}\n'
    with pytest.raises(Q4osPlanRefusal, match="Duplicate"):
        verify(raw=bad)
    with pytest.raises(Q4osPlanRefusal, match="canonical"):
        verify(raw=b" " + raw)
    with pytest.raises(Q4osPlanRefusal, match="fields"):
        verify(plan=dict(payload, totallyUntrusted="value"))


def test_replay_and_independent_digest_mismatch_refused(signed):
    _, _, evidence, _, _, _, verify = signed
    for kwargs in ({"run_id": "another-run-12345678"}, {"nonce": "a" * 32},
                   {"independent": dict(evidence, gptBackupSha256="0" * 64)}):
        with pytest.raises(Q4osPlanRefusal):
            verify(**kwargs)


def test_gpt_detects_corrupt_primary_header(vm):
    workspace, disk, _ = vm
    with disk.open("r+b") as fp:
        fp.seek(512 + 56)
        fp.write(b"Z")
    with pytest.raises(Q4osPlanRefusal, match="CRC"):
        inspect_owned_vm_disk(workspace, disk)


def test_gpt_detects_corrupt_backup_table(vm):
    workspace, disk, _ = vm
    with disk.open("r+b") as fp:
        fp.seek((DISK_SECTORS - 33) * 512 + 123)
        fp.write(b"Z")
    with pytest.raises(Q4osPlanRefusal, match="entry bytes"):
        inspect_owned_vm_disk(workspace, disk)


def test_protective_mbr_rejects_hybrid(vm):
    workspace, disk, _ = vm
    with disk.open("r+b") as fp:
        fp.seek(446 + 16 + 4)
        fp.write(b"\x07")
    with pytest.raises(Q4osPlanRefusal, match="MBR"):
        inspect_owned_vm_disk(workspace, disk)


def test_crc_valid_second_partition_still_rejected(tmp_path):
    disk = _create_synthetic_q4os_disk(tmp_path, extra=True)
    with pytest.raises(Q4osPlanRefusal, match="Foreign or residual"):
        inspect_owned_vm_disk(tmp_path, disk)


def test_crc_valid_foreign_esp_name_refused(tmp_path):
    disk = _create_synthetic_q4os_disk(tmp_path, esp_name="EFI-WINDOWS")
    with pytest.raises(Q4osPlanRefusal, match="Foreign ESP"):
        inspect_owned_vm_disk(tmp_path, disk)


def test_symlink_hardlink_or_wrong_target_refused(vm):
    workspace, disk, _ = vm
    alias = workspace / "other.img"
    alias.symlink_to(disk)
    with pytest.raises(Q4osPlanRefusal):
        inspect_owned_vm_disk(workspace, alias)
    second = workspace / "hardlink"
    os.link(disk, second)
    with pytest.raises(Q4osPlanRefusal, match="exclusively owned"):
        inspect_owned_vm_disk(workspace, disk)


def test_wrong_disk_length_and_private_workspace(vm):
    workspace, disk, _ = vm
    with disk.open("r+b") as fp:
        fp.truncate(DISK_BYTES - 512)
    with pytest.raises(Q4osPlanRefusal, match="byte size"):
        inspect_owned_vm_disk(workspace, disk)
    disk.touch()
    workspace.chmod(0o755)
    with pytest.raises(Q4osPlanRefusal, match="private"):
        inspect_owned_vm_disk(workspace, disk)


def test_nonfat32_esp_fails_before_plan(vm):
    workspace, disk, _ = vm
    with disk.open("r+b") as fp:
        fp.seek(ESP_START * 512 + 82)
        fp.write(b"NOTFAT32")
    with pytest.raises(Q4osPlanRefusal, match="FAT32"):
        inspect_owned_vm_disk(workspace, disk)


def test_proposal_requires_independent_disk_evidence(vm):
    _, _, evidence = vm
    with pytest.raises(Q4osPlanRefusal, match="Incomplete"):
        propose_read_only_plan({"diskGuid": evidence["diskGuid"]}, run_id=RUN_ID, nonce=NONCE)
    with pytest.raises(Q4osPlanRefusal, match="run ID"):
        propose_read_only_plan(evidence, run_id="../etc/passwd", nonce=NONCE)
    with pytest.raises(Q4osPlanRefusal, match="nonce"):
        propose_read_only_plan(evidence, run_id=RUN_ID, nonce="0" * 31)


def test_signed_schema_matches_runtime_and_rejects_install_authority(signed):
    import json

    from gaslux_q4os_vm_target_plan import _PLAN_FIELDS
    from jsonschema import Draft202012Validator

    _, _, _, proposal, _, _, _ = signed
    schema_path = ROOT / "schemas" / "gaslux-q4os-vm-target-plan.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert set(schema["properties"]) == _PLAN_FIELDS
    Draft202012Validator(schema).validate(proposal)
    bad = dict(proposal, installationAuthorized=True)
    assert not Draft202012Validator(schema).is_valid(bad)
    bad = dict(proposal, vmFileInode=True)
    assert not Draft202012Validator(schema).is_valid(bad)


def test_valid_signature_for_a_cloned_disk_still_refused(tmp_path, signed):
    _, _, _, _, _, _, verify = signed
    cloned_dir = tmp_path / "different-owned-vm"
    cloned_dir.mkdir(mode=0o700)
    clone = _create_synthetic_q4os_disk(cloned_dir)
    clone_evidence = inspect_owned_vm_disk(cloned_dir, clone)
    with pytest.raises(Q4osPlanRefusal, match="vmFileInode"):
        verify(independent=clone_evidence)


def test_read_only_disk_revalidated_after_signing(signed):
    workspace, disk, _, payload, private, public, _ = signed
    from gaslux_q4os_vm_target_plan import verify_signed_plan_against_disk

    raw = canonical_json(payload)
    signature = private.sign(b"GASLUX-Q4OS-VM-READONLY-TARGET-V1\n" + raw)
    with disk.open("r+b") as fp:
        fp.seek(512 + 16)
        fp.write(bytes(4))
    with pytest.raises(Q4osPlanRefusal, match="CRC"):
        verify_signed_plan_against_disk(
            workspace,
            disk,
            raw,
            signature,
            public,
            trusted_public_key_sha256=hashlib.sha256(public).hexdigest(),
            independently_expected_run_id=RUN_ID,
            independently_expected_nonce=NONCE,
        )
