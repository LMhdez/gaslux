#!/usr/bin/env python3
"""Fail-closed, read-only Q4OS UEFI/GPT disposable-VM target plan contract.

No installed Linux, Calamares job, shared Windows ESP write or rollback
is authorized. A signature authenticates a *proposal*, not disk mutation.
The independent authority/nonce expected by a verifier is NOT in the plan.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import uuid
import zlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

OFFICIAL_ISO_SHA256 = "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d"
DISK_BYTES = 32 * 1024**3
SECTOR_BYTES = 512
DISK_SECTORS = DISK_BYTES // SECTOR_BYTES
ESP_START = 2048
ESP_END = 1050623
ROOT_START = ESP_END + 1
ROOT_END = ((DISK_SECTORS - 33) // 2048) * 2048 - 1
GPT_ESP_GUID = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
_DOMAIN = b"GASLUX-Q4OS-VM-READONLY-TARGET-V1\n"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_RUN = re.compile(r"[A-Za-z0-9_-]{12,100}\Z")
_PLAN_FIELDS = frozenset(
    {
        "schemaVersion", "distributionId", "backend", "firmwareLayout", "sourceKind",
        "isoSha256", "runId", "nonce", "diskSizeBytes", "sectorBytes", "diskGuid",
        "espGuid", "espName", "espStartLba", "espEndLba", "rootName",
        "vmFileDeviceId", "vmFileInode",
        "rootStartLba", "rootEndLba", "rootFilesystem", "gptPrimarySha256",
        "gptBackupSha256", "operation", "guestOnly", "installationAuthorized",
        "calamaresJobsAuthorized", "windowsEspWritesAuthorized",
    }
)


class Q4osPlanRefusal(ValueError):
    """The Q4OS VM evidence or signed proposal failed its trust boundary."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Q4osPlanRefusal(message)


def canonical_json(obj: dict) -> bytes:
    """Stable, domain-separated JSON; duplicate keys rejected on read."""
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode(
        "utf-8"
    )


def _read_u64(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", buf, offset)[0]


def _validate_gpt_header(buf: bytes, *, expected_lba: int, peer_lba: int, part_lba: int) -> dict:
    _require(buf[:8] == b"EFI PART", "Missing GPT header signature")
    _require(struct.unpack_from("<I", buf, 8)[0] == 0x00010000, "Unexpected GPT revision")
    size = struct.unpack_from("<I", buf, 12)[0]
    _require(size == 92 and buf[92:512] == b"\0" * 420, "Malformed GPT header length")
    crc = struct.unpack_from("<I", buf, 16)[0]
    header = bytearray(buf[:size])
    header[16:20] = b"\0" * 4
    _require(zlib.crc32(header) == crc, "GPT header CRC mismatch")
    _require(_read_u64(buf, 24) == expected_lba, "GPT header at unexpected LBA")
    _require(_read_u64(buf, 32) == peer_lba, "GPT cross-reference mismatch")
    _require(_read_u64(buf, 40) == 34, "GPT first usable sector mismatch")
    _require(_read_u64(buf, 48) == DISK_SECTORS - 34, "GPT last usable sector mismatch")
    _require(_read_u64(buf, 72) == part_lba, "GPT table LBA mismatch")
    entries_count, entry_size, entries_crc = struct.unpack_from("<III", buf, 80)
    _require(entries_count == 128 and entry_size == 128, "Unexpected GPT entry format")
    guid = uuid.UUID(bytes_le=buf[56:72])
    _require(guid.int != 0, "Empty GPT disk GUID")
    return {"guid": str(guid), "entriesCrc": entries_crc}


def _inspect_gpt(fd: int) -> dict:
    """Read exactly the two GPT tables and the protective MBR; never write."""
    def read(lba: int, n: int) -> bytes:
        raw = os.pread(fd, n * SECTOR_BYTES, lba * SECTOR_BYTES)
        _require(len(raw) == n * SECTOR_BYTES, "Truncated GPT disk image")
        return raw

    mbr = read(0, 1)
    _require(mbr[510:512] == b"\x55\xaa", "Missing protective MBR signature")
    entries = [mbr[446 + 16 * i : 446 + 16 * (i + 1)] for i in range(4)]
    _require(entries[0][0] == 0 and entries[0][4] == 0xEE, "Hybrid/nonprotective MBR")
    _require(struct.unpack_from("<I", entries[0], 8)[0] == 1, "Protective MBR start mismatch")
    _require(struct.unpack_from("<I", entries[0], 12)[0] == 0xFFFFFFFF, "MBR size mismatch")
    _require(all(x == bytes(16) for x in entries[1:]), "Foreign MBR partition")
    primary_h = read(1, 1)
    backup_h = read(DISK_SECTORS - 1, 1)
    primary = _validate_gpt_header(
        primary_h, expected_lba=1, peer_lba=DISK_SECTORS - 1, part_lba=2
    )
    backup = _validate_gpt_header(
        backup_h,
        expected_lba=DISK_SECTORS - 1,
        peer_lba=1,
        part_lba=DISK_SECTORS - 33,
    )
    _require(primary == backup, "Primary/backup GPT identity or CRC differs")
    table_a = read(2, 32)
    table_b = read(DISK_SECTORS - 33, 32)
    _require(table_a == table_b, "Primary/backup GPT entry bytes differ")
    _require(zlib.crc32(table_a) == primary["entriesCrc"], "GPT entry CRC mismatch")
    part = table_a[:128]
    _require(part[:16] == GPT_ESP_GUID.bytes_le, "Partition 1 is not an ESP")
    esp_guid = uuid.UUID(bytes_le=part[16:32])
    _require(esp_guid.int != 0, "Empty ESP partition GUID")
    _require(_read_u64(part, 32) == ESP_START, "ESP start differs from owned fixture")
    _require(_read_u64(part, 40) == ESP_END, "ESP end differs from owned fixture")
    _require(_read_u64(part, 48) == 0, "Unexpected ESP GPT flags")
    try:
        part_name = part[56:128].decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError as exc:
        raise Q4osPlanRefusal("Invalid ESP partition name") from exc
    _require(part_name == "GASLUX-LAB-ESP", "Foreign ESP partition label")
    _require(table_a[128:] == bytes(len(table_a) - 128), "Foreign or residual GPT entries")
    _require(ROOT_START <= ROOT_END <= DISK_SECTORS - 34, "Invalid proposed Linux extent")
    esp_vbr = read(ESP_START, 1)
    _require(esp_vbr[510:512] == b"\x55\xaa", "No FAT ESP boot-sector signature")
    _require(esp_vbr[82:90] == b"FAT32   ", "ESP is not FAT32")
    _require(struct.unpack_from("<H", esp_vbr, 11)[0] == SECTOR_BYTES, "ESP sector size mismatch")
    return {
        "diskGuid": primary["guid"],
        "espGuid": str(esp_guid),
        "gptPrimarySha256": hashlib.sha256(read(0, 34)).hexdigest(),
        "gptBackupSha256": hashlib.sha256(read(DISK_SECTORS - 33, 33)).hexdigest(),
    }


def inspect_owned_vm_disk(workspace: Path, disk: Path) -> dict:
    """Fail closed on arbitrary paths, symlinks, devices, hardlinks, foreign GPT."""
    _require(isinstance(workspace, Path) and workspace.is_absolute(), "Absolute workspace required")
    _require(isinstance(disk, Path) and disk.is_absolute(), "Absolute disk image path required")
    _require(disk.parent == workspace and disk.name == "efi-disk.img", "Foreign QEMU disk path")
    try:
        st_dir = workspace.lstat()
    except OSError as exc:
        raise Q4osPlanRefusal("Workspace does not exist") from exc
    _require(stat.S_ISDIR(st_dir.st_mode), "Workspace must be a physical directory")
    _require(st_dir.st_uid == os.getuid(), "Workspace not owned by current user")
    _require(st_dir.st_mode & 0o077 == 0, "Workspace must be private")
    # A symlink component anywhere in the workspace is rejected, not just its tail.
    current = workspace
    while current != current.parent:
        _require(not current.is_symlink(), "Symlink in workspace path")
        current = current.parent
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(disk, flags)
    except OSError as exc:
        raise Q4osPlanRefusal("Owned VM disk cannot be safely opened") from exc
    try:
        meta = os.fstat(fd)
        _require(stat.S_ISREG(meta.st_mode), "VM disk must be a regular file")
        _require(meta.st_uid == os.getuid() and meta.st_nlink == 1, "VM disk not exclusively owned")
        _require(meta.st_size == DISK_BYTES, "Unexpected VM disk byte size")
        evidence = _inspect_gpt(fd)
        post = os.fstat(fd)
        _require(
            (meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns, meta.st_ino, meta.st_dev)
            == (post.st_size, post.st_mtime_ns, post.st_ctime_ns, post.st_ino, post.st_dev),
            "VM disk changed during read-only GPT audit",
        )
        evidence.update(
            {
                "diskSizeBytes": DISK_BYTES,
                "vmFileDeviceId": meta.st_dev,
                "vmFileInode": meta.st_ino,
                "sectorBytes": SECTOR_BYTES,
                "espStartLba": ESP_START,
                "espEndLba": ESP_END,
                "rootStartLba": ROOT_START,
                "rootEndLba": ROOT_END,
            }
        )
        return evidence
    finally:
        os.close(fd)


def propose_read_only_plan(evidence: dict, *, run_id: str, nonce: str) -> dict:
    """Produce data for an independently signed laboratory *non-install* plan."""
    _require(type(run_id) is str and _RUN.fullmatch(run_id) is not None, "Unsafe run ID")
    _require(type(nonce) is str and _NONCE.fullmatch(nonce) is not None, "Unsafe nonce")
    for key in (
        "diskGuid", "espGuid", "gptPrimarySha256", "gptBackupSha256",
        "diskSizeBytes", "sectorBytes", "espStartLba", "espEndLba",
        "rootStartLba", "rootEndLba", "vmFileDeviceId", "vmFileInode",
    ):
        _require(key in evidence, "Incomplete independent GPT evidence")
    for key in ("gptPrimarySha256", "gptBackupSha256"):
        _require(
            type(evidence[key]) is str and _HEX64.fullmatch(evidence[key]) is not None,
            "Invalid GPT digest",
        )
    plan = {
        "schemaVersion": 1,
        "distributionId": "q4os",
        "backend": "q4os-native",
        "firmwareLayout": "uefi/gpt",
        "sourceKind": "native-live-calamares",
        "isoSha256": OFFICIAL_ISO_SHA256,
        "runId": run_id,
        "nonce": nonce,
        "diskGuid": evidence["diskGuid"],
        "espGuid": evidence["espGuid"],
        "espName": "GASLUX-LAB-ESP",
        "rootName": "GASLUX-Q4OS-ROOT",
        "rootFilesystem": "ext4",
        "operation": "read-only-plan",
        "guestOnly": True,
        "installationAuthorized": False,
        "calamaresJobsAuthorized": False,
        "windowsEspWritesAuthorized": False,
    }
    plan.update({key: evidence[key] for key in (
        "gptPrimarySha256", "gptBackupSha256", "diskSizeBytes", "sectorBytes",
        "espStartLba", "espEndLba", "rootStartLba", "rootEndLba",
        "vmFileDeviceId", "vmFileInode",
    )})
    return plan


def _decode_unique(raw: bytes) -> dict:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Q4osPlanRefusal("Duplicate signed JSON property")
            out[key] = value
        return out

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Q4osPlanRefusal:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise Q4osPlanRefusal("Unreadable signed Q4OS plan") from exc
    _require(type(result) is dict, "Signed Q4OS plan is not an object")
    _require(canonical_json(result) == raw, "Q4OS plan is not canonical JSON")
    _require(result.keys() == _PLAN_FIELDS, "Unknown/missing signed Q4OS plan fields")
    return result


def verify_signed_read_only_plan(
    raw_plan: bytes,
    signature: bytes,
    public_key: bytes,
    *,
    trusted_public_key_sha256: str,
    independently_expected_run_id: str,
    independently_expected_nonce: str,
    evidence: dict,
) -> dict:
    """Signature and separately observed disk facts; NEVER a write capability."""
    _require(type(raw_plan) is bytes and 0 < len(raw_plan) <= 8192, "Invalid plan size")
    _require(type(signature) is bytes and len(signature) == 64, "Invalid Ed25519 signature length")
    _require(type(public_key) is bytes and len(public_key) == 32, "Invalid Ed25519 public key")
    _require(
        type(trusted_public_key_sha256) is str
        and _HEX64.fullmatch(trusted_public_key_sha256) is not None
        and hashlib.sha256(public_key).hexdigest() == trusted_public_key_sha256,
        "Independent trusted public-key fingerprint mismatch",
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, _DOMAIN + raw_plan)
    except (InvalidSignature, ValueError) as exc:
        raise Q4osPlanRefusal("Q4OS plan signature rejected") from exc
    doc = _decode_unique(raw_plan)
    _require(
        type(independently_expected_run_id) is str
        and _RUN.fullmatch(independently_expected_run_id) is not None,
        "Expected run identity is missing",
    )
    _require(
        type(independently_expected_nonce) is str
        and _NONCE.fullmatch(independently_expected_nonce) is not None,
        "Expected nonce is missing",
    )
    independent_plan = propose_read_only_plan(
        evidence, run_id=independently_expected_run_id, nonce=independently_expected_nonce
    )
    for key, value in independent_plan.items():
        _require(
            type(doc.get(key)) is type(value) and doc.get(key) == value,
            "Signed Q4OS disk plan differs from independently verified evidence: " + key,
        )
    _require(doc == independent_plan, "Signed Q4OS plan contains unknown semantics")
    return {
        "signatureVerified": True,
        "gptMetadataVerified": True,
        "rootExtentProposed": True,
        "rootPartitionPresent": False,
        "guestDiskIdentityVerified": False,
        "isoBytesVerifiedInThisStep": False,
        "installationAuthorized": False,
        "calamaresJobsAuthorized": False,
        "diskWritesAuthorized": False,
        "windowsEspWritesAuthorized": False,
        "rollbackVerified": False,
        "evidenceSha256": hashlib.sha256(raw_plan).hexdigest(),
    }


def verify_signed_plan_against_disk(
    workspace: Path,
    disk: Path,
    raw_plan: bytes,
    signature: bytes,
    public_key: bytes,
    *,
    trusted_public_key_sha256: str,
    independently_expected_run_id: str,
    independently_expected_nonce: str,
) -> dict:
    """Re-read actual owner-checked VM GPT after signing; reject stale/replayed plan."""
    observed = inspect_owned_vm_disk(workspace, disk)
    return verify_signed_read_only_plan(
        raw_plan,
        signature,
        public_key,
        trusted_public_key_sha256=trusted_public_key_sha256,
        independently_expected_run_id=independently_expected_run_id,
        independently_expected_nonce=independently_expected_nonce,
        evidence=observed,
    )
