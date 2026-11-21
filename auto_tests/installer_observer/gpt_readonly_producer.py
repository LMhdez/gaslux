"""Bounded real GPT sector capture for disposable regular-file laboratory images.

Reuses Safety's pinned GPT parser/CRC validator at runtime; it is not a GPT
parser, QEMU attestor, guest input channel, plan approval or disk writer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import struct
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

MAX_LAB_BYTES = 512 * 1024 * 1024
SOURCE_METHODS = {
    "host": "host-readonly-pread",
    "guest": "guest-virtio-readonly-sector",
    "immediate": "immediate-readonly-pread",
}


class GptProducerRefused(ValueError):
    """Local capture or binding failed; never authorizes any mutations."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str) -> None:
    if not condition:
        raise GptProducerRefused(code)


def own_file(path: Path, parent: Path) -> os.stat_result:
    require(path.is_absolute() and path.parent == parent, "DISK_PATH_UNOWNED")
    require(parent.is_dir() and not parent.is_symlink(), "LAB_PARENT_UNSAFE")
    require(parent.resolve(strict=True) == parent, "LAB_PARENT_UNSAFE")
    st = os.lstat(path)
    require(
        stat.S_ISREG(st.st_mode)
        and st.st_uid == os.getuid()
        and st.st_nlink == 1
        and 0 < st.st_size <= MAX_LAB_BYTES,
        "DISK_FILE_UNSAFE",
    )
    return st


@dataclass(frozen=True)
class Capture:
    source: str
    method: str
    observed_at: str
    gpt: dict[str, Any]
    sectors: dict[str, Any]
    trace: dict[str, Any]
    trace_sha256: str


def capture_gpt(
    path: Path,
    workspace: Path,
    *,
    source: str,
    logical_sector_size: int,
    safety_disk: Any,
    guest_sample_origin: bool = False,
) -> Capture:
    """Read bytes with pread and validate the SAME disk via existing Safety parser.

    Guest mode requires a reconstruct_guest_sample output derived from actual
    libguestfs.pread_device bytes; never relabel a host image as a guest.
    """
    require(source in SOURCE_METHODS, "GPT_SOURCE_INVALID")
    require(source != "guest" or guest_sample_origin, "GUEST_ORIGIN_MISSING")
    require(
        logical_sector_size in (512, 4096) and type(logical_sector_size) is int,
        "SECTOR_SIZE_INVALID",
    )
    before = own_file(path, workspace)
    require(
        before.st_size % logical_sector_size == 0 and before.st_size >= 68 * logical_sector_size,
        "DISK_GEOMETRY_INVALID",
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        first_stat = os.fstat(fd)
        require(
            (first_stat.st_dev, first_stat.st_ino) == (before.st_dev, before.st_ino),
            "DISK_REPLACED",
        )
        sectors = first_stat.st_size // logical_sector_size
        # Existing Safety implementation validates protective MBR, both GPT
        # headers, CRCs, entries and exact GPT partition inventory.
        try:
            snapshot = safety_disk.inspect_gpt_image(path, logical_sector_size=logical_sector_size)
            primary = safety_disk.read_header(fd, logical_sector_size, 1, sectors)
            secondary = safety_disk.read_header(fd, logical_sector_size, sectors - 1, sectors)
        except (OSError, ValueError, IndexError, struct.error) as exc:
            raise GptProducerRefused("GPT_SECTOR_INVALID") from exc
        require(
            primary["entries"] == secondary["entries"]
            and primary["disk_guid"] == secondary["disk_guid"]
            and snapshot["partitionTableId"] == "gpt:" + primary["disk_guid"],
            "GPT_PRIMARY_BACKUP_MISMATCH",
        )
        samples: dict[str, dict[str, Any]] = {}
        raw_samples: dict[str, str] = {}
        for name, header, is_header in (
            ("primaryHeader", primary, True),
            ("primaryArray", primary, False),
            ("backupHeader", secondary, True),
            ("backupArray", secondary, False),
        ):
            offset = (
                header["current"] * logical_sector_size
                if is_header
                else header["array_lba"] * logical_sector_size
            )
            length = logical_sector_size if is_header else header["count"] * header["entry_size"]
            raw = safety_disk.exact_read(fd, offset, length)
            if is_header:
                header_length = struct.unpack_from("<I", raw, 12)[0]
                stored = struct.unpack_from("<I", raw, 16)[0]
                normalized = bytearray(raw[:header_length])
                normalized[16:20] = b"\x00" * 4
                require(zlib.crc32(normalized) == stored, "GPT_HEADER_CRC_INVALID")
                crc = stored
            else:
                require(raw == header["entries"], "GPT_ARRAY_BYTES_MISMATCH")
                crc = zlib.crc32(raw)
            samples[name] = {
                "offsetBytes": offset,
                "lengthBytes": length,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "crc32": crc,
            }
            raw_samples[name] = base64.b64encode(raw).decode("ascii")
        primary_header = samples["primaryHeader"]
        secondary_header = samples["backupHeader"]
        primary_array = samples["primaryArray"]
        secondary_array = samples["backupArray"]
        require(primary_array["crc32"] == secondary_array["crc32"], "GPT_ARRAY_CRC_MISMATCH")
        sector_claims = {
            "primaryHeaderLba": 1,
            "backupHeaderLba": sectors - 1,
            "primaryHeaderCrc32": primary_header["crc32"],
            "backupHeaderCrc32": secondary_header["crc32"],
            "primaryArrayCrc32": primary_array["crc32"],
            "backupArrayCrc32": secondary_array["crc32"],
            "primaryHeaderSha256": primary_header["sha256"],
            "backupHeaderSha256": secondary_header["sha256"],
            "primaryArraySha256": primary_array["sha256"],
            "backupArraySha256": secondary_array["sha256"],
        }
        end = os.fstat(fd)
        after = own_file(path, workspace)

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)

        require(
            identity(before) == identity(first_stat) == identity(end) == identity(after),
            "DISK_CHANGED_DURING_READ",
        )
        observed = datetime.now(UTC).isoformat()
        trace = {
            "source": source,
            "readMethod": SOURCE_METHODS[source],
            "readOnly": True,
            "labOnly": True,
            "guestSampleDerivedFromLibguestfs": guest_sample_origin,
            "imageFile": str(path),
            "fileDev": end.st_dev,
            "fileInode": end.st_ino,
            "fileSizeBytes": end.st_size,
            "logicalSectorSizeBytes": logical_sector_size,
            "observedAt": observed,
            "samples": samples,
            "sampleBytesBase64": raw_samples,
            "noInput": True,
            "productionWriteAuthorized": False,
            "classification": "NOT_INDEPENDENT",
        }
        encoded = json.dumps(
            trace, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return Capture(
            source,
            SOURCE_METHODS[source],
            observed,
            snapshot,
            sector_claims,
            trace,
            hashlib.sha256(encoded).hexdigest(),
        )
    finally:
        os.close(fd)


def build_safety_v1(
    captures: tuple[Capture, Capture, Capture],
    *,
    pins: Any,
    authority: Any,
    logical_sector_size: int,
    schema_path: Path,
    expected_observer_result_sha256: str,
) -> dict[str, Any]:
    """Produce a strict Safety v1 DIAGNOSTIC statement, with external parameters.

    Caller must independently verify the Observer state result; this function
    does not sign it or infer authenticity from the source of 'pins'.
    """
    require(
        tuple(c.source for c in captures) == ("host", "guest", "immediate"),
        "GUEST_MEASUREMENT_MISSING",
    )
    first = captures[0]
    require(
        all(c.gpt == first.gpt and c.sectors == first.sectors for c in captures),
        "GPT_THREE_WAY_MISMATCH",
    )
    require(
        logical_sector_size == first.gpt["logicalSectorSizeBytes"]
        and first.gpt["sizeBytes"] == pins.virtual_size_bytes
        and first.gpt["partitionTableId"] == pins.disk_id,
        "GPT_PIN_MISMATCH",
    )
    measurements = [
        {
            "source": c.source,
            "assurance": "LOCALLY_MEASURED",
            "readMethod": c.method,
            "observerId": authority.observer_id,
            "collectorId": authority.collector_id,
            "observedAt": c.observed_at,
            "qemuPid": pins.qemu_pid,
            "qemuStartTicks": pins.qemu_start_ticks,
            "deviceId": authority.device_id,
            "virtualSerial": pins.virtual_serial,
            "gpt": c.gpt,
            "gptSectors": c.sectors,
            "originProof": {
                "kind": "local-read-trace",
                "evidenceSha256": c.trace_sha256,
                "issuerId": authority.issuer_id,
            },
        }
        for c in captures
    ]
    statement = {
        "contractVersion": 1,
        "kind": "safety-gpt-provenance",
        "classification": "NOT_INDEPENDENT",
        "purpose": "read-only-diagnostic",
        "transactionId": pins.transaction_id,
        "vmUuid": pins.vm_uuid,
        "requestId": pins.request_id,
        "nonce": pins.nonce,
        "sequence": pins.sequence,
        "observerResultSha256": expected_observer_result_sha256,
        "issuer": {
            "issuerId": authority.issuer_id,
            "observerId": authority.observer_id,
            "collectorId": authority.collector_id,
            "controllerId": authority.controller_id,
            "policyId": authority.policy_id,
            "policySha256": authority.policy_sha256,
            "signingKeyId": authority.signing_key_id,
            "administrativeDomain": authority.administrative_domain,
        },
        "qemu": {
            "pid": pins.qemu_pid,
            "startTicks": pins.qemu_start_ticks,
            "executableSha256": authority.qemu_executable_sha256,
            "deviceId": authority.device_id,
            "virtualSerial": pins.virtual_serial,
            "virtualSizeBytes": pins.virtual_size_bytes,
            "logicalSectorSizeBytes": logical_sector_size,
        },
        "backingChain": [
            {
                "role": "overlay",
                "path": authority.overlay_path,
                "format": "qcow2",
                "sha256": pins.overlay_sha256,
                "virtualSizeBytes": pins.virtual_size_bytes,
                "backingFilename": pins.backing_filename,
                "backingFormat": "raw",
                "deviceId": authority.overlay_device_id,
                "inode": authority.overlay_inode,
            },
            {
                "role": "parent",
                "path": pins.backing_filename,
                "format": "raw",
                "sha256": pins.backing_sha256,
                "virtualSizeBytes": pins.virtual_size_bytes,
                "backingFilename": None,
                "backingFormat": None,
                "deviceId": authority.parent_device_id,
                "inode": authority.parent_inode,
            },
        ],
        "measurements": measurements,
        "writeAuthorized": False,
    }
    # The result digest is an explicit parameter, never inferred from host bytes.
    require(
        isinstance(expected_observer_result_sha256, str)
        and len(expected_observer_result_sha256) == 64
        and all(c in "0123456789abcdef" for c in expected_observer_result_sha256),
        "OBSERVER_RESULT_NOT_VERIFIED",
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(statement)
    return statement
