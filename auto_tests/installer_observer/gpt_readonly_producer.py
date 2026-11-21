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
class GuestSliceProof:
    """Original in-memory libguestfs pread bytes; still same-runner trust."""

    first: bytes
    last: bytes
    device_label: str
    qemu_pid: int
    qemu_start_ticks: int


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
    guest_sample_origin: GuestSliceProof | None = None,
) -> Capture:
    """Read bytes with pread and validate the SAME disk via existing Safety parser.

    Guest mode requires a reconstruct_guest_sample output derived from actual
    libguestfs.pread_device bytes; never relabel a host image as a guest.
    """
    require(source in SOURCE_METHODS, "GPT_SOURCE_INVALID")
    require(
        (source == "guest" and isinstance(guest_sample_origin, GuestSliceProof))
        or (source != "guest" and guest_sample_origin is None),
        "GUEST_ORIGIN_MISSING",
    )
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
        if source == "guest":
            proof = guest_sample_origin
            require(
                path.name == "guest-reconstructed.raw"
                and isinstance(proof.first, bytes)
                and isinstance(proof.last, bytes)
                and len(proof.first) == 34 * logical_sector_size
                and len(proof.last) == 34 * logical_sector_size
                and isinstance(proof.device_label, str)
                and proof.device_label.startswith("gaslux")
                and len(proof.device_label) == 18
                and proof.qemu_pid > 1
                and proof.qemu_start_ticks > 0,
                "GUEST_ORIGIN_INVALID",
            )
            require(
                os.pread(fd, len(proof.first), 0) == proof.first
                and os.pread(fd, len(proof.last), first_stat.st_size - len(proof.last))
                == proof.last,
                "GUEST_SLICE_BYTES_MISMATCH",
            )
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
            "guestSampleDerivedFromLibguestfs": source == "guest",
            "guestDeviceLabel": (guest_sample_origin.device_label if source == "guest" else None),
            "guestProcessPid": (guest_sample_origin.qemu_pid if source == "guest" else None),
            "guestProcessStartTicks": (
                guest_sample_origin.qemu_start_ticks if source == "guest" else None
            ),
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



def capture_fresh_immediate(
    *,
    workspace: Path,
    overlay: Path,
    base: Path,
    host: Capture,
    lab: Any,
    safety_disk: Any,
    expected_overlay: os.stat_result,
    expected_base: os.stat_result,
    expected_chain: dict[str, Any],
    logical_sector_size: int,
) -> Capture:
    """Validate a new post-QEMU, read-only QCOW2 export; no independent trust."""
    output = workspace / "immediate.raw"
    historical = workspace / "host.raw"

    def same_owned(path: Path, original: os.stat_result) -> None:
        lab.same_file(path, workspace, original)
        current = own_file(path, workspace)
        attrs = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(
            tuple(getattr(current, key) for key in attrs)
            == tuple(getattr(original, key) for key in attrs),
            "OBSERVATION_INCOMPLETE",
        )

    try:
        require(
            workspace.is_absolute()
            and workspace.resolve(strict=True) == workspace
            and overlay == workspace / "overlay.qcow2"
            and base == workspace / "base.raw"
            and not output.exists()
            and not output.is_symlink()
            and host.source == "host"
            and host.trace["imageFile"] == str(historical),
            "OBSERVATION_INCOMPLETE",
        )
        historical_stat = own_file(historical, workspace)
        require(
            (historical_stat.st_dev, historical_stat.st_ino, historical_stat.st_size)
            == (
                host.trace["fileDev"],
                host.trace["fileInode"],
                host.trace["fileSizeBytes"],
            ),
            "OBSERVATION_INCOMPLETE",
        )
        require(
            expected_chain["format"] == "qcow2"
            and expected_chain["backingFormat"] == "raw"
            and expected_chain["backingFilename"] == str(base),
            "OBSERVATION_INCOMPLETE",
        )
        same_owned(overlay, expected_overlay)
        same_owned(base, expected_base)
        require(
            lab.verify_chain(overlay, base, workspace) == expected_chain,
            "OBSERVATION_INCOMPLETE",
        )

        # Existing pinned Safety host_snapshot does the actual qemu-img convert.
        lab.host_snapshot(overlay, output, workspace)

        same_owned(overlay, expected_overlay)
        same_owned(base, expected_base)
        require(
            lab.verify_chain(overlay, base, workspace) == expected_chain,
            "OBSERVATION_INCOMPLETE",
        )
        immediate = capture_gpt(
            output,
            workspace,
            source="immediate",
            logical_sector_size=logical_sector_size,
            safety_disk=safety_disk,
        )
        require(
            immediate.trace["imageFile"] == str(output)
            and (immediate.trace["fileDev"], immediate.trace["fileInode"])
            != (host.trace["fileDev"], host.trace["fileInode"])
            and immediate.observed_at >= host.observed_at
            and immediate.gpt == host.gpt
            and immediate.sectors == host.sectors,
            "OBSERVATION_INCOMPLETE",
        )
        same_owned(overlay, expected_overlay)
        same_owned(base, expected_base)
        require(
            lab.verify_chain(overlay, base, workspace) == expected_chain,
            "OBSERVATION_INCOMPLETE",
        )
        return immediate
    except Exception as exc:
        raise GptProducerRefused("OBSERVATION_INCOMPLETE") from exc


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
