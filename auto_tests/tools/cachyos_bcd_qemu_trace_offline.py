#!/usr/bin/env python3
"""Offline parser for the *actual* QEMU -trace simple text output (no VM).

Never assumes that a blk pointer identifies Windows. No ETW data and no
process identity are present in the original traces. A synthetic-only binding
exists to test the interval algorithm; it is not a production attestation.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import re
from typing import Any

MAX_TRACE_BYTES = 10 * 1024 * 1024
MAX_TRACE_LINES = 200000
MAX_WRITE_BYTES = 16 * 1024 * 1024
MAX_DISK_BYTES = 8 * 1024 ** 4
BLK_WRITE = re.compile(
    r"blk_co_pwritev blk (0x[0-9a-f]+) bs (0x[0-9a-f]+) "
    r"offset (0|[1-9][0-9]*) bytes ([1-9][0-9]*) flags (0x[0-9a-f]+)"
)
KNOWN_EVENTS = frozenset((
    "blk_co_pwritev", "bdrv_co_pwritev_part",
    "bdrv_co_pwrite_zeroes", "qcow2_writev_start_part",
    "qcow2_writev_done_part", "qcow2_writev_data",
    "qcow2_writev_start_req", "qcow2_writev_done_req",
    "qcow2_l2_allocate_write_l1", "qcow2_l2_allocate_write_l2",
    "qcow2_pwrite_zeroes", "qcow2_pwrite_zeroes_start_req",
    "virtio_blk_handle_write",
))


class QemuTraceError(ValueError):
    pass


def require(ok: bool, error: str) -> None:
    if not ok:
        raise QemuTraceError(error)


def _overlap(a: int, n: int, b: int, m: int) -> int:
    return max(0, min(a + n, b + m) - max(a, b))


def parse_qemu_trace(trace: bytes) -> dict[str, Any]:
    require(type(trace) is bytes and 0 < len(trace) <= MAX_TRACE_BYTES
            and trace.endswith(b"\n") and b"\x00" not in trace,
            "invalid, truncated or oversized QEMU simple trace")
    try:
        lines = trace.decode("ascii").splitlines()
    except UnicodeDecodeError as e:
        raise QemuTraceError("non-ASCII QEMU trace") from e
    require(0 < len(lines) <= MAX_TRACE_LINES,
            "QEMU trace contains too many records")
    records = []
    handles: Counter[str] = Counter()
    for index, line in enumerate(lines):
        require(0 < len(line) <= 1024, "unsafe QEMU trace line length")
        name = line.split(" ", 1)[0]
        require(name in KNOWN_EVENTS, "unexpected QEMU trace event")
        if name != "blk_co_pwritev":
            continue
        matched = BLK_WRITE.fullmatch(line)
        require(matched is not None, "malformed blk_co_pwritev QEMU record")
        handle, bs, offset, length, flags = matched.groups()
        off, n = int(offset), int(length)
        require(0 <= off < MAX_DISK_BYTES and 0 < n <= MAX_WRITE_BYTES
                and off + n <= MAX_DISK_BYTES,
                "QEMU trace write interval invalid")
        handles[handle] += 1
        records.append({
            "ordinal": index, "blkPointer": handle, "bsPointer": bs,
            "diskOffsetCandidate": off, "length": n, "flags": flags,
            # The original trace has no timestamp; ordinal is not wall clock.
            "timestampNs": None,
        })
    require(bool(records), "no top-level QEMU block writes observed")
    return {
        "status": "QEMU_TRACE_PARSED_NODE_UNBOUND",
        "traceSha256": hashlib.sha256(trace).hexdigest(),
        "eventCount": len(lines),
        "blockWriteCount": len(records),
        "blkPointers": dict(sorted(handles.items())),
        "timestampsPresent": False,
        "sourceHasDiskIdentityAttestation": False,
        "processAttributionProven": False,
        "records": records,
    }


def correlate_qemu_writes(
    parsed: dict[str, Any], *, disk_bytes: int, esp_start_lba: int,
    esp_end_lba: int, fat32_map: dict[str, Any] | None = None,
    synthetic_fixture_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Report overlaps, never confirmed BCD modification or process authorship.

    Without independent block-node attestation, historical events are only
    geometric candidates. Synthetic fixture binding is explicitly TEST ONLY.
    """
    require(type(parsed) is dict and type(parsed.get("records")) is list
            and parsed.get("sourceHasDiskIdentityAttestation") is False
            and parsed.get("processAttributionProven") is False,
            "unexpected/untrusted QEMU trace parser result")
    require(all(type(x) is int for x in
                (disk_bytes, esp_start_lba, esp_end_lba))
            and 0 <= esp_start_lba <= esp_end_lba
            and 0 < disk_bytes <= MAX_DISK_BYTES
            and (esp_end_lba + 1) * 512 <= disk_bytes,
            "invalid virtual disk/GPT geometry")
    esp_start, esp_end = esp_start_lba * 512, (esp_end_lba + 1) * 512
    if fat32_map is not None:
        require(type(fat32_map) is dict
                and fat32_map.get("status") == "FAT32_STRUCTURAL_MAP_ONLY"
                and fat32_map.get("espStartLba") == esp_start_lba
                and fat32_map.get("espEndLba") == esp_end_lba
                and fat32_map.get("diskBytes") == disk_bytes
                and fat32_map.get("imageProvenanceAuthenticated") is False,
                "BCD FAT32 map lacks matching geometry or expected trust level")
    fixture_ptr = None
    if synthetic_fixture_binding is not None:
        proof = synthetic_fixture_binding
        require(type(proof) is dict
                and set(proof) == {"scope", "blkPointer", "traceSha256"}
                and proof["scope"] == "SYNTHETIC_FIXTURE_ONLY"
                and type(proof["blkPointer"]) is str
                and proof["blkPointer"] in parsed["blkPointers"]
                and proof["traceSha256"] == parsed["traceSha256"],
                "synthetic-only fixture binding invalid")
        fixture_ptr = proof["blkPointer"]
    counts: Counter[str] = Counter()
    examples: list[dict[str, Any]] = []
    overlapped_events = 0
    distinct_offsets: set[int] = set()
    for rec in parsed["records"]:
        off, n = rec["diskOffsetCandidate"], rec["length"]
        if not _overlap(off, n, esp_start, esp_end - esp_start):
            continue
        overlapped_events += 1
        distinct_offsets.add(off)
        # Block pointers cannot be assigned to a disk by ordering or naming.
        if (fixture_ptr is None or rec["blkPointer"] != fixture_ptr
                or fat32_map is None):
            categories = ["UNMAPPED_ESP_WRITE", "PROCESS_UNATTRIBUTED"]
        else:
            data = fat32_map["bcdDataExtents"]
            meta = fat32_map["fat32MetadataExtents"]
            if any(_overlap(off, n, e["diskOffset"], e["length"]) for e in data):
                kind = "BCD_DATA_SECTOR_OVERLAP"
            elif any(_overlap(off, n, e["diskOffset"], e["length"]) for e in meta):
                kind = "FAT32_METADATA_OVERLAP"
            else:
                kind = "ESP_OTHER_SECTOR_OVERLAP"
            categories = [kind, "PROCESS_UNATTRIBUTED"]
        for category in categories:
            counts[category] += 1
        if len(examples) < 64:
            examples.append({
                "ordinal": rec["ordinal"], "offset": off,
                "length": n, "categories": categories,
            })
    return {
        "status": ("SYNTHETIC_GEOMETRY_CLASSIFIED_NOT_ATTESTED"
                   if fixture_ptr is not None and fat32_map is not None
                   else "UNMAPPED_ESP_WRITE"),
        "traceSha256": parsed["traceSha256"],
        "qemuBlkNodeToDiskAuthenticated": False,
        "fat32ImageProvenanceAuthenticated": False,
        "bcdModificationConfirmed": False,
        "processAttributionProven": False,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
        "espCandidateWriteCount": overlapped_events,
        "distinctEspCandidateWriteOffsets": len(distinct_offsets),
        "classificationCounts": dict(sorted(counts.items())),
        "first64OverlapExamples": examples,
        "hasTimestamps": False,
    }


def analyze_historical_trace(trace: bytes, *, arm: str) -> dict[str, Any]:
    """No FAT32 image nor independently proven blk->disk mapping in the ZIP."""
    require(arm in ("WINDOWS_ONLY_A", "POST_PACSTRAP_B"),
            "unknown historical arm")
    parsed = parse_qemu_trace(trace)
    result = correlate_qemu_writes(
        parsed, disk_bytes=128 * 1024**3,
        esp_start_lba=2048, esp_end_lba=534527,
    )
    return {
        "arm": arm,
        "mapping": "BCD_PHYSICAL_MAPPING_UNAVAILABLE",
        "traceSha256": parsed["traceSha256"],
        "blockWrites": parsed["blockWriteCount"],
        "pointerCounts": parsed["blkPointers"],
        "candidateEspOverlapCount": result["espCandidateWriteCount"],
        "candidateEspUniqueOffsets": result["distinctEspCandidateWriteOffsets"],
        "processAttribution": "PROCESS_ATTRIBUTION_UNPROVEN",
        "qemuNodeBindingAuthenticated": False,
        "approvedMutation": False,
    }
