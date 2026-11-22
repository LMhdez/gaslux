#!/usr/bin/env python3
"""Read-only ESP/Recovery block-offset RCA on detached, owned A/B QCOW2.

No raw Windows bytes, driver/process attribution, boot authorization or repair.
An offset map is NOT evidence that Windows or Mint caused a block change.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from windows_cachyos_qcow2_gpt_readonly import VIRTUAL_BYTES
from windows_mint_ab_checkpoint import (
    AB_DIR,
    ARMS,
    REFERENCE,
    assert_detached_from_processes,
    file_guard,
    image_info,
    sha256_file,
)
from windows_mint_ab_forensic import gpt_manifest, write_manifest

SECTOR = 512
CHUNK_BYTES = 1024 * 1024
MAX_CHANGED_WINDOWS = 4096
PROTECTED = ((0, "esp"), (3, "recovery"))


class OffsetRcaError(RuntimeError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise OffsetRcaError(message)


def valid_hashes(hashes: object) -> bool:
    return (isinstance(hashes, list) and len(hashes) == 4
            and all(isinstance(h, str) and re.fullmatch(r"[a-f0-9]{64}", h)
                    for h in hashes))


def analyze_partition_windows(
    read_before, read_after, *, partition_bytes: int, disk_start_byte: int,
    expected_before_sha256: str, expected_after_sha256: str,
    chunk_bytes: int = CHUNK_BYTES, max_changed_windows: int = MAX_CHANGED_WINDOWS,
) -> dict:
    """Hash every byte of both snapshots; report only different bounded windows.

    read_before/read_after take (count, relative_offset) and return bytes.
    The stream comparison and full SHA-256 prevent treating partial reads as
    complete forensic data.
    """
    require(type(partition_bytes) is int and partition_bytes > 0
            and partition_bytes % SECTOR == 0
            and type(disk_start_byte) is int and disk_start_byte >= 0
            and disk_start_byte % SECTOR == 0
            and chunk_bytes == CHUNK_BYTES and max_changed_windows == MAX_CHANGED_WINDOWS
            and all(isinstance(x, str) and re.fullmatch(r"[a-f0-9]{64}", x)
                    for x in (expected_before_sha256, expected_after_sha256)),
            "BLOCKED_EVIDENCE: invalid fixed-size read-only offset profile")
    before_sha, after_sha = hashlib.sha256(), hashlib.sha256()
    differing = []
    changed_count = 0
    scanned = 0
    for pos in range(0, partition_bytes, chunk_bytes):
        count = min(chunk_bytes, partition_bytes - pos)
        a, b = read_before(count, pos), read_after(count, pos)
        require(isinstance(a, bytes) and isinstance(b, bytes)
                and len(a) == count and len(b) == count,
                "BLOCKED_EVIDENCE: partial or invalid libguestfs read")
        before_sha.update(a)
        after_sha.update(b)
        scanned += count
        if a != b:
            changed_count += 1
            if len(differing) < max_changed_windows:
                differing.append({
                    "partitionRelativeByteOffset": pos,
                    "diskAbsoluteByteOffset": disk_start_byte + pos,
                    "lengthBytes": count,
                    "beforeSha256": hashlib.sha256(a).hexdigest(),
                    "afterSha256": hashlib.sha256(b).hexdigest(),
                })
    before_digest, after_digest = before_sha.hexdigest(), after_sha.hexdigest()
    require(scanned == partition_bytes
            and before_digest == expected_before_sha256
            and after_digest == expected_after_sha256,
            "BLOCKED_EVIDENCE: protected partition digest or read length mismatch")
    return {
        "partitionBytesReadEachArm": scanned,
        "fullPartitionSha256Before": before_digest,
        "fullPartitionSha256After": after_digest,
        "changedWindowCount": changed_count,
        "windowByteGranularity": chunk_bytes,
        "listedChangedWindows": differing,
        "offsetMapComplete": changed_count <= max_changed_windows,
        "byteExactOffsetsProven": False,
        "fileAttributionProven": False,
        "writerAttributionProven": False,
    }


def _open_readonly(image: Path):
    import guestfs

    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.add_drive_opts(str(image), format="qcow2", readonly=1)
        guest.launch()
        devices = guest.list_devices()
        require(len(devices) == 1 and guest.blockdev_getsize64(devices[0])
                == VIRTUAL_BYTES, "BLOCKED_EVIDENCE: unexpected guest disk")
        device = devices[0]
        suffix = "p" if device[-1].isdigit() else ""
        parts = [device + suffix + str(i) for i in range(1, 6)]
        require(guest.list_partitions() == parts,
                "BLOCKED_EVIDENCE: guest partitions do not match fixed GPT layout")
        return guest, parts
    except Exception:
        try:
            guest.shutdown()
        finally:
            guest.close()
        raise


def _close(guest) -> None:
    try:
        guest.shutdown()
    finally:
        guest.close()


def compare_owned_ab_protected_offsets(
    *, directory: Path, reference: Path, observed: Path, evidence: Path,
    manifest_name: str, transaction_id: str,
    expected_gpt: dict, before_partition_sha256: list[str],
    after_partition_sha256: list[str],
) -> dict:
    """Optional diagnostic AFTER a guest was shut down; never launches a guest.

    Never accepts host block devices, arbitrary directories, shared backing,
    or non-standalone images. Evidence is append-only in its private directory.
    This capability does NOT bypass existing capacity/F-01/F-02/F-03 gates.
    """
    require(directory.name == AB_DIR and directory.is_dir()
            and not directory.is_symlink()
            and directory.stat().st_uid == os.getuid()
            and stat.S_IMODE(directory.stat().st_mode) == 0o700
            and reference == directory / REFERENCE
            and observed in {directory / name for name in ARMS}
            and evidence.is_dir() and not evidence.is_symlink()
            and evidence.stat().st_uid == os.getuid()
            and re.fullmatch(r"mint-ab-offset-(arm-a|arm-b)-[a-z-]+\.json", manifest_name)
            and isinstance(transaction_id, str) and 0 < len(transaction_id) <= 128
            and valid_hashes(before_partition_sha256)
            and valid_hashes(after_partition_sha256),
            "BLOCKED_EVIDENCE: source, transaction or output identity not approved")
    file_guard(reference, directory, 0o400)
    file_guard(observed, directory, 0o600)
    assert_detached_from_processes(reference)
    assert_detached_from_processes(observed)
    image_info(reference)
    image_info(observed)
    checkpoint_file = directory / "checkpoint.json"
    file_guard(checkpoint_file, directory)
    checkpoint = json.loads(checkpoint_file.read_bytes())
    require(checkpoint.get("transactionId") == transaction_id
            and checkpoint.get("checkpointReadyForReview") is True
            and checkpoint.get("qemuCompareReferenceBothArmsPassed") is True
            and checkpoint.get("sharedBackingChains") is False
            and checkpoint.get("referenceSha256") == sha256_file(reference)
            and checkpoint.get("productionInstallAuthorized") is False,
            "BLOCKED_EVIDENCE: checkpoint not authenticated")
    pre_info = gpt_manifest(reference, directory.parent)
    post_info = gpt_manifest(observed, directory.parent)
    require(pre_info == expected_gpt == post_info
            and pre_info.get("sectorBytes") == SECTOR
            and len(pre_info.get("partitionRanges", [])) == 5,
            "BLOCKED_EVIDENCE: GPT mismatch before offset acquisition")
    before_file_hash = sha256_file(reference)
    after_file_hash = sha256_file(observed)
    first, before_parts = _open_readonly(reference)
    try:
        second, after_parts = _open_readonly(observed)
        try:
            part_reports = {}
            for index, name in PROTECTED:
                span = pre_info["partitionRanges"][index]
                length = (span["lastLba"] - span["firstLba"] + 1) * SECTOR
                require(length > 0 and 0 <= span["firstLba"] <= span["lastLba"]
                        and span["lastLba"] * SECTOR < VIRTUAL_BYTES
                        and first.blockdev_getsize64(before_parts[index]) == length
                        and second.blockdev_getsize64(after_parts[index]) == length,
                        "BLOCKED_EVIDENCE: ESP/Recovery partition extent mismatch")
                part_reports[name] = {
                    "partitionIndex": index + 1,
                    "firstLba": span["firstLba"],
                    "lastLba": span["lastLba"],
                    **analyze_partition_windows(
                        lambda n, pos, part=before_parts[index]:
                            first.pread_device(part, n, pos),
                        lambda n, pos, part=after_parts[index]:
                            second.pread_device(part, n, pos),
                        partition_bytes=length,
                        disk_start_byte=span["firstLba"] * SECTOR,
                        expected_before_sha256=before_partition_sha256[index],
                        expected_after_sha256=after_partition_sha256[index],
                    ),
                }
        finally:
            _close(second)
    finally:
        _close(first)
    require(sha256_file(reference) == before_file_hash
            and sha256_file(observed) == after_file_hash,
            "BLOCKED_EVIDENCE: image changed during read-only acquisition")
    report = {
        "schema": "gaslux-mint-ab-protected-offset-diagnostic-v1",
        "transactionId": transaction_id,
        "checkpointManifestSha256": sha256_file(checkpoint_file),
        "referenceQcow2Sha256": before_file_hash,
        "observedQcow2Sha256": after_file_hash,
        "result": "PASS" if all(x["offsetMapComplete"] for x in part_reports.values())
                  else "PARTIAL_EVIDENCE",
        "partitions": part_reports,
        "readOnly": True,
        "windowsOrMintWriterAttribution": "UNKNOWN",
        "fileAttribution": "UNKNOWN_WITHOUT_CLUSTER_MAPPING",
        "historicalFourthWindowsOffsetsRecovered": False,
        "windowsInPlaceRollbackProven": False,
        "sameDiskDualBootVerified": False,
        "productionInstallAuthorized": False,
        "releaseEligible": False,
        "stable": False,
    }
    write_manifest(evidence, manifest_name, report)
    return report
