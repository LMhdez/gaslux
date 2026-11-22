"""Offline destination assessment using real Linux FD/QEMU observations.

No external trust root is supplied. The name describes the *goal*, not a
claim that independent destination, QEMU backend or guest authentication exists.
No disk, guest, QMP control or storage writer is exposed.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

from assets.live.libertix_disk_identity_gate import (
    DiskIdentityError,
    assert_snapshot_matches,
    inspect_gpt_fd,
)

from .qemu_local_disk_witness import (
    QemuDiskPins,
    QemuDiskRefused,
    QemuLocalDiskWitness,
)

MAX_BYTES = 512 * 1024 * 1024  # Maximum per-file full SHA-256 work budget.
MAX_SCALE_VIRTUAL_BYTES = 128 * 1024 * 1024 * 1024  # Metadata-only upper bound.
QCOW2_HEADER_READ_BYTES = 32
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class DestinationRefused(ValueError):
    """A required local observation or invariant did not hold."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise DestinationRefused(reason)


def _stat_identity(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _pin(
    fd: int, path: Path, workspace: Path, *, max_file_bytes: int = MAX_BYTES
) -> os.stat_result:
    require(
        type(max_file_bytes) is int and 0 < max_file_bytes <= MAX_SCALE_VIRTUAL_BYTES,
        "SIZE_BUDGET_INVALID",
    )
    require(type(fd) is int and fd >= 0, "FOREIGN_FD")
    require(
        type(path) is type(Path())
        and path.is_absolute()
        and path.parent == workspace
        and not path.is_symlink(),
        "UNOWNED_PATH",
    )
    try:
        before = path.lstat()
        opened = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as exc:
        raise DestinationRefused("FD_UNAVAILABLE") from exc
    require(
        stat.S_ISREG(before.st_mode)
        and stat.S_ISREG(opened.st_mode)
        and before.st_nlink == opened.st_nlink == 1
        and opened.st_uid == before.st_uid == os.getuid()
        and 0 < opened.st_size <= max_file_bytes
        and (flags & os.O_ACCMODE) == os.O_RDONLY
        and not (flags & getattr(os, "O_PATH", 0))
        and _stat_identity(before) == _stat_identity(opened),
        "FD_ALIAS_OR_WRITABLE_FILE",
    )
    return opened


def _digest(fd: int, expected: str) -> str:
    require(type(expected) is str and bool(HEX64.fullmatch(expected)), "HASH_PIN_INVALID")
    initial = os.fstat(fd)
    require(0 < initial.st_size <= MAX_BYTES, "HASH_RESOURCE_LIMIT")
    sha = hashlib.sha256()
    for offset in range(0, initial.st_size, 1024 * 1024):
        want = min(1024 * 1024, initial.st_size - offset)
        chunk = os.pread(fd, want, offset)
        require(len(chunk) == want, "FD_SHORT_READ")
        sha.update(chunk)
    require(_stat_identity(initial) == _stat_identity(os.fstat(fd)), "FD_MUTATED_DURING_HASH")
    actual = sha.hexdigest()
    require(actual == expected, "PINNED_HASH_MISMATCH")
    return actual


def _allocated_bytes(st: os.stat_result) -> int:
    """Measure resident filesystem blocks, not nominal sparse file length."""
    require(type(st.st_blocks) is int and st.st_blocks >= 0, "SCALE_ALLOCATION_UNAVAILABLE")
    allocated = st.st_blocks * 512
    require(allocated >= 0, "SCALE_ALLOCATION_UNAVAILABLE")
    return allocated


def probe_destination_scale_metadata(
    *,
    qcow2_fd: int,
    qcow2_path: Path,
    backing_fd: int,
    backing_path: Path,
    workspace: Path,
) -> dict[str, Any]:
    """Bounded 128-GiB *metadata* probe; NEVER a destination authentication.

    Reads exactly the 32-byte QCOW2 header from a caller-pinned read-only FD,
    and measures a separate read-only RAW backing using fstat only. No complete
    backing hash, guest-visible QCOW2 GPT, checkpoint or QEMU mapping is
    authenticated. This function cannot authorize any writer.
    """
    require(type(workspace) is type(Path()) and workspace.is_absolute(), "SCALE_WORKSPACE")
    try:
        ws = workspace.lstat()
        require(
            stat.S_ISDIR(ws.st_mode)
            and not workspace.is_symlink()
            and workspace.resolve(strict=True) == workspace
            and ws.st_uid == os.getuid()
            and (stat.S_IMODE(ws.st_mode) & 0o077) == 0,
            "SCALE_WORKSPACE",
        )
    except OSError as exc:
        raise DestinationRefused("SCALE_WORKSPACE") from exc
    require(qcow2_path != backing_path, "ALIASING_DESTINATION_RESOURCES")
    overlay = _pin(qcow2_fd, qcow2_path, workspace)
    backing = _pin(backing_fd, backing_path, workspace, max_file_bytes=MAX_SCALE_VIRTUAL_BYTES)
    require(
        overlay.st_size >= 72
        and 68 * 512 <= backing.st_size <= MAX_SCALE_VIRTUAL_BYTES
        and backing.st_size % 512 == 0,
        "SCALE_GEOMETRY_INVALID",
    )
    overlay_allocated = _allocated_bytes(overlay)
    backing_allocated = _allocated_bytes(backing)
    require(
        overlay_allocated + backing_allocated <= MAX_BYTES,
        "SCALE_PHYSICAL_BUDGET_EXCEEDED",
    )
    try:
        header = os.pread(qcow2_fd, QCOW2_HEADER_READ_BYTES, 0)
        stats = os.statvfs(workspace)
    except OSError as exc:
        raise DestinationRefused("SCALE_METADATA_READ_FAILED") from exc
    require(len(header) == QCOW2_HEADER_READ_BYTES, "SCALE_HEADER_SHORT_READ")
    require(
        header[:4] == b"QFI\xfb" and int.from_bytes(header[4:8], "big") in (2, 3),
        "QCOW2_HEADER_INVALID",
    )
    virtual_bytes = int.from_bytes(header[24:32], "big")
    require(
        68 * 512 <= virtual_bytes <= MAX_SCALE_VIRTUAL_BYTES and virtual_bytes == backing.st_size,
        "SCALE_VIRTUAL_BACKING_MISMATCH",
    )
    require(stats.f_frsize > 0 and stats.f_bavail >= 0, "SCALE_RESOURCES_UNKNOWN")
    free_estimate = stats.f_frsize * stats.f_bavail
    for fd, path, pinned in (
        (qcow2_fd, qcow2_path, overlay),
        (backing_fd, backing_path, backing),
    ):
        try:
            now = os.fstat(fd)
            present = path.lstat()
        except OSError as exc:
            raise DestinationRefused("SCALE_SOURCE_CHANGED") from exc
        require(
            _stat_identity(now) == _stat_identity(present) == _stat_identity(pinned)
            and _allocated_bytes(now) == _allocated_bytes(pinned),
            "SCALE_SOURCE_CHANGED",
        )
    # A capacity estimate is neither a reservation nor a recovery checkpoint.
    capacity_insufficient = free_estimate < virtual_bytes
    return {
        "status": (
            "READONLY_SCALE_CAPACITY_INSUFFICIENT"
            if capacity_insufficient
            else "READONLY_SCALE_METADATA_ONLY"
        ),
        "reasonCode": (
            "INSUFFICIENT_CHECKPOINT_SPACE"
            if capacity_insufficient
            else "FULL_HASH_AND_CHECKPOINT_NOT_VERIFIED"
        ),
        "authorization": "DENY_NO_WRITER",
        "qcow2HeaderBytesRead": QCOW2_HEADER_READ_BYTES,
        "qcow2FileSizeBytes": overlay.st_size,
        "qcow2AllocatedBytes": overlay_allocated,
        "virtualSizeBytes": virtual_bytes,
        "backingFileSizeBytes": backing.st_size,
        "backingAllocatedBytes": backing_allocated,
        "backingIsSparse": backing_allocated < backing.st_size,
        "fullHashBytesRequired": overlay.st_size + backing.st_size,
        "fullHashBudgetPerFileBytes": MAX_BYTES,
        "freeSpaceEstimatedBytes": free_estimate,
        "fullCheckpointReserveMinimumBytes": virtual_bytes,
        "checkpointCapacityEstimateSufficient": not capacity_insufficient,
        "checkpointReserveProven": False,
        "fullSha256Performed": False,
        "qcow2BackingChainAuthenticated": False,
        "qemuBackendFdAssociationProven": False,
        "guestEffectiveGptProven": False,
        "windowsRollbackProven": False,
        "productionStorageWritesAuthorized": False,
        "guestCommandChannelAuthorized": False,
        "rollbackProven": False,
        "sameDiskDualBootVerified": False,
        "stable": False,
    }


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        require(key not in value, "CHECKPOINT_DUPLICATE_KEY")
        value[key] = item
    return value


def _qcow2_chain(fd: int, backing: Path, virtual_bytes: int) -> None:
    """Read actual pinned QCOW2 via qemu-img; do not parse its bytes as RAW/GPT.

    qemu-img is a local host diagnostic. It does not independently authenticate
    QEMU's internal backend pointer, its open parent FD or a guest deployment.
    """
    try:
        response = subprocess.run(
            [
                "/usr/bin/qemu-img",
                "info",
                "--output=json",
                "--backing-chain",
                f"/proc/self/fd/{fd}",
            ],
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            timeout=12,
            check=True,
        )
        chain = json.loads(response.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise DestinationRefused("QCOW2_CHAIN_INSPECTION_FAILED") from exc
    require(
        type(chain) is list and len(chain) == 2 and all(type(node) is dict for node in chain),
        "QCOW2_BACKING_DEPTH_INVALID",
    )
    overlay, parent = chain
    require(
        overlay.get("format") == "qcow2"
        and parent.get("format") == "raw"
        and type(overlay.get("virtual-size")) is int
        and overlay["virtual-size"] == virtual_bytes
        and parent.get("virtual-size") == virtual_bytes
        and overlay.get("backing-filename-format") == "raw"
        and overlay.get("full-backing-filename") == str(backing)
        and parent.get("filename") == str(backing),
        "QCOW2_BACKING_OR_GEOMETRY_MISMATCH",
    )


def assess_authenticated_destination(
    *,
    pins: QemuDiskPins,
    qcow2_fd: int,
    backing_fd: int,
    backing_path: Path,
    checkpoint_fd: int,
    checkpoint_path: Path,
    expected_overlay_sha256: str,
    expected_backing_sha256: str,
    expected_checkpoint_sha256: str,
    expected_gpt: dict[str, Any],
    prewrite_inputs: dict[str, Any],
    guest_claim: dict[str, Any] | None = None,
    source_claim: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess one stopped-QEMU read-only QCOW2 and pinned RAW backing.

    Inputs and pinned hashes are CLAIMED by a caller, not independently
    authenticated. We require real FD bytes and a real QEMU peer/process, and
    reuse the already-existing #267 no-writer decision and canonical GPT-FD
    parser. Even on success all privileged operations remain DENIED.
    """
    require(type(pins) is QemuDiskPins, "INVALID_QEMU_PINS")
    require(pins.disk_format == "qcow2", "QCOW2_REQUIRED")
    require(type(prewrite_inputs) is dict, "TRANSACTION_REQUIRED")
    require(
        prewrite_inputs.get("transaction_id") == pins.transaction_id
        and type(prewrite_inputs.get("plan")) is dict
        and prewrite_inputs["plan"].get("planId") == pins.transaction_id,
        "TRANSACTION_MISMATCH",
    )
    require(guest_claim is None, "GUEST_ORIGIN_NOT_AUTHENTICATED")
    require(
        source_claim is None
        or (
            type(source_claim) is dict
            and set(source_claim) == {"kind", "digest"}
            and source_claim["kind"] in {"iso", "oci", "native-iso"}
            and type(source_claim["digest"]) is str
            and bool(HEX64.fullmatch(source_claim["digest"]))
        ),
        "SOURCE_IDENTITY_CLAIM_INVALID",
    )
    require(
        backing_path != checkpoint_path
        and backing_path != pins.media_path
        and checkpoint_path != pins.media_path,
        "ALIASING_DESTINATION_RESOURCES",
    )
    require(
        type(expected_gpt) is dict
        and prewrite_inputs["plan"].get("disk", {}).get("partitionStyle") == "GPT",
        "INVALID_TYPED_PLAN",
    )
    require(
        backing_path.parent == pins.workspace and checkpoint_path.parent == pins.workspace,
        "FOREIGN_RESOURCE_PATH",
    )
    try:
        qcow_st = _pin(qcow2_fd, pins.media_path, pins.workspace)
        raw_st = _pin(backing_fd, backing_path, pins.workspace)
        check_st = _pin(checkpoint_fd, checkpoint_path, pins.workspace)
        require(check_st.st_size <= 64 * 1024, "CHECKPOINT_SIZE_EXCEEDS_LIMIT")
        require(
            (qcow_st.st_dev, qcow_st.st_ino, qcow_st.st_size)
            == (pins.media_dev, pins.media_inode, pins.media_size),
            "DESTINATION_SWAP_OR_FD_ALIAS",
        )
        require(
            68 * 512 <= raw_st.st_size <= MAX_BYTES and raw_st.st_size % 512 == 0,
            "GPT_GEOMETRY_MISMATCH",
        )
        require(os.pread(qcow2_fd, 4, 0) == b"QFI\xfb", "QCOW2_HEADER_INVALID")
        with QemuLocalDiskWitness(pins) as witnessed:
            overlay_hash = _digest(qcow2_fd, expected_overlay_sha256)
            backing_hash = _digest(backing_fd, expected_backing_sha256)
            snapshot = inspect_gpt_fd(backing_fd, logical_sector_size=512)
            assert_snapshot_matches(expected_gpt, snapshot)
            require(
                snapshot["sizeBytes"] == raw_st.st_size
                and snapshot["logicalSectorSizeBytes"] == 512,
                "GPT_GEOMETRY_MISMATCH",
            )
            _qcow2_chain(qcow2_fd, backing_path, raw_st.st_size)
            _digest(checkpoint_fd, expected_checkpoint_sha256)
            payload = os.pread(checkpoint_fd, check_st.st_size, 0)
            receipt = json.loads(payload, object_pairs_hook=_unique_pairs)
            require(
                type(receipt) is dict
                and set(receipt)
                == {
                    "schemaVersion",
                    "transactionId",
                    "qcow2Sha256",
                    "backingSha256",
                    "gptPartitionTableId",
                    "restoreProven",
                }
                and type(receipt["schemaVersion"]) is int
                and receipt["schemaVersion"] == 1
                and receipt["transactionId"] == pins.transaction_id
                and receipt["qcow2Sha256"] == overlay_hash
                and receipt["backingSha256"] == backing_hash
                and receipt["gptPartitionTableId"] == snapshot["partitionTableId"]
                and receipt["restoreProven"] is False,
                "CHECKPOINT_TRANSACTION_OR_IDENTITY_MISMATCH",
            )
            # Exact #267 gate is imported, never rewritten or used as a writer.
            gate = importlib.import_module("libertix_prewrite_no_writer")
            decision = gate.decide_no_writer(**prewrite_inputs)
            require(
                type(decision) is dict
                and decision.get("decision") == "ACCEPT_NO_WRITER"
                and decision.get("transactionId") == pins.transaction_id,
                "UNOWNED_WRITESET_OR_PLAN",
            )
            assert_snapshot_matches(
                snapshot, prewrite_inputs["host_evidence"]["payload"]["snapshot"]
            )
            observation = witnessed.finish()
            require(
                observation["status"] == "BLOCKED_TRUST_ROOT"
                and observation["localQemuReadonlyDiskFdOpenProven"] is True,
                "LOCAL_QEMU_FD_NOT_VERIFIED",
            )
            for fd, path, original in (
                (qcow2_fd, pins.media_path, qcow_st),
                (backing_fd, backing_path, raw_st),
                (checkpoint_fd, checkpoint_path, check_st),
            ):
                require(
                    _stat_identity(os.fstat(fd))
                    == _stat_identity(path.lstat())
                    == _stat_identity(original),
                    "RESOURCE_CHANGED_DURING_ASSESSMENT",
                )
    except (QemuDiskRefused, DiskIdentityError, OSError, ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, DestinationRefused):
            raise
        raise DestinationRefused("UNVERIFIED_DESTINATION_OR_CHECKPOINT") from exc

    return {
        "status": "READONLY_STRUCTURE_OBSERVED",
        "authorization": "DENY_NO_WRITER",
        "transactionId": pins.transaction_id,
        "gptPartitionTableId": snapshot["partitionTableId"],
        "properties": {
            "localQemuProcess": "PROVEN",
            "qemuOpenReadonlyFd": "PROVEN",
            "qcow2FdIdentity": "PROVEN",
            "backingFdIdentityAndHash": "PROVEN",
            "backingGptPrimaryBackup": "PROVEN",
            "planAndSourceTrustRoot": "CLAIMED",
            "qcow2BackingInternalBinding": "UNPROVEN",
            "qemuBackendToFdInternalBinding": "UNPROVEN",
            "checkpointBytesAndHash": "PROVEN",
            "checkpointIndependentAuthenticity": "UNPROVEN",
            "guestOrigin": "DENIED",
            "writeSetOwnership": "CLAIMED",
            "windowsFunctionalRollback": "UNPROVEN",
        },
        "productionStorageWritesAuthorized": False,
        "guestCommandChannelAuthorized": False,
        "rollbackProven": False,
        "sameDiskDualBootVerified": False,
        "stable": False,
    }
