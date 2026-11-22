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

MAX_BYTES = 512 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class DestinationRefused(ValueError):
    """A required local observation or invariant did not hold."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise DestinationRefused(reason)


def _stat_identity(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _pin(fd: int, path: Path, workspace: Path) -> os.stat_result:
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
        and 0 < opened.st_size <= MAX_BYTES
        and (flags & os.O_ACCMODE) == os.O_RDONLY
        and not (flags & getattr(os, "O_PATH", 0))
        and _stat_identity(before) == _stat_identity(opened),
        "FD_ALIAS_OR_WRITABLE_FILE",
    )
    return opened


def _digest(fd: int, expected: str) -> str:
    require(type(expected) is str and bool(HEX64.fullmatch(expected)), "HASH_PIN_INVALID")
    initial = os.fstat(fd)
    sha = hashlib.sha256()
    for offset in range(0, initial.st_size, 1024 * 1024):
        chunk = os.pread(fd, min(1024 * 1024, initial.st_size - offset), offset)
        require(bool(chunk), "FD_SHORT_READ")
        sha.update(chunk)
    require(_stat_identity(initial) == _stat_identity(os.fstat(fd)), "FD_MUTATED_DURING_HASH")
    actual = sha.hexdigest()
    require(actual == expected, "PINNED_HASH_MISMATCH")
    return actual


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
