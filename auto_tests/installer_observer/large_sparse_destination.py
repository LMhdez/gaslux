"""128-GiB sparse QCOW2/RAW host-only geometry assessment. NEVER a writer.

No subset SHA is reported as an authenticated whole-image digest. The large
RAW backing cannot be fully hashed within this bounded laboratory budget,
so even a valid 128-GiB geometry is returned as an explicit refusal.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assets.live.libertix_disk_identity_gate import (
    DiskIdentityError,
    assert_snapshot_matches,
    inspect_gpt_fd,
)

from .authenticated_destination import (
    DestinationRefused,
    _pin,
    _stat_identity,
    _unique_pairs,
)
from .qemu_local_disk_witness import QemuDiskPins, QemuDiskRefused, QemuLocalDiskWitness

GIB = 1024**3
MIB = 1024**2
MAX_LARGE_VIRTUAL_BYTES = 128 * GIB
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class LargeDestinationRefused(DestinationRefused):
    """Contains bounded, non-authorizing observations on partial inspection."""

    def __init__(self, reason: str, *, observed: dict[str, Any] | None = None):
        super().__init__(reason)
        self.code = reason
        self.observed = observed


@dataclass(frozen=True)
class LargeReadOnlyBudget:
    """Explicit resource maxima; caller-supplied quota remains CLAIMED only."""

    known_quota_bytes: int | None
    max_virtual_bytes: int = MAX_LARGE_VIRTUAL_BYTES
    max_qcow2_apparent_bytes: int = 64 * MIB
    max_qcow2_allocated_bytes: int = 32 * MIB
    max_raw_allocated_bytes: int = 32 * MIB
    max_total_allocated_bytes: int = 64 * MIB
    max_checkpoint_bytes: int = 64 * 1024
    max_qemu_info_bytes: int = 64 * 1024
    max_seconds: int = 15

    def __post_init__(self) -> None:
        permitted = {
            "max_virtual_bytes": (68 * 512, MAX_LARGE_VIRTUAL_BYTES),
            "max_qcow2_apparent_bytes": (68 * 512, 64 * MIB),
            "max_qcow2_allocated_bytes": (512, 32 * MIB),
            "max_raw_allocated_bytes": (512, 32 * MIB),
            "max_total_allocated_bytes": (1024, 64 * MIB),
            "max_checkpoint_bytes": (128, 64 * 1024),
            "max_qemu_info_bytes": (256, 64 * 1024),
            "max_seconds": (1, 30),
        }
        for field, (low, high) in permitted.items():
            value = getattr(self, field)
            _require(type(value) is int and low <= value <= high, "INVALID_RESOURCE_LIMIT")
        _require(
            self.known_quota_bytes is None
            or (type(self.known_quota_bytes) is int and 0 < self.known_quota_bytes <= 1024**5),
            "INVALID_QUOTA_CLAIM",
        )


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise LargeDestinationRefused(code)


def _elapsed(deadline: float) -> None:
    _require(time.monotonic() < deadline, "READONLY_INSPECTION_TIMEOUT")


def _allocated(st: os.stat_result) -> int:
    _require(
        type(st.st_blocks) is int and 0 <= st.st_blocks <= (1 << 50),
        "ALLOCATION_MEASUREMENT_UNAVAILABLE",
    )
    return st.st_blocks * 512


def _pin_sparse(fd: int, path: Path, workspace: Path, max_apparent: int) -> os.stat_result:
    _require(type(fd) is int and fd >= 0, "FOREIGN_FD")
    _require(
        type(path) is type(Path())
        and path.is_absolute()
        and type(workspace) is type(Path())
        and workspace.is_absolute()
        and path.parent == workspace
        and not path.is_symlink(),
        "SPARSE_PATH_UNOWNED",
    )
    try:
        before = path.lstat()
        observed = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as exc:
        raise LargeDestinationRefused("SPARSE_FD_STAT_FAILED") from exc
    _require(
        stat.S_ISREG(before.st_mode)
        and stat.S_ISREG(observed.st_mode)
        and before.st_nlink == observed.st_nlink == 1
        and before.st_uid == observed.st_uid == os.getuid()
        and 68 * 512 <= observed.st_size <= max_apparent
        and observed.st_size % 512 == 0
        and (flags & os.O_ACCMODE) == os.O_RDONLY
        and not (flags & getattr(os, "O_PATH", 0))
        and _stat_identity(before) == _stat_identity(observed),
        "SPARSE_FOREIGN_FD_OR_GEOMETRY",
    )
    return observed


def _read_exact(fd: int, offset: int, count: int, deadline: float) -> bytes:
    _elapsed(deadline)
    try:
        data = os.pread(fd, count, offset)
    except OSError as exc:
        raise LargeDestinationRefused("SPARSE_READ_IO_FAILED") from exc
    _require(len(data) == count, "SPARSE_SHORT_READ")
    _elapsed(deadline)
    return data


def _bounded_info(fd: int, budget: LargeReadOnlyBudget, deadline: float) -> list[dict]:
    """Bounded qemu-img output, with owned POSIX process-group cleanup."""
    _elapsed(deadline)
    command = [
        "/usr/bin/qemu-img",
        "info",
        "--output=json",
        "--backing-chain",
        f"/proc/self/fd/{fd}",
    ]
    try:
        # setsid() happens in the child before exec: no parent-side setpgid race.
        proc = subprocess.Popen(
            command,
            pass_fds=(fd,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise LargeDestinationRefused("QEMU_INFO_START_FAILED") from exc
    payload = bytearray()
    try:
        _require(proc.stdout is not None, "QEMU_INFO_PIPE_MISSING")
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                _elapsed(deadline)
                events = selector.select(timeout=max(0, deadline - time.monotonic()))
                _require(bool(events), "QEMU_INFO_TIMEOUT")
                chunk = os.read(proc.stdout.fileno(), min(8192, budget.max_qemu_info_bytes + 1))
                if not chunk:
                    break
                _require(
                    len(payload) + len(chunk) <= budget.max_qemu_info_bytes,
                    "QEMU_INFO_OUTPUT_LIMIT",
                )
                payload.extend(chunk)
        # Observe the exit without reaping the session leader. Keeping its
        # zombie PID allocated prevents PID/PGID reuse before killpg below.
        while True:
            _elapsed(deadline)
            exited = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if exited is not None:
                _require(
                    exited.si_code == os.CLD_EXITED and exited.si_status == 0,
                    "QEMU_INFO_FAILED",
                )
                break
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
    except (OSError, ChildProcessError, subprocess.TimeoutExpired) as exc:
        raise LargeDestinationRefused("QEMU_INFO_IO_OR_TIMEOUT") from exc
    finally:
        # Signal ONLY our own session/process group, before wait() releases
        # the leader PID. A dead leader can still have live pipe-holding
        # descendants. Never signal the caller's or an unknown process group.
        cleanup_failed = False
        cleanup_deadline = time.monotonic() + 3
        try:
            if os.getpgid(proc.pid) != proc.pid:
                cleanup_failed = True
            else:
                os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            cleanup_failed = True
        try:
            proc.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            cleanup_failed = True
            # The direct PID remains owned by Popen; best-effort final reap.
            try:
                proc.kill()
                proc.wait(timeout=0.25)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except OSError:
            cleanup_failed = True
        # After reaping the leader, wait for descendants (including adopted
        # zombies) to leave the group; do not send any more group signals,
        # since that PGID could subsequently be reused.
        if not cleanup_failed:
            while True:
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    break
                except OSError:
                    cleanup_failed = True
                    break
                if time.monotonic() >= cleanup_deadline:
                    cleanup_failed = True
                    break
                time.sleep(min(0.02, cleanup_deadline - time.monotonic()))
        if cleanup_failed:
            raise LargeDestinationRefused("QEMU_INFO_CLEANUP_FAILED")
    try:
        chain = json.loads(payload, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise LargeDestinationRefused("QEMU_INFO_INVALID_JSON") from exc
    _require(
        type(chain) is list and len(chain) == 2 and all(type(x) is dict for x in chain),
        "QEMU_INFO_BACKING_DEPTH",
    )
    return chain


def _small_full_digest(fd: int, expected: str, budget: LargeReadOnlyBudget, deadline: float) -> str:
    """A complete, bounded digest. Short reads are refused, NEVER skipped."""
    _require(type(expected) is str and HEX64.fullmatch(expected) is not None, "HASH_PIN_INVALID")
    initial = os.fstat(fd)
    _require(initial.st_size <= budget.max_qcow2_apparent_bytes, "HASH_RESOURCE_CAP")
    digest = hashlib.sha256()
    done = 0
    while done < initial.st_size:
        _elapsed(deadline)
        amount = min(MIB, initial.st_size - done)
        block = _read_exact(fd, done, amount, deadline)
        digest.update(block)
        done += len(block)
    _require(done == initial.st_size, "HASH_NOT_COMPLETED")
    _require(_stat_identity(initial) == _stat_identity(os.fstat(fd)), "HASH_CONCURRENT_MUTATION")
    result = digest.hexdigest()
    _require(result == expected, "FULL_QCOW2_HASH_MISMATCH")
    return result


def assess_sparse_128g_readonly(
    *,
    pins: QemuDiskPins,
    qcow2_fd: int,
    backing_fd: int,
    backing_path: Path,
    checkpoint_fd: int,
    checkpoint_path: Path,
    expected_overlay_sha256: str,
    expected_checkpoint_sha256: str,
    expected_gpt: dict[str, Any],
    prewrite_inputs: dict[str, Any],
    budget: LargeReadOnlyBudget,
    guest_claim: dict[str, Any] | None = None,
) -> None:
    """Observe 128-GiB sparse geometry then EXPLICITLY DENY uncompleted RAW hash.

    The only successful observation is attached to a refusal. No write
    authority, effective guest GPT, Windows rollback or full RAW SHA is
    represented as proven.
    """
    _require(type(budget) is LargeReadOnlyBudget, "BUDGET_REQUIRED")
    _require(budget.known_quota_bytes is not None, "QUOTA_UNKNOWN")
    _require(guest_claim is None, "GUEST_ORIGIN_UNPROVEN")
    _require(type(pins) is QemuDiskPins and pins.disk_format == "qcow2", "QEMU_PINS_INVALID")
    _require(type(prewrite_inputs) is dict, "TRANSACTION_MISSING")
    _require(
        prewrite_inputs.get("transaction_id") == pins.transaction_id
        and type(prewrite_inputs.get("plan")) is dict
        and prewrite_inputs["plan"].get("planId") == pins.transaction_id,
        "TRANSACTION_MISMATCH",
    )
    _require(type(expected_gpt) is dict, "GPT_EXPECTATION_MISSING")
    _require(
        backing_path != pins.media_path and checkpoint_path not in (pins.media_path, backing_path),
        "RESOURCE_ALIAS",
    )
    deadline = time.monotonic() + budget.max_seconds
    try:
        workspace = pins.workspace
        workspace_st = workspace.lstat()
        _require(
            type(workspace) is type(Path())
            and workspace.is_absolute()
            and workspace.resolve(strict=True) == workspace
            and workspace_st.st_uid == os.getuid()
            and stat.S_ISDIR(workspace_st.st_mode)
            and (workspace_st.st_mode & 0o077) == 0,
            "WORKSPACE_UNOWNED",
        )
        overlay_st = _pin(qcow2_fd, pins.media_path, workspace)
        raw_st = _pin_sparse(backing_fd, backing_path, workspace, budget.max_virtual_bytes)
        receipt_st = _pin(checkpoint_fd, checkpoint_path, workspace)
        _require(
            overlay_st.st_size <= budget.max_qcow2_apparent_bytes
            and receipt_st.st_size <= budget.max_checkpoint_bytes
            and (overlay_st.st_dev, overlay_st.st_ino, overlay_st.st_size)
            == (pins.media_dev, pins.media_inode, pins.media_size),
            "IMAGE_OR_RECEIPT_CAP_EXCEEDED",
        )
        overlay_blocks = _allocated(overlay_st)
        raw_blocks = _allocated(raw_st)
        receipt_blocks = _allocated(receipt_st)
        _require(
            overlay_blocks <= budget.max_qcow2_allocated_bytes
            and raw_blocks <= budget.max_raw_allocated_bytes
            and sum((overlay_blocks, raw_blocks, receipt_blocks))
            <= budget.max_total_allocated_bytes
            and sum((overlay_blocks, raw_blocks, receipt_blocks)) <= budget.known_quota_bytes,
            "ALLOCATION_BUDGET_EXCEEDED",
        )
        vfs = os.statvfs(workspace)
        _require(vfs.f_bavail > 0 and vfs.f_frsize > 0, "FILESYSTEM_QUOTA_UNAVAILABLE")
        free_space_estimate = vfs.f_bavail * vfs.f_frsize
        _require(free_space_estimate >= 1024 * 1024, "INSUFFICIENT_HOST_FREE_SPACE")
        _require(raw_st.st_size == MAX_LARGE_VIRTUAL_BYTES, "NOT_128G_BACKING_GEOMETRY")
        # #342 supplied this bounded header/version and geometry cross-check.
        # qemu-img remains a local chain inspector, not a guest proof.
        _require(overlay_st.st_size >= 72, "QCOW2_HEADER_TRUNCATED")
        header = _read_exact(qcow2_fd, 0, 32, deadline)
        _require(header[:4] == b"QFI\xfb", "QCOW2_MAGIC_INVALID")
        qcow2_version = int.from_bytes(header[4:8], "big")
        _require(qcow2_version in (2, 3), "QCOW2_HEADER_VERSION_INVALID")
        _require(
            int.from_bytes(header[24:32], "big") == raw_st.st_size,
            "QCOW2_HEADER_VIRTUAL_GEOMETRY_MISMATCH",
        )
        with QemuLocalDiskWitness(pins) as witness:
            overlay_hash = _small_full_digest(qcow2_fd, expected_overlay_sha256, budget, deadline)
            _elapsed(deadline)
            chain = _bounded_info(qcow2_fd, budget, deadline)
            image, parent = chain
            _require(
                image.get("format") == "qcow2"
                and image.get("backing-filename-format") == "raw"
                and image.get("full-backing-filename") == str(backing_path)
                and parent.get("filename") == str(backing_path)
                and parent.get("format") == "raw"
                and type(image.get("virtual-size")) is int
                and image["virtual-size"] == raw_st.st_size
                and type(parent.get("virtual-size")) is int
                and parent["virtual-size"] == raw_st.st_size,
                "QCOW2_BACKING_OR_VIRTUAL_GEOMETRY_MISMATCH",
            )
            # Exactly two 32-KiB local samples, never a whole-image digest.
            sample_bytes = 64 * 512
            front = _read_exact(backing_fd, 0, sample_bytes, deadline)
            back = _read_exact(backing_fd, raw_st.st_size - sample_bytes, sample_bytes, deadline)
            local_sample_sha256 = hashlib.sha256(front + back).hexdigest()
            _elapsed(deadline)
            gpt = inspect_gpt_fd(backing_fd, logical_sector_size=512)
            assert_snapshot_matches(expected_gpt, gpt)
            _require(
                gpt["sizeBytes"] == raw_st.st_size and gpt["logicalSectorSizeBytes"] == 512,
                "GPT_SECTOR_OR_SIZE_MISMATCH",
            )
            # Keep the existing no-writer transaction/extent check; MACs do
            # not authenticate where source observations came from.
            from importlib import import_module

            gate = import_module("libertix_prewrite_no_writer")
            decision = gate.decide_no_writer(**prewrite_inputs)
            _require(
                decision.get("decision") == "ACCEPT_NO_WRITER"
                and decision.get("transactionId") == pins.transaction_id,
                "TRANSACTION_OR_OWNERSHIP_REFUSED",
            )
            assert_snapshot_matches(gpt, prewrite_inputs["host_evidence"]["payload"]["snapshot"])
            _require(type(expected_checkpoint_sha256) is str, "CHECKPOINT_DIGEST_MISSING")
            receipt = _read_exact(checkpoint_fd, 0, receipt_st.st_size, deadline)
            _require(
                hashlib.sha256(receipt).hexdigest() == expected_checkpoint_sha256,
                "CHECKPOINT_HASH_DIVERGED",
            )
            try:
                checkpoint = json.loads(receipt, object_pairs_hook=_unique_pairs)
            except (ValueError, UnicodeError) as exc:
                raise LargeDestinationRefused("CHECKPOINT_INVALID_JSON") from exc
            _require(
                type(checkpoint) is dict
                and set(checkpoint)
                == {
                    "schemaVersion",
                    "transactionId",
                    "virtualBytes",
                    "gptPartitionTableId",
                    "qcow2Sha256",
                    "restoreProven",
                }
                and type(checkpoint["schemaVersion"]) is int
                and checkpoint["schemaVersion"] == 1
                and checkpoint["transactionId"] == pins.transaction_id
                and checkpoint["virtualBytes"] == raw_st.st_size
                and checkpoint["gptPartitionTableId"] == gpt["partitionTableId"]
                and checkpoint["qcow2Sha256"] == overlay_hash
                and checkpoint["restoreProven"] is False,
                "CHECKPOINT_TRANSACTION_MISMATCH",
            )
            observation = witness.finish()
            _require(
                observation["status"] == "BLOCKED_TRUST_ROOT"
                and observation["localQemuReadonlyDiskFdOpenProven"] is True,
                "QEMU_WITNESS_REFUSED",
            )
            for fd, path, initial in (
                (qcow2_fd, pins.media_path, overlay_st),
                (backing_fd, backing_path, raw_st),
                (checkpoint_fd, checkpoint_path, receipt_st),
            ):
                current = os.fstat(fd)
                present = path.lstat()
                _require(
                    _stat_identity(current) == _stat_identity(present) == _stat_identity(initial)
                    and _allocated(current) == _allocated(present) == _allocated(initial),
                    "RESOURCE_MUTATED_DURING_INSPECTION",
                )
            _elapsed(deadline)
    except (
        OSError,
        DiskIdentityError,
        QemuDiskRefused,
        DestinationRefused,
        KeyError,
        TypeError,
    ) as exc:
        if isinstance(exc, LargeDestinationRefused):
            raise
        raise LargeDestinationRefused("LARGE_DESTINATION_INSPECTION_REFUSED") from exc

    raise LargeDestinationRefused(
        "FULL_BACKING_HASH_NOT_COMPLETED",
        observed={
            "status": "STRUCTURE_OBSERVED_FULL_HASH_DENIED",
            "authorization": "DENY_NO_WRITER",
            "virtualCapacityBytes": raw_st.st_size,
            "qcow2ApparentBytes": overlay_st.st_size,
            "qcow2AllocatedBytes": overlay_blocks,
            "rawApparentBytes": raw_st.st_size,
            "rawAllocatedBytes": raw_blocks,
            "backingIsSparse": raw_blocks < raw_st.st_size,
            "qcow2HeaderBytesRead": len(header),
            "qcow2HeaderVersion": qcow2_version,
            "checkpointApparentBytes": receipt_st.st_size,
            # A statvfs ESTIMATE, never a reservation or trust root.
            "freeSpaceEstimatedBytes": free_space_estimate,
            "fullCheckpointReserveMinimumBytes": raw_st.st_size,
            "checkpointCapacityEstimateSufficient": free_space_estimate >= raw_st.st_size,
            "checkpointReserveProven": False,
            "backingGptPartitionTableId": gpt["partitionTableId"],
            "locallyMeasuredRawSampleBytes": 2 * sample_bytes,
            "locallyMeasuredRawSampleSha256": local_sample_sha256,
            "rawBackingFullSha256Verified": False,
            "fullRawContentBytesAuthenticated": 0,
            "qemuBackendFdIndependentlyProven": False,
            "guestProvenanceAuthenticated": False,
            "checkpointRestorationProven": False,
            "productionStorageWritesAuthorized": False,
            "guestCommandChannelAuthorized": False,
            "rollbackProven": False,
            "sameDiskDualBootVerified": False,
            "stable": False,
        },
    )
