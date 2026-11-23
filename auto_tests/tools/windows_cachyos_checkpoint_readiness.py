#!/usr/bin/env python3
"""Read-only Windows/CachyOS A/B checkpoint recovery-readiness gate.

This checks local *structure*, never authorizes a Windows guest, Linux writer,
QEMU, a BCD modification, checkpoint recovery or an E2E run. The genuine
Windows checkpoint is absent from the historical Actions evidence artifact.
A caller's manifest, quota estimate and boot witness are NEVER trust roots.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from windows_cachyos_bcd_ab_control import (
    TPM_CONTROL, TPM_TREATMENT,
    WINDOWS_CONTROL_OVERLAY, WINDOWS_CONTROL_VARS,
    preflight_ab_clone_capacity, tpm_state_tree_sha256,
    tpm_state_trees_independent,
)
from windows_cachyos_cow_checkpoint import CHECKPOINT_DIR, OVERLAY_NAME

# These are conservative *minimum* headroom requests, not capacity proof.
GUEST_OVERLAY_GROWTH_RESERVE = 16 * 1024**3
PRIVATE_FORENSIC_RETENTION_RESERVE = 2 * 1024**3


class CheckpointReadinessRefusal(ValueError):
    def __init__(self, code: str, *, diagnostics: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        # Only numeric local host measurements; no BCD content or source paths.
        self.diagnostics = diagnostics


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CheckpointReadinessRefusal(code)


def _digest_owned(path: Path, parent: Path, *, readonly: bool = False) -> tuple[str, os.stat_result]:
    """Hash through a pinned read-only FD, rejecting foreign/changed pathnames."""
    _require(path.parent == parent and not path.is_symlink(),
             "CHECKPOINT_NOT_FOUND")
    try:
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError, OSError) as error:
        raise CheckpointReadinessRefusal("CHECKPOINT_NOT_FOUND") from error
    try:
        found = os.fstat(fd)
        _require(stat.S_ISREG(found.st_mode) and found.st_uid == os.getuid()
                 and found.st_nlink == 1 and found.st_size > 0,
                 "CHECKPOINT_NOT_FOUND")
        _require((not readonly or not (stat.S_IMODE(found.st_mode) & 0o222)),
                 "CHECKPOINT_NOT_FOUND")
        _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns) ==
                 (found.st_dev, found.st_ino, found.st_size, found.st_mtime_ns,
                  found.st_ctime_ns), "SOURCE_HASH_MISMATCH")
        sha = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            sha.update(chunk)
        after = path.lstat()
        _require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                  after.st_ctime_ns) ==
                 (found.st_dev, found.st_ino, found.st_size, found.st_mtime_ns,
                  found.st_ctime_ns), "SOURCE_HASH_MISMATCH")
        return sha.hexdigest(), found
    finally:
        os.close(fd)


def _self_process_uses(identities: set[tuple[int, int]]) -> bool:
    """Detect known open FDs; absence is NOT proof across all host processes."""
    root = Path("/proc/self/fd")
    _require(root.is_dir(), "PROCESS_STATE_UNVERIFIED")
    try:
        for entry in root.iterdir():
            try:
                fd = entry.stat()
            except FileNotFoundError:
                continue
            except (OSError, PermissionError) as error:
                raise CheckpointReadinessRefusal("PROCESS_STATE_UNVERIFIED") from error
            if (fd.st_dev, fd.st_ino) in identities:
                return True
    except OSError as error:
        raise CheckpointReadinessRefusal("PROCESS_STATE_UNVERIFIED") from error
    return False


def _private(directory: Path) -> bool:
    try:
        st = directory.lstat()
    except OSError:
        return False
    return (stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()
            and stat.S_IMODE(st.st_mode) == 0o700)


def _distinct(left: Path, right: Path, *, code: str) -> None:
    _require(left != right and not left.is_symlink() and not right.is_symlink(),
             code)
    try:
        a, b = left.lstat(), right.lstat()
    except OSError as error:
        raise CheckpointReadinessRefusal(code) from error
    _require(stat.S_ISREG(a.st_mode) and stat.S_ISREG(b.st_mode)
             and a.st_nlink == b.st_nlink == 1
             and (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino), code)


def inspect_readonly_ab_checkpoint(
    workspace: Path, *, transaction_id: str, manifest: Mapping[str, Any],
    external_quota_bytes: int | None,
    restore_witness: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Examine existing A/B materials without starting or writing anything.

    Any data inside manifest/restore_witness is a CALLER CLAIM. Even a fully
    matching synthetic structure is refused as RESTORE_NOT_PROVEN. In
    particular, this function must NEVER become a guest-write approval gate.
    """
    _require(type(transaction_id) is str and 1 <= len(transaction_id) <= 128,
             "FOREIGN_TRANSACTION")
    _require(type(manifest) is dict
             and manifest.get("transactionId") == transaction_id
             and manifest.get("artifactTransactionId") == transaction_id,
             "FOREIGN_TRANSACTION")
    _require(_private(workspace) and _private(workspace / CHECKPOINT_DIR),
             "CHECKPOINT_NOT_FOUND")
    checkpoint = workspace / CHECKPOINT_DIR
    disk = checkpoint / OVERLAY_NAME
    control = checkpoint / WINDOWS_CONTROL_OVERLAY
    vars_b = checkpoint / "trial-ovmf-variables.fd"
    vars_a = checkpoint / WINDOWS_CONTROL_VARS
    base = workspace / "only-disposable-windows-target.qcow2"
    original_vars = workspace / "ovmf-variables.fd"

    # Reject missing or aliased sources before reporting a local digest.
    for path in (disk, control, vars_b, vars_a, base, original_vars):
        _require(path.is_file() and not path.is_symlink(),
                 "CHECKPOINT_NOT_FOUND")
    _distinct(disk, control, code="SHARED_MUTABLE_OVERLAY")
    _distinct(vars_a, vars_b, code="SHARED_OVMF_VARS")
    disk_hash, disk_st = _digest_owned(disk, checkpoint)
    control_hash, control_st = _digest_owned(control, checkpoint)
    vars_b_hash, vars_b_st = _digest_owned(vars_b, checkpoint)
    vars_a_hash, vars_a_st = _digest_owned(vars_a, checkpoint)
    base_hash, base_st = _digest_owned(base, workspace, readonly=True)
    original_vars_hash, original_vars_st = _digest_owned(original_vars, workspace)

    def matching(field: str, digest: str) -> bool:
        claim = manifest.get(field)
        return (type(claim) is str and len(claim) == 64
                and claim == digest)

    _require(matching("sourceOverlaySha256", disk_hash)
             and matching("controlOverlaySha256", control_hash)
             and matching("sourceVarsSha256", vars_b_hash)
             and matching("controlVarsSha256", vars_a_hash),
             "SOURCE_HASH_MISMATCH")
    _require(matching("immutableBackingSha256", base_hash)
             and matching("originalOvmfVarsSha256", original_vars_hash),
             "BACKING_IDENTITY_MISMATCH")
    _require(disk_hash == control_hash and vars_a_hash == vars_b_hash,
             "SOURCE_HASH_MISMATCH")
    _require(not _self_process_uses({
        (s.st_dev, s.st_ino) for s in (
            disk_st, control_st, vars_a_st, vars_b_st, base_st, original_vars_st
        )
    }), "SOURCE_STILL_IN_USE")

    # Existing real statvfs preflight, plus explicit future overlay growth and
    # retained forensics; never mistake file st_blocks for bytes to clone.
    try:
        capacity = preflight_ab_clone_capacity(checkpoint, disk_st, vars_b_st)
    except Exception as error:
        raise CheckpointReadinessRefusal("INSUFFICIENT_CAPACITY") from error
    required = (capacity["requiredFreeBytesBeforeClone"]
                + GUEST_OVERLAY_GROWTH_RESERVE
                + PRIVATE_FORENSIC_RETENTION_RESERVE)
    _require(capacity["availableFreeBytesBeforeClone"] >= required,
             "INSUFFICIENT_CAPACITY")
    _require(type(external_quota_bytes) is int and
             external_quota_bytes >= required,
             "UNKNOWN_QUOTA")

    tpm_a = workspace / TPM_CONTROL
    tpm_b = workspace / TPM_TREATMENT
    _require(_private(tpm_a) and _private(tpm_b)
             and tpm_a != tpm_b and
             tpm_state_trees_independent(tpm_a, tpm_b),
             "SHARED_TPM_STATE")
    try:
        _require(tpm_state_tree_sha256(tpm_a)
                 == tpm_state_tree_sha256(tpm_b),
                 "SHARED_TPM_STATE")
    except (ValueError, OSError) as error:
        raise CheckpointReadinessRefusal("SHARED_TPM_STATE") from error

    # A self-reported preboot BCD digest is not a measurement of the hive.
    bcd = manifest.get("initialBcdSha256")
    _require(type(bcd) is str and len(bcd) == 64
             and manifest.get("controlBcdSha256") == bcd
             and manifest.get("treatmentBcdSha256") == bcd,
             "INITIAL_BCD_MISMATCH")
    # No self-supplied booleans can prove genuine restore, live Windows boot,
    # independent source provenance, process quiescence, quota or QEMU backing.
    _ = restore_witness
    raise CheckpointReadinessRefusal(
        "RESTORE_NOT_PROVEN",
        diagnostics={
            "localApparentArtifactBytes": sum(
                st.st_size for st in (
                    disk_st, control_st, vars_a_st, vars_b_st,
                    base_st, original_vars_st,
                )
            ),
            "localAllocatedArtifactBytes": sum(
                st.st_blocks * 512 for st in (
                    disk_st, control_st, vars_a_st, vars_b_st,
                    base_st, original_vars_st,
                )
            ),
            "physicalAvailableBytesAtInspection":
                capacity["availableFreeBytesBeforeClone"],
            "physicalRequiredFreeBytesBeforeRun": required,
            "quotaIndependentlyVerified": False,
            "sourceProvenanceAuthenticated": False,
            "externalQemuProcessQuiescenceProven": False,
            "checkpointInPlaceRecoveryProven": False,
            "operationalWritesAuthorized": False,
        },
    )
