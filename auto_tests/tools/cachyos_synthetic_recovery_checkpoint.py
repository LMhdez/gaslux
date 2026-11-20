#!/usr/bin/env python3
"""Disposable CI only: durable copy of a synthetic QCOW2 before any mutation.

This is NOT a Windows recovery implementation or an authorization to write.
Never accepts a block device, physical disk, Windows QCOW2, or arbitrary path.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

MAX_BYTES = 128 * 1024**2
SOURCE_NAME = "synthetic-owned-disk.qcow2"
PREFIX = "gaslux-synthetic-checkpoint-"


class CheckpointRejected(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise CheckpointRejected(message)


def encode(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_root(root: Path) -> Path:
    require(isinstance(root, Path) and not root.is_symlink(), "unsafe checkpoint root")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux",
            "checkpoint requires authorized hosted CI")
    temp = os.environ.get("RUNNER_TEMP")
    require(bool(temp), "missing hosted temporary directory")
    base = Path(temp).resolve(strict=True)
    require(root.parent == base and root.name.startswith(PREFIX),
            "checkpoint root is outside synthetic runner temp")
    st = root.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()
            and stat.S_IMODE(st.st_mode) == 0o700,
            "checkpoint root is not private and owned")
    return root


def validate_proposal(proposal: dict[str, Any]) -> tuple[str, str]:
    require(isinstance(proposal, dict), "missing proposal")
    tx = proposal.get("identity", {}).get("transactionId") if isinstance(
        proposal.get("identity"), dict) else None
    claimed = proposal.get("proposalSha256")
    require(isinstance(tx, str) and re.fullmatch("[0-9a-f]{32}", tx) is not None
            and isinstance(claimed, str) and re.fullmatch("[0-9a-f]{64}", claimed) is not None,
            "invalid proposal identity")
    identity = proposal["identity"]
    require(set(identity) == {"transactionId", "diskGuidSha256",
                              "gptAuditWindowsSha256", "firstLba",
                              "lastLba", "sectorBytes"},
            "unexpected proposal fields")
    require(digest(encode(identity)) == claimed, "modified proposal identity")
    require(proposal.get("proposalSchema") ==
            "gaslux-cachyos-simulated-partition-v1" and
            proposal.get("simulationOnly") is True,
            "not a synthetic simulation")
    for field in ("storageWritesAuthorized", "partitionCreated",
                  "recoveryPrepared", "recoveryVerified",
                  "windowsBootAfterLinuxVerified", "sameDiskDualBootVerified",
                  "releaseEligible"):
        require(proposal.get(field) is False, "proposal claims forbidden authority")
    return tx, claimed


def open_readonly_regular(path: Path, *, max_bytes: int = MAX_BYTES) -> tuple[int, os.stat_result]:
    require(not path.is_symlink(), "symlinked checkpoint source")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    st = os.fstat(fd)
    try:
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
                and st.st_nlink == 1 and 0 < st.st_size <= max_bytes,
                "not a bounded exclusive owned regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def fingerprint(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_synthetic_checkpoint(root: Path, source: Path,
                                proposal: dict[str, Any],
                                *, interrupt_after_copy: bool = False) -> dict[str, Any]:
    """Publish a full-file checkpoint; never alter the source or return write authority.

    The manifest is the last file to be fsynced. A power cut before that point
    leaves a recognizably incomplete checkpoint, rejected by verification.
    """
    root = validate_root(root)
    tx, proposal_sha = validate_proposal(proposal)
    require(isinstance(source, Path) and source.parent == root and
            source.name == SOURCE_NAME, "unexpected synthetic checkpoint source")
    input_fd, before = open_readonly_regular(source)
    checkpoint = root / ("checkpoint-" + tx)
    try:
        try:
            os.mkdir(checkpoint, 0o700)
        except FileExistsError as exc:
            raise CheckpointRejected("transaction checkpoint already exists") from exc
        fsync_dir(root)
        file_hash = hashlib.sha256()
        total = 0
        target = checkpoint / "baseline.qcow2"
        out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(out_fd, "wb", closefd=True) as output:
                with os.fdopen(input_fd, "rb", closefd=False) as initial:
                    require(initial.read(4) == b"QFI\xfb", "not a QCOW2 synthetic source")
                    initial.seek(0)
                    while True:
                        chunk = initial.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        require(total <= MAX_BYTES, "checkpoint source exceeded bound")
                        output.write(chunk)
                        file_hash.update(chunk)
                output.flush()
                os.fsync(output.fileno())
        finally:
            # output descriptor is closed by fdopen even if an exception occurs.
            pass
        require(total == before.st_size and
                fingerprint(os.fstat(input_fd)) == fingerprint(before) and
                fingerprint(source.stat()) == fingerprint(before),
                "checkpoint source changed during copy")
        fsync_dir(checkpoint)
        if interrupt_after_copy:
            raise CheckpointRejected("injected interruption before checkpoint seal")
        manifest = {
            "schema": "gaslux-synthetic-qcow2-checkpoint-v1",
            "transactionId": tx,
            "proposalSha256": proposal_sha,
            "baselineSha256": file_hash.hexdigest(),
            "baselineBytes": total,
            "simulationOnly": True,
            "windowsRecoveryVerified": False,
            "storageWritesAuthorized": False,
            "releaseEligible": False,
        }
        payload = encode(manifest)
        manifest_fd = os.open(checkpoint / "manifest.json", os.O_WRONLY | os.O_CREAT |
                              os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(manifest_fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        fsync_dir(checkpoint)
        fsync_dir(root)
        return {"checkpointManifestSha256": digest(payload),
                "checkpointDirectory": checkpoint.name,
                "windowsRecoveryVerified": False,
                "storageWritesAuthorized": False, "releaseEligible": False}
    finally:
        os.close(input_fd)


def verify_synthetic_checkpoint(root: Path, proposal: dict[str, Any],
                                expected_manifest_sha256: str) -> dict[str, Any]:
    root = validate_root(root)
    tx, proposal_sha = validate_proposal(proposal)
    require(isinstance(expected_manifest_sha256, str) and
            re.fullmatch("[0-9a-f]{64}", expected_manifest_sha256) is not None,
            "missing independent checkpoint manifest digest")
    folder = root / ("checkpoint-" + tx)
    require(not folder.is_symlink(), "unsafe checkpoint directory")
    st = folder.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and
            stat.S_IMODE(st.st_mode) == 0o700,
            "unowned checkpoint directory")
    manifest_path = folder / "manifest.json"
    fd, _ = open_readonly_regular(manifest_path, max_bytes=4096)
    with os.fdopen(fd, "rb") as f:
        payload = f.read(4097)
    require(len(payload) <= 4096 and digest(payload) == expected_manifest_sha256,
            "checkpoint manifest digest mismatch")
    try:
        manifest = json.loads(payload)
    except (UnicodeError, ValueError) as exc:
        raise CheckpointRejected("invalid checkpoint manifest") from exc
    require(type(manifest) is dict and set(manifest) == {
        "schema", "transactionId", "proposalSha256", "baselineSha256",
        "baselineBytes", "simulationOnly", "windowsRecoveryVerified",
        "storageWritesAuthorized", "releaseEligible"
    }, "unrecognized checkpoint manifest")
    require(manifest["schema"] == "gaslux-synthetic-qcow2-checkpoint-v1" and
            manifest["transactionId"] == tx and
            manifest["proposalSha256"] == proposal_sha and
            manifest["simulationOnly"] is True and
            manifest["windowsRecoveryVerified"] is False and
            manifest["storageWritesAuthorized"] is False and
            manifest["releaseEligible"] is False, "invalid checkpoint ownership or authority")
    fd, before = open_readonly_regular(folder / "baseline.qcow2")
    with os.fdopen(fd, "rb") as f:
        evidence = hashlib.sha256()
        size = 0
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            evidence.update(block)
            size += len(block)
        require(fingerprint(os.fstat(f.fileno())) == fingerprint(before),
                "checkpoint changed during verification")
    require(size == manifest["baselineBytes"] and
            evidence.hexdigest() == manifest["baselineSha256"],
            "checkpoint baseline is incomplete or corrupted")
    return {"syntheticSnapshotHashVerified": True,
            "checkpointManifestSha256": expected_manifest_sha256,
            "windowsRecoveryVerified": False,
            "storageWritesAuthorized": False,
            "releaseEligible": False}
