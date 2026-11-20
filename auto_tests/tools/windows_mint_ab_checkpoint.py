#!/usr/bin/env python3
"""Disposable Mint A/B checkpoint, no Windows boot or production disk access.

Flatten the already staged Windows+Mint QCOW2 before the FIRST Mint boot.
All three QCOW2 images are standalone (no shared backing chain).
A deliberately corrupted control arm is rehydrated from the immutable
reference and compared byte-for-byte LOGICALLY before any VM is allowed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import uuid

from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, sha256_file, validate_workspace,
)
from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, qcow2_file_identity, require_unchanged_qcow2,
)

CONSENT = "I_ACCEPT_DISPOSABLE_MINT_AB_FORENSIC_CHECKPOINT_ONLY"
AB_DIR = "mint-ab-independent-checkpoint"
REFERENCE = "reference.qcow2"
ARMS = ("arm-a.qcow2", "arm-b.qcow2")
VARS = ("arm-a-vars.fd", "arm-b-vars.fd")
WRITE_SIZE = 4096  # Fault injection must use GPT-measured unallocated tail


class AbCheckpointError(RuntimeError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise AbCheckpointError(why)


def command(argv: list[str], timeout: int = 1800, check: bool = True):
    return subprocess.run(argv, check=check, text=True, capture_output=True,
                          timeout=timeout)


def file_guard(path: Path, parent: Path, mode: int | None = None):
    require(path.parent == parent and not path.is_symlink(),
            "foreign or symlinked A/B path")
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
            and s.st_nlink == 1 and s.st_size > 0,
            "nonexclusive A/B file or hardlink")
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode, "unsafe A/B file permissions")
    return s


def image_info(path: Path, expected_virtual: int = VIRTUAL_BYTES) -> dict:
    info = json.loads(command(["qemu-img", "info", "-f", "qcow2",
                               "--output=json", str(path)], timeout=60).stdout)
    require(info.get("format") == "qcow2"
            and info.get("virtual-size") == expected_virtual
            and not info.get("backing-filename")
            and not info.get("full-backing-filename")
            and not info.get("encrypted", False),
            "A/B image is not independent standalone qcow2")
    return info


def equivalent(a: Path, b: Path) -> None:
    command(["qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
             str(a), str(b)], timeout=1800)


def standalone(source: Path, destination: Path, directory: Path,
               expected_virtual: int = VIRTUAL_BYTES) -> str:
    require(destination.parent == directory and not destination.exists()
            and not destination.is_symlink(), "reused A/B image destination")
    # qemu-img convert creates a standalone image, flattening any source backing.
    # A private directory and exclusive name protect against aliasing.
    command(["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
             "-c", str(source), str(destination)], timeout=3600)
    destination.chmod(0o600)
    file_guard(destination, directory, 0o600)
    image_info(destination, expected_virtual)
    equivalent(source, destination)
    return sha256_file(destination)


def clone_vars(source: Path, destination: Path, directory: Path) -> str:
    file_guard(source, source.parent)
    require(destination.parent == directory and not destination.exists()
            and not destination.is_symlink(), "reused OVMF destination")
    with source.open("rb") as inp, destination.open("xb") as out:
        shutil.copyfileobj(inp, out, 262144)
        out.flush()
        os.fsync(out.fileno())
    destination.chmod(0o600)
    file_guard(destination, directory, 0o600)
    digest = sha256_file(source)
    require(sha256_file(destination) == digest
            and source.stat().st_ino != destination.stat().st_ino,
            "A/B OVMF clone differs or aliases")
    return digest


def clone_tpm_state(source: Path | None, directory: Path) -> dict:
    """Windows 10 uses no swtpm in this lab; if found, clone stopped state.

    Only ordinary regular files and directories may be copied, never sockets,
    symlinks, hardlinks, devices, or an active swtpm listener.
    """
    if source is None:
        return {"applicable": False, "reason": "Windows 10 QEMU profile has no TPM device"}
    require(source.is_dir() and not source.is_symlink()
            and source.parent == directory.parent
            and source.name == "swtpm-state"
            and not (directory.parent / "swtpm.sock").exists(),
            "TPM state unsafe or swtpm may still be active")
    records = {}
    for entry in source.rglob("*"):
        s = entry.lstat()
        require(s.st_uid == os.getuid() and not entry.is_symlink()
                and (stat.S_ISDIR(s.st_mode)
                     or (stat.S_ISREG(s.st_mode) and s.st_nlink == 1)),
                "unsafe TPM state entry")
        if entry.is_file():
            records[str(entry.relative_to(source))] = sha256_file(entry)
    require(bool(records), "empty TPM state is not a checkpoint")
    for arm in ("arm-a-tpm", "arm-b-tpm"):
        target = directory / arm
        require(not target.exists() and not target.is_symlink(),
                "reused TPM arm state")
        shutil.copytree(source, target, symlinks=False)
        cloned = {}
        for item in target.rglob("*"):
            file_guard(item, item.parent) if item.is_file() else require(
                item.is_dir() and not item.is_symlink(), "unsafe cloned TPM directory")
            if item.is_file():
                cloned[str(item.relative_to(target))] = sha256_file(item)
        require(cloned == records, "TPM arm state differs from baseline")
    return {"applicable": True, "sourceHashes": records,
            "armA": "arm-a-tpm", "armB": "arm-b-tpm"}


def choose_injection_offset(reference: Path) -> int:
    """Use the existing validated GPT reader: never write into partition #5."""
    from windows_cachyos_overlay_reboot import gpt_windows
    from windows_cachyos_qcow2_gpt_readonly import (
        SECTOR, WINDOW_BYTES, header_at, part_array,
    )
    with tempfile.TemporaryDirectory(prefix="mint-ab-gpt-read-", dir=reference.parent) as t:
        front, back = gpt_windows(reference, Path(t))
    total = VIRTUAL_BYTES // SECTOR
    h = header_at(front, SECTOR, 1, total-1, total)
    entries = part_array(h, front, back, total)
    require(not any(entries[5*128:]) and all(
        any(entries[i*128:i*128+16]) for i in range(5)),
        "invalid GPT partition count before scratch injection")
    spans = [struct.unpack_from("<QQ", entries, i*128+32) for i in range(5)]
    require(all(a <= b for a, b in spans)
            and all(spans[i][1] < spans[i+1][0] for i in range(4)),
            "invalid GPT partition extents before scratch injection")
    # At least 1 MiB after the real GPT fifth-partition end, preserving backup GPT.
    scratch_lba = ((spans[-1][1] + 2048 + 2047) // 2048) * 2048
    require(scratch_lba * SECTOR + WRITE_SIZE <= (total-34) * SECTOR
            and scratch_lba > spans[-1][1],
            "no verified unallocated GPT extent for scratch corruption")
    return scratch_lba * SECTOR


def reproduce_restore(reference: Path, arm: Path, directory: Path) -> bool:
    """Corrupt only verified free GPT extent, restore via atomic independent clone."""
    file_guard(reference, directory, 0o400)
    file_guard(arm, directory, 0o600)
    offset = choose_injection_offset(reference)
    from windows_mint_ab_capacity import qemu_fully_allocated_bytes
    bound = qemu_fully_allocated_bytes()
    fs = os.statvfs(directory)
    require(fs.f_bavail * fs.f_frsize > bound + 2 * 1024**3,
            "insufficient additional space for atomic A/B restoration")
    temp = directory / (arm.name + ".restore.tmp.qcow2")
    require(not temp.exists() and not temp.is_symlink(),
            "refusing reused A/B restore temporary file")
    command(["qemu-io", "-f", "qcow2", "-c",
             f"write -P 0xa5 {offset} {WRITE_SIZE}", str(arm)], timeout=120)
    corrupted = command(["qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
                         str(reference), str(arm)], timeout=1800, check=False)
    require(corrupted.returncode == 1,
            "controlled scratch corruption was not independently detected")
    # Do not unlink the arm until a full NEW standalone restore is checked.
    # On ENOSPC, leave the corrupted arm and immutable reference as evidence.
    standalone(reference, temp, directory)
    equivalent(reference, temp)
    file_guard(arm, directory, 0o600)
    os.replace(temp, arm)
    fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    equivalent(reference, arm)
    return True


def prepare_checkpoint(*, base: Path, nvram: Path, overlay: Path,
                       mint_root_uuid: str, ovmf_code: Path,
                       tpm_state: Path | None = None,
                       diagnostic_dir: Path | None = None) -> dict:
    """VM-only, fail-closed source identity and COMPLETE restoration gate."""
    require(os.environ.get("GASLUX_MINT_AB_CHECKPOINT_CONSENT") == CONSENT,
            "missing separate Mint A/B checkpoint consent")
    validate_workspace(base, nvram)
    require(ovmf_code.is_file() and ovmf_code.stat().st_size > 1024*1024,
            "missing checked OVMF_CODE firmware")
    code_id = (ovmf_code.stat().st_dev, ovmf_code.stat().st_ino,
               ovmf_code.stat().st_size, ovmf_code.stat().st_mtime_ns)
    code_hash = sha256_file(ovmf_code)
    from uuid import UUID
    require(type(mint_root_uuid) is str
            and str(UUID(mint_root_uuid)) == mint_root_uuid,
            "missing authentic Mint filesystem UUID")
    source_dir = base.parent / CHECKPOINT_DIR
    require(overlay == source_dir / OVERLAY_NAME
            and source_dir.is_dir() and not source_dir.is_symlink()
            and stat.S_IMODE(source_dir.stat().st_mode) == 0o700,
            "unexpected source COW path")
    file_guard(overlay, source_dir, 0o600)
    require(stat.S_IMODE(base.stat().st_mode) == 0o400,
            "Windows backing not immutable")
    raw = json.loads(command(["qemu-img", "info", "-f", "qcow2",
                              "--output=json", str(overlay)], 60).stdout)
    require(raw.get("virtual-size") == VIRTUAL_BYTES
            and raw.get("backing-filename") == str(base)
            and raw.get("backing-filename-format") == "qcow2",
            "source is not authenticated Windows overlay")
    vars_source = source_dir / "trial-ovmf-variables.fd"
    file_guard(vars_source, source_dir, 0o600)
    source_id, base_id = qcow2_file_identity(overlay), qcow2_file_identity(base)
    source_vars_hash = sha256_file(vars_source)
    base_hash = sha256_file(base)
    # No Windows/TPM is running; clone VM state after fifth-root preparation,
    # before the first Mint kernel boots.
    directory = base.parent / AB_DIR
    require(not directory.exists() and not directory.is_symlink(),
            "refusing reused A/B checkpoint")
    # Second (late) gate: the early runner preflight is not a guarantee that
    # Windows Setup/ISO/root preparation left its originally measured budget.
    # Fail BEFORE mkdir, any large clone/convert or guest boot.
    from windows_mint_ab_capacity import (
        evidence as capacity_evidence, measure_capacity,
        qemu_fully_allocated_bytes,
    )
    capacity = measure_capacity(
        directory=base.parent, phase="late",
        full_allocated_bytes=qemu_fully_allocated_bytes(),
        base=base, overlay=overlay,
    )
    if diagnostic_dir is not None:
        capacity_evidence(diagnostic_dir/"mint-ab-capacity-late.json", capacity)
    require(capacity["result"] == "PASS",
            "insufficient runner space for independent A/B images and atomic restore")
    directory.mkdir(mode=0o700)
    require(stat.S_IMODE(directory.stat().st_mode) == 0o700,
            "A/B checkpoint directory permissions")
    reference = directory / REFERENCE
    standalone(overlay, reference, directory)
    reference.chmod(0o400)
    file_guard(reference, directory, 0o400)
    arm_a, arm_b = (directory / name for name in ARMS)
    for arm in (arm_a, arm_b):
        standalone(reference, arm, directory)
    require(len({p.stat().st_ino for p in (reference, arm_a, arm_b)}) == 3,
            "A/B images alias inode")
    for name in VARS:
        clone_vars(vars_source, directory / name, directory)
    tpm = clone_tpm_state(tpm_state, directory)
    require(reproduce_restore(reference, arm_a, directory),
            "A control recovery test failed")
    require(reproduce_restore(reference, arm_b, directory),
            "B treatment recovery test failed")
    reference_hash = sha256_file(reference)
    equivalent(reference, arm_a)
    equivalent(reference, arm_b)
    require(sha256_file(reference) == reference_hash
            and (ovmf_code.stat().st_dev, ovmf_code.stat().st_ino,
                 ovmf_code.stat().st_size, ovmf_code.stat().st_mtime_ns) == code_id
            and sha256_file(ovmf_code) == code_hash
            and sha256_file(vars_source) == source_vars_hash
            and sha256_file(directory / VARS[0]) == source_vars_hash
            and sha256_file(directory / VARS[1]) == source_vars_hash
            and sha256_file(base) == base_hash,
            "checkpoint or OVMF/backing mutated")
    require_unchanged_qcow2(overlay, source_id)
    require_unchanged_qcow2(base, base_id)
    txn = str(uuid.uuid4())
    result = {
        "schema": "gaslux-mint-independent-ab-checkpoint-v1",
        "transactionId": txn, "labOnly": True,
        "windowsWriteAuthorized": False, "productionInstallAuthorized": False,
        "nativeGrubDualBootVerified": False, "releaseEligible": False,
        "mintRootUuid": mint_root_uuid, "virtualDiskBytes": VIRTUAL_BYTES,
        "referenceSha256": reference_hash,
        "controlSha256": sha256_file(arm_a),
        "treatmentSha256": sha256_file(arm_b),
        "windowsBackingSha256": base_hash,
        "initialOvmfVarsSha256": source_vars_hash,
        "ovmfCodeSha256": code_hash,
        "tpm": tpm, "controlRecoveredAfterFaultInjection": True,
        "treatmentRecoveredAfterFaultInjection": True,
        "capacityPreflightSha256": (
            sha256_file(diagnostic_dir/"mint-ab-capacity-late.json")
            if diagnostic_dir is not None else None),
        "treatmentIndependent": True, "sharedBackingChains": False,
        "qemuCompareReferenceBothArmsPassed": True,
        "checkpointReadyForReview": True,
        "armsBooted": False, "windowsIntegrityAfterABVerified": False,
        "cleanupRestrictedToOwnedDirectory": AB_DIR,
    }
    manifest = directory / "checkpoint.json"
    with manifest.open("xb") as out:
        out.write((json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
        out.flush()
        os.fsync(out.fileno())
    handle = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)
    return result


if __name__ == "__main__":
    raise SystemExit("Library only; hosted isolated disposable Windows COW prerequisite")
