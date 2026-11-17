#!/usr/bin/env python3
"""Prepare an isolated, disposable Windows 10 QEMU copy-on-write trial checkpoint.

This is an OVERLAY-BASED lab checkpoint, not an independent Windows backup.
The immutable-in-this-run Windows QCOW2 remains a backing file and the
corresponding UEFI variable files are copied locally. No Linux is installed.
Never expose this helper to disks or Windows installation media in production.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, qcow2_file_identity,
)

EXPECTED_CONSENT = "I_ACCEPT_GITHUB_HOSTED_POSTBOOT_OVERLAY_ONLY"
ROOT = Path("/home/runner/work/_temp")
BASE_NAME = "only-disposable-windows-target.qcow2"
VARS_NAME = "ovmf-variables.fd"
OVERLAY_NAME = "cachyos-unwritten-trial-overlay.qcow2"
CHECKPOINT_DIR = "windows-uefi-cow-checkpoint"


class CheckpointError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise CheckpointError(reason)


def run_qemu(args: list[str], *, timeout: int = 40) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=timeout,
    )


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def owned_regular(path: Path, parent: Path, name: str) -> os.stat_result:
    require(path.parent == parent and path.name == name and
            not path.is_symlink(), "refusing foreign or redirected checkpoint source")
    entry = path.lstat()
    require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.getuid() and
            entry.st_nlink == 1 and entry.st_size > 0,
            "checkpoint source is not an exclusive owned regular file")
    return entry


def validate_workspace(disk: Path, nvram: Path) -> None:
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux" and
            os.environ.get("RUNNER_TEMP") == str(ROOT) and
            os.environ.get("GASLUX_WINDOWS_COW_CHECKPOINT_CONSENT") ==
            EXPECTED_CONSENT and
            os.environ.get("GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT") ==
            "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
            "COW checkpoint requires additional hosted-VM-only consent")
    parent = disk.parent
    require(parent.is_absolute() and parent.parent == ROOT and
            parent.name.startswith("gaslux-win-x64-") and
            not parent.is_symlink() and parent.is_dir() and
            parent.resolve() == parent and
            parent.stat().st_uid == os.getuid() and
            stat.S_IMODE(parent.stat().st_mode) == 0o700,
            "checkpoint must remain inside private owned Windows VM workspace")
    disk_stat = owned_regular(disk, parent, BASE_NAME)
    vars_stat = owned_regular(nvram, parent, VARS_NAME)
    require(disk_stat.st_size > 65536 and
            500_000 < vars_stat.st_size < 16*1024*1024,
            "Windows QCOW2 or private OVMF variables missing")
    # Stat and no-follow checks above intentionally precede invoking QEMU.
    # Only a disposable file-backed QCOW2 with no backing chain is accepted.
    info = json.loads(run_qemu([
        "qemu-img", "info", "-f", "qcow2", "--output=json", str(disk),
    ]).stdout)
    require(info.get("format") == "qcow2" and
            info.get("virtual-size") == VIRTUAL_BYTES and
            not info.get("backing-filename") and
            not info.get("full-backing-filename") and
            not info.get("encrypted", False),
            "Windows checkpoint source has incorrect QCOW2 geometry or backing")


def prepare_postboot_cow(
    disk: Path, nvram: Path, geometry: dict[str, object],
) -> dict[str, object]:
    """After verified Windows firstboot+shutdown+GPT, prepare protected trial.

    Only a disposable OVERLAY gets guest-writable disk semantics in the future.
    Base Windows QCOW2 and two UEFI VARS files never leave this runner.
    """
    require(type(geometry) is dict and
            geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True and
            geometry.get("storageWritesAuthorized") is False and
            geometry.get("releaseEligible") is False,
            "missing fail-closed post-Windows GPT geometry candidate")
    validate_workspace(disk, nvram)
    parent = disk.parent
    checkpoint = parent / CHECKPOINT_DIR
    require(not checkpoint.exists() and not checkpoint.is_symlink(),
            "refusing existing checkpoint directory")
    checkpoint.mkdir(mode=0o700)
    require(stat.S_IMODE(checkpoint.stat().st_mode) == 0o700,
            "checkpoint directory not private")
    # Freeze only runner-owned baseline file, *never* a real disk, EFI volume,
    # or user data. Source is kept intact for trial-overlay discard.
    disk.chmod(0o400)
    baseline_id = qcow2_file_identity(disk)
    vars_digest = sha256_file(nvram)
    base_vars = checkpoint / "windows-ovmf-baseline.fd"
    trial_vars = checkpoint / "trial-ovmf-variables.fd"
    for target in (base_vars, trial_vars):
        require(not target.exists() and not target.is_symlink(),
                "refusing to reuse UEFI variable checkpoint")
        with nvram.open("rb") as origin, target.open("xb") as out:
            shutil.copyfileobj(origin, out, length=256*1024)
        require(sha256_file(target) == vars_digest,
                "UEFI variable checkpoint differs from Windows source")
    base_vars.chmod(0o400)
    trial_vars.chmod(0o600)
    overlay = checkpoint / OVERLAY_NAME
    require(not overlay.exists() and not overlay.is_symlink(),
            "refusing existing Linux-trial overlay")
    run_qemu([
        "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
        "-b", str(disk), str(overlay),
    ])
    owned_regular(overlay, checkpoint, OVERLAY_NAME)
    # Keep the future writable trial image private even if qemu-img honors a
    # permissive default umask; never change the Windows source permissions.
    overlay.chmod(0o600)
    require(stat.S_IMODE(overlay.stat().st_mode) == 0o600,
            "disposable overlay not private")
    overlay_info = json.loads(run_qemu([
        "qemu-img", "info", "-f", "qcow2", "--output=json", str(overlay),
    ]).stdout)
    require(overlay_info.get("format") == "qcow2" and
            overlay_info.get("virtual-size") == VIRTUAL_BYTES and
            overlay_info.get("backing-filename") == str(disk) and
            overlay_info.get("backing-filename-format") == "qcow2" and
            not overlay_info.get("encrypted", False),
            "trial overlay is not bound to the exact Windows QCOW2")
    run_qemu([
        "qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
        str(disk), str(overlay),
    ], timeout=180)
    require(qcow2_file_identity(disk) == baseline_id and
            sha256_file(base_vars) == vars_digest and
            sha256_file(trial_vars) == vars_digest and
            stat.S_IMODE(disk.stat().st_mode) & 0o222 == 0,
            "Windows base or UEFI checkpoint changed during COW creation")
    return {
        "candidateWindowsCowCheckpointPrepared": True,
        "sourceVirtualDiskBytes": VIRTUAL_BYTES,
        "checkpointStrategy": "owned-qcow2-external-overlay-with-base-and-uefi-vars",
        "baselineCowBackingFormat": "qcow2",
        "uefiVarsCopySha256": vars_digest,
        "trialOverlayInitiallyMatchesWindows": True,
        "windowsBaselineUnchangedDuringCheckpoint": True,
        "snapshotIndependentlyRestorable": False,
        "windowsRebootAfterOverlayVerified": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only. No OS install, no host disks, no release approval.")
