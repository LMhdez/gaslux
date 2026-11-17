#!/usr/bin/env python3
"""One disposable Windows 10 QCOW2: Linux GPT entry solely in throwaway COW.

Reuses PR #136/#142 Windows COW+bounded libguestfs GPT stage and PR #150
real read-only EFI/BCD/WinRE hash audit. NO Linux OS installed. Only runs
after the real Windows guest's verified clean shutdown in GitHub-hosted KVM.
The immutable Windows base is never attached writable after checkpoint.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid

from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, prepare_postboot_cow,
    sha256_file, validate_workspace,
)
from windows_cachyos_overlay_gpt_stage import (
    stage_overlay_gpt,
)
from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, qcow2_file_identity, inspect_owned_qcow2,
)
from windows_x64_installed_gpt_ro_audit import inspect_owned_disk


class GptOverlayTrialRejected(ValueError):
    pass


def require(value: bool, why: str) -> None:
    if not value:
        raise GptOverlayTrialRejected(why)


def run(*args: str, timeout: int = 180) -> str:
    return subprocess.run(args, check=True, capture_output=True,
                          text=True, timeout=timeout).stdout


def directory_sync(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_overlay(disk: Path, overlay: Path, name: str) -> None:
    owned_regular(overlay, overlay.parent, name)
    require(stat.S_IMODE(overlay.stat().st_mode) == 0o600,
            "COW overlay must be exclusively owned and private")
    info = json.loads(run("qemu-img", "info", "-f", "qcow2",
                          "--output=json", str(overlay)))
    require(info.get("format") == "qcow2"
            and info.get("virtual-size") == VIRTUAL_BYTES
            and info.get("backing-filename") == str(disk)
            and info.get("backing-filename-format") == "qcow2"
            and not info.get("encrypted", False),
            "foreign or ambiguous COW backing chain")


def prepare_linux_gpt_rehearsal(disk: Path, nvram: Path,
                                geometry: dict) -> dict:
    """Write exactly the fifth GPT entry ONLY into new disposable COW.

    Leaves a separate pristine overlay for a third Windows guest. Disk,
    original NVRAM and both GPT Windows baselines are never written here.
    """
    validate_workspace(disk, nvram)
    require(os.environ.get("GASLUX_WINDOWS_OVERLAY_REBOOT_TEST") ==
            "I_ACCEPT_HOSTED_WINDOWS_POST_OVERLAY_REBOOT_ONLY" and
            os.environ.get("GASLUX_CACHYOS_OVERLAY_GPT_CONSENT") ==
            "I_ACCEPT_DISPOSABLE_QCOW2_OVERLAY_GPT_ONLY",
            "explicit same-run Windows reboot and GPT overlay consents absent")
    require(type(geometry) is dict and
            geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True
            and geometry.get("storageWritesAuthorized") is False
            and geometry.get("releaseEligible") is False
            and len(geometry.get("windowsPartitions", [])) == 4,
            "real installed Windows GPT candidate absent or unsafe")
    ext4_consent = os.environ.get("GASLUX_CACHYOS_ROOT_EXT4_COW_CONSENT")
    require(ext4_consent in (None,
            "I_ACCEPT_ONLY_OWNED_FIFTH_EXT4_IN_THROWAWAY_QCOW2"),
            "unknown ext4 COW-only format consent")
    windows_files = inspect_owned_disk(disk)
    require(windows_files["partitionCount"] == 4 and
            windows_files["espBootManagerPresent"] and
            windows_files["espBcdPresent"] and
            windows_files["winreImageOnRecoveryPresent"],
            "independent Windows EFI/BCD/WinRE baseline unavailable")
    original_hash = sha256_file(disk)
    original_vars = sha256_file(nvram)
    checkpoint_proof = prepare_postboot_cow(disk, nvram, geometry)
    checkpoint = disk.parent / CHECKPOINT_DIR
    initial_identity = qcow2_file_identity(disk)
    # Deterministic, strongly bound lab GUID; no host disk identifiers.
    unique = uuid.uuid5(
        uuid.NAMESPACE_URL,
        "gaslux-owned-cachyos-only-guest-gpt:" +
        str(geometry["diskGuidSha256"]) + ":" + original_hash,
    )
    staged = stage_overlay_gpt(
        disk, nvram, geometry, checkpoint_proof, unique)
    require(all(staged.get(k) is True for k in (
        "overlayGptLinuxRootEntryPrepared", "onlyDisposableOverlayModified",
        "windowsPartitionEntriesUnchanged", "windowsPartitionBoundarySamplesUnchanged",
        "protectiveMbrAndGptOutsideWhitelistUnchanged",
        "bothGptMirrorsAfterStageVerified", "windowsBackingQcow2Unchanged",
        "windowsUefiVariablesUnchanged")),
        "COW GPT stage did not fully prove Windows partition preservation")
    require(staged["linuxRoot"]["index"] == 5 and
            staged["linuxRoot"]["lengthBytes"] == 24 * 1024**3 and
            staged["linuxRoot"]["uniqueGuid"] == str(unique),
            "unexpected transaction-owned Linux GPT partition")
    require(staged.get("cachyosInstalled") is False and
            staged.get("linuxRootFilesystemFormatted") is False and
            staged.get("storageWritesAuthorized") is False,
            "partition stage falsely claimed installed Linux or write authorization")
    ext4_trial = None
    if ext4_consent:
        from windows10_cachyos_owned_ext4_cow import format_fifth_ext4_only_in_cow
        ext4_trial = format_fifth_ext4_only_in_cow(
            disk, nvram, geometry, staged, windows_files)
        require(
            ext4_trial.get("linuxRootExt4FormattedInDiscardableCOW") is True and
            ext4_trial.get("onlyOwnedFifthPartitionFormatted") is True and
            ext4_trial.get("windowsEfiBcdUnchangedInsideOverlay") is True and
            ext4_trial.get("windowsBackingQcow2Unchanged") is True and
            ext4_trial.get("cachyosInstalled") is False and
            ext4_trial.get("storageWritesAuthorized") is False,
            "ext4 target COW format evidence not trustworthy")
    linux_overlay = checkpoint / OVERLAY_NAME
    validate_overlay(disk, linux_overlay, OVERLAY_NAME)
    require(qcow2_file_identity(disk) == initial_identity and
            sha256_file(disk) == original_hash and
            sha256_file(nvram) == original_vars and
            inspect_owned_disk(disk) == windows_files,
            "Windows backing or actual EFI/BCD/WinRE hashes changed after GPT stage")
    # Overlay discard, NOT filesystem/Windows recovery or in-place undo.
    linux_overlay.unlink()
    directory_sync(checkpoint)
    require(not linux_overlay.exists() and
            qcow2_file_identity(disk) == initial_identity,
            "Linux GPT overlay not discarded or base identity changed")
    # Third Windows boot MUST be writable only on this fresh, initially
    # identical COW. The installed Windows OS has a scheduled audit task.
    boot_name = "windows-reboot-after-linux-gpt-discard.qcow2"
    boot_overlay = checkpoint / boot_name
    require(not boot_overlay.exists() and not boot_overlay.is_symlink(),
            "refusing a reused Windows boot overlay")
    run("qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
        "-b", str(disk), str(boot_overlay))
    boot_overlay.chmod(0o600)
    validate_overlay(disk, boot_overlay, boot_name)
    require("Images are identical" in run(
        "qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
        str(disk), str(boot_overlay), timeout=240),
        "third Windows boot overlay does not match its immutable baseline")
    base_vars = checkpoint / "windows-ovmf-baseline.fd"
    trial_vars = checkpoint / "trial-ovmf-variables.fd"
    require(sha256_file(base_vars) == original_vars and
            sha256_file(trial_vars) == original_vars,
            "OVMF baseline/trial variables differ before Windows reboot")
    print("GASLUX_WINDOWS10_REAL_GPT_LINUX_PARTITION_STAGED_ONLY_ON_COW=1", flush=True)
    print("GASLUX_WINDOWS10_LINUX_GPT_COW_DISCARDED_BASE_UNCHANGED=1", flush=True)
    return {
        "bootOverlay": boot_overlay,
        "trialVars": trial_vars,
        "originalVarsSha256": original_vars,
        "originalDiskSha256": original_hash,
        "originalIdentity": initial_identity,
        "originalWindowsHashes": windows_files,
        "linuxPartition": staged["linuxRoot"],
        "rootExt4Trial": ext4_trial,
        "windowsBootAfterLinuxPartitionDiscardVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


def build_post_discard_boot_args(
    normal_args: list[str], clean_overlay: Path, trial_vars: Path,
) -> list[str]:
    """Change only the third guest's lab disk and pflash VARS to COW targets."""
    args = list(normal_args)
    drives = [i for i in range(len(args) - 1)
              if args[i] == "-drive" and
              args[i + 1].startswith("if=none,id=only_windows,format=qcow2,file=")]
    vars_drives = [i for i in range(len(args) - 1)
                   if args[i] == "-drive" and
                   args[i + 1].startswith("if=pflash,format=raw,file=")]
    require(len(drives) == 1 and len(vars_drives) == 1 and
            drives[0] != vars_drives[0],
            "unknown third-guest disk or OVMF device chain")
    require(clean_overlay.name == "windows-reboot-after-linux-gpt-discard.qcow2"
            and trial_vars.name == "trial-ovmf-variables.fd"
            and clean_overlay.parent == trial_vars.parent,
            "foreign third-guest COW targets")
    args[drives[0] + 1] = ("if=none,id=only_windows,format=qcow2,file="
                           + str(clean_overlay))
    args[vars_drives[0] + 1] = "if=pflash,format=raw,file=" + str(trial_vars)
    require("order=c" in args and
            all("verified_iso" not in v and "if=floppy" not in v
                for v in args),
            "third Windows guest still has installation media")
    return args


def verify_after_independent_windows_boot(
    disk: Path, nvram: Path, staged: dict, *, guest_verified: bool,
) -> dict:
    """Require guest-side COM1 proof already checked by the caller."""
    require(guest_verified is True and
            staged.get("windowsBootAfterLinuxPartitionDiscardVerified") is False,
            "independent third Windows boot not proven")
    validate_workspace(disk, nvram)
    checkpoint = disk.parent / CHECKPOINT_DIR
    overlay = staged["bootOverlay"]
    require(overlay.parent == checkpoint and
            overlay.name == "windows-reboot-after-linux-gpt-discard.qcow2",
            "foreign Windows reboot overlay")
    validate_overlay(disk, overlay, overlay.name)
    # The Windows boot guest writes only into this new, private COW. The
    # baseline disk is read-only and its OVMF VARS are never attached writable.
    overlay.unlink()
    directory_sync(checkpoint)
    require(not overlay.exists() and
            qcow2_file_identity(disk) == staged["originalIdentity"] and
            sha256_file(disk) == staged["originalDiskSha256"] and
            sha256_file(nvram) == staged["originalVarsSha256"],
            "base Windows disk/OVMF was modified during third boot")
    original_vars = checkpoint / "windows-ovmf-baseline.fd"
    require(sha256_file(original_vars) == staged["originalVarsSha256"],
            "baseline Windows UEFI variables changed after third boot")
    require(inspect_owned_qcow2(disk)["candidateWindowsGptPrimaryAndBackupConsistent"]
            is True and
            inspect_owned_disk(disk) == staged["originalWindowsHashes"],
            "actual Windows ESP, BCD, loader, WinRE or GPT changed")
    print("GASLUX_WINDOWS10_POST_LINUX_GPT_OVERLAY_DISCARD_WINDOWS_BOOT=1", flush=True)
    print("GASLUX_WINDOWS10_POST_LINUX_GPT_OVERLAY_DISCARD_EFI_BCD_WINRE_SHA=1",
          flush=True)
    return {
        "linuxPartitionEntryCreatedOnlyInDiscardedOverlay": True,
        "linuxPartitionGuid": staged["linuxPartition"]["uniqueGuid"],
        "linuxPartitionLengthBytes": 24 * 1024**3,
        "linuxRootFilesystemFormatted": False,
        "linuxRootExt4TrialPerformedOnlyOnDiscardedOverlay":
            staged.get("rootExt4Trial") is not None,
        "linuxRootExt4TrialUuid": (
            staged["rootExt4Trial"]["rootUuid"]
            if staged.get("rootExt4Trial") is not None else None),
        "cachyosInstalled": False,
        "windowsBootAfterLinuxPartitionDiscardVerified": True,
        "windowsEspBcdWinreBaseHashesUnchanged": True,
        "windowsBackingQcow2Sha256Unchanged": True,
        "windowsUefiBaselineUnchanged": True,
        "windowsBcdWinreRestorationVerified": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }
