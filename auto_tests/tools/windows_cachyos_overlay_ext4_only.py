"""CI-only Windows+CachyOS fifth GPT ext4 stage, hosted disposable QCOW2 only.

After genuine third Windows boot on the Linux-GPT overlay, hash ALL four
Windows partitions, format only the fifth GUEST partition and compare again.
No host block devices, ESP/BCD writes, pacstrap, bootloader, or release.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from uuid import UUID
from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, validate_workspace, sha256_file,
)
from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, WINDOW_BYTES, qcow2_file_identity, require_unchanged_qcow2,
)
from windows_cachyos_overlay_gpt_stage import (
    LAB_CONSENT as GPT_CONSENT, verify_linux_root_layout,
)
from windows_cachyos_overlay_reboot import (
    CONSENT as BOOT_CONSENT, PROOF as WINDOWS_PROOF, gpt_windows,
)

CONSENT = "I_ACCEPT_EXT4_ONLY_FIFTH_PARTITION_ON_HOSTED_WIN10_COW"

class Ext4SafetyError(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise Ext4SafetyError(message)

def format_only_fifth(guest, front: bytes, back: bytes) -> dict:
    """The only write is mkfs(ext4, exact guest partition #5), then sync."""
    devices = guest.list_devices()
    require(len(devices) == 1, "ambiguous libguestfs disk identity")
    dev = devices[0]
    require(type(dev) is str and dev.startswith("/dev/")
            and guest.blockdev_getsize64(dev) == VIRTUAL_BYTES,
            "wrong single guest disk geometry")
    suffix = "p" if dev[-1].isdigit() else ""
    parts = [dev + suffix + str(i) for i in range(1, 6)]
    require(guest.list_partitions() == parts,
            "extra, missing or reordered guest partitions")
    root = parts[4]
    require(guest.blockdev_getsize64(root) == 24*1024**3,
            "unowned Linux partition extent")
    require(guest.pread_device(dev, WINDOW_BYTES, 0) == front
            and guest.pread_device(dev, WINDOW_BYTES,
                                   VIRTUAL_BYTES-WINDOW_BYTES) == back,
            "GPT changed before ext4")
    require(guest.vfs_type(root) in ("", "unknown"),
            "refusing foreign or already-formatted root")
    before = [guest.checksum_device("sha256", p) for p in parts[:4]]
    require(len(before) == 4 and all(
        type(x) is str and len(x) == 64 and
        all(c in "0123456789abcdef" for c in x) for x in before
    ), "missing full-partition Windows hashes")
    guest.mkfs("ext4", root)
    guest.sync()
    require(guest.vfs_type(root) == "ext4",
            "ext4 format did not persist")
    try:
        fs_uuid = UUID(guest.vfs_uuid(root))
    except (TypeError, ValueError, AttributeError) as exc:
        raise Ext4SafetyError("invalid ext4 filesystem UUID") from exc
    require(fs_uuid.int != 0, "zero ext4 filesystem UUID")
    after = [guest.checksum_device("sha256", p) for p in parts[:4]]
    require(before == after,
            "Windows partition changed during ext4 operation")
    require(guest.pread_device(dev, WINDOW_BYTES, 0) == front
            and guest.pread_device(dev, WINDOW_BYTES,
                                   VIRTUAL_BYTES-WINDOW_BYTES) == back,
            "GPT changed during ext4 operation")
    return {"filesystemType": "ext4", "filesystemUuid": str(fs_uuid),
            "windowsFourPartitionSha256": before,
            "allFourWindowsPartitionSha256Unchanged": True,
            "gptMirrorsByteIdenticalAfterExt4": True}

def format_owned_fifth(base: Path, nvram: Path, geometry: dict,
                       cow: dict, stage: dict, third: dict) -> dict:
    """All evidence and ownership gates run before any guestfs RW open."""
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT") == CONSENT
            and os.environ.get("GASLUX_CACHYOS_OVERLAY_GPT_CONSENT") == GPT_CONSENT
            and os.environ.get("GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT") == BOOT_CONSENT,
            "separate hosted fifth ext4 consent required")
    require(type(geometry) is dict and type(cow) is dict and
            type(stage) is dict and type(third) is dict
            and geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True
            and geometry.get("storageWritesAuthorized") is False
            and cow.get("candidateWindowsCowCheckpointPrepared") is True
            and cow.get("windowsBaselineUnchangedDuringCheckpoint") is True
            and stage.get("overlayGptLinuxRootEntryPrepared") is True
            and stage.get("onlyDisposableOverlayModified") is True
            and stage.get("bothGptMirrorsAfterStageVerified") is True
            and stage.get("windowsBackingQcow2Unchanged") is True
            and stage.get("linuxRootFilesystemFormatted") is False
            and stage.get("cachyosInstalled") is False
            and third.get("windowsBootAfterOverlayMutationVerified") is True
            and third.get("guestBcdWinreEspAfterOverlayVerified") is True
            and third.get("windowsGuestShutdownAfterOverlayVerified") is True
            and third.get("fifthGptUnchangedAfterGuestBoot") is True
            and third.get("windowsBackingUnchangedAfterGuestBoot") is True
            and third.get("originalUefiVarsUnchangedAfterGuestBoot") is True
            and third.get("sameDiskDualBootVerified") is False
            and third.get("releaseEligible") is False,
            "fifth ext4 requires successful genuine Windows third boot")
    validate_workspace(base, nvram)
    directory = base.parent / CHECKPOINT_DIR
    require(directory.is_dir() and not directory.is_symlink()
            and directory.stat().st_uid == os.getuid()
            and stat.S_IMODE(directory.stat().st_mode) == 0o700,
            "unowned COW directory")
    overlay = directory / OVERLAY_NAME
    vars_baseline = directory / "windows-ovmf-baseline.fd"
    vars_trial = directory / "trial-ovmf-variables.fd"
    for item in (overlay, vars_baseline, vars_trial):
        owned_regular(item, directory, item.name)
    require(stat.S_IMODE(base.stat().st_mode) == 0o400
            and stat.S_IMODE(overlay.stat().st_mode) == 0o600
            and stat.S_IMODE(vars_baseline.stat().st_mode) == 0o400,
            "unsafe COW backing permissions")
    nv_hash = sha256_file(nvram)
    require(nv_hash == cow.get("uefiVarsCopySha256")
            and sha256_file(vars_baseline) == nv_hash,
            "Windows UEFI baseline changed")
    trial_hash = sha256_file(vars_trial)
    info = json.loads(subprocess.run(
        ["qemu-img", "info", "-f", "qcow2", "--output=json", str(overlay)],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout)
    require(info.get("format") == "qcow2"
            and info.get("virtual-size") == VIRTUAL_BYTES
            and info.get("backing-filename") == str(base)
            and info.get("backing-filename-format") == "qcow2"
            and not info.get("encrypted", False),
            "unexpected COW backing image")
    identity = qcow2_file_identity(base)
    serial = base.parent / "third-overlay-windows-serial.log"
    require(serial.is_file() and not serial.is_symlink()
            and 0 < serial.stat().st_size <= 512_000
            and sha256_file(serial) == third.get("thirdBootGuestSerialSha256"),
            "unverified Windows overlay boot COM1")
    lines = set(serial.read_text(encoding="utf-8", errors="replace").splitlines())
    require(set(WINDOWS_PROOF).issubset(lines)
            and "GASLUX_COW_WIN10_REBOOT_FAIL=1" not in lines,
            "Windows audit missing or rejected")
    linux = stage.get("linuxRoot")
    require(type(linux) is dict and linux.get("index") == 5
            and linux.get("lengthBytes") == 24*1024**3
            and linux.get("firstLba") > geometry["windowsPartitions"][-1]["lastLba"],
            "unowned fifth GPT extent")
    with tempfile.TemporaryDirectory(prefix="gaslux-ext4-before-", dir=base.parent) as tmp:
        baseline = gpt_windows(base, Path(tmp))
        staged = gpt_windows(overlay, Path(tmp))
    verify_linux_root_layout(
        *baseline, *staged, linux["firstLba"],
        linux["lastLba"], UUID(linux["uniqueGuid"]),
    )
    require_unchanged_qcow2(base, identity)
    import guestfs  # available only in hosted VM lab after all checks
    guest = guestfs.GuestFS(python_return_dict=True)
    try:
        guest.add_drive_opts(str(overlay), format="qcow2", readonly=0)
        guest.launch()
        formatted = format_only_fifth(guest, *staged)
    finally:
        try:
            guest.shutdown()
        finally:
            guest.close()
    with tempfile.TemporaryDirectory(prefix="gaslux-ext4-after-", dir=base.parent) as tmp:
        final = gpt_windows(overlay, Path(tmp))
    require(final == staged, "post-close GPT differs from pre-format GPT")
    require_unchanged_qcow2(base, identity)
    require(sha256_file(nvram) == nv_hash
            and sha256_file(vars_baseline) == nv_hash
            and sha256_file(vars_trial) == trial_hash,
            "original Windows or trial EFI variables changed")
    return {
        "onlyOwnedOverlayFifthPartitionFormatted": True,
        "linuxRootFilesystemFormatted": True,
        "linuxRoot": linux,
        "rootFilesystem": formatted,
        "windowsBaseGptUnchangedAfterExt4": True,
        "windowsBackingQcow2UnchangedAfterExt4": True,
        "windowsOriginalUefiUnchangedAfterExt4": True,
        "windowsBootAfterExt4Verified": False,
        "cachyosInstalled": False,
        "cachyosFirstBootVerified": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "rollbackProven": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }

if __name__ == "__main__":
    raise SystemExit("Library only; never open host disk devices")
