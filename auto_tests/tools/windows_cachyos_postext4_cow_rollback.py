#!/usr/bin/env python3
"""Prove disposable COW discard and a NEW Windows boot after fifth-root ext4.

This is a QCOW2 overlay experiment, NOT recovery after Linux installation or
in-place Windows/EFI/BCD/WinRE repair. Never operates on a physical disk.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time

from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, validate_workspace,
    sha256_file,
)
from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, qcow2_file_identity, require_unchanged_qcow2,
)
from windows_cachyos_overlay_reboot import (
    CONSENT as THIRD_BOOT_CONSENT,
    audit_complete_four_partition_serial,
    audit_complete_third_serial,
    gpt_windows, third_guest_args,
)
from windows_cachyos_overlay_ext4_only import CONSENT as EXT4_CONSENT
from windows_cachyos_postext4_windows import CONSENT as FOURTH_BOOT_CONSENT

CONSENT = "I_ACCEPT_COW_EXT4_DISCARD_AND_INDEPENDENT_WINDOWS_BASELINE_REBOOT"
RESTORED_OVERLAY = "windows-baseline-post-ext4-discard-boot.qcow2"
RESTORED_VARS = "windows-baseline-post-ext4-discard-vars.fd"


class CowRollbackError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise CowRollbackError(reason)


def verify_discard_postext4_cow(
    original: list[str], base: Path, nvram: Path, geometry: dict, cow: dict,
    stage: dict, third: dict, ext4: dict, fourth: dict, timeout: int = 1200,
) -> dict:
    """Discard only owned trial COW; boot Windows via a fresh disposable COW."""
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
        and os.environ.get("GASLUX_WINDOWS_POST_EXT4_COW_DISCARD_CONSENT") == CONSENT
        and os.environ.get("GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT") == FOURTH_BOOT_CONSENT
        and os.environ.get("GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT") == THIRD_BOOT_CONSENT
        and os.environ.get("GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT") == EXT4_CONSENT
        and type(timeout) is int and 120 <= timeout <= 1800,
        "separate GitHub-hosted ext4 COW discard and Windows reboot consent required",
    )
    require(
        all(type(v) is dict for v in (geometry, cow, stage, third, ext4, fourth))
        and geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True
        and len(geometry.get("windowsPartitions", [])) == 4
        and geometry.get("storageWritesAuthorized") is False
        and cow.get("candidateWindowsCowCheckpointPrepared") is True
        and cow.get("windowsBaselineUnchangedDuringCheckpoint") is True
        and cow.get("snapshotIndependentlyRestorable") is False
        and stage.get("overlayGptLinuxRootEntryPrepared") is True
        and stage.get("linuxRootFilesystemFormatted") is False
        and stage.get("linuxRoot", {}).get("index") == 5
        and stage.get("linuxRoot", {}).get("lengthBytes") == 24 * 1024**3
        and third.get("windowsBootAfterOverlayMutationVerified") is True
        and third.get("guestBcdWinreEspAfterOverlayVerified") is True
        and third.get("windowsGuestShutdownAfterOverlayVerified") is True
        and ext4.get("onlyOwnedOverlayFifthPartitionFormatted") is True
        and ext4.get("linuxRootFilesystemFormatted") is True
        and ext4.get("windowsBackingQcow2UnchangedAfterExt4") is True
        and ext4.get("windowsOriginalUefiUnchangedAfterExt4") is True
        and ext4.get("rootFilesystem", {}).get("allFourWindowsPartitionSha256Unchanged") is True
        and fourth.get("windowsBootAfterExt4Verified") is True
        and fourth.get("windowsBcdWinreEspAfterExt4Verified") is True
        and fourth.get("fourthGuestCleanShutdownVerified") is True
        and fourth.get("fifthExt4UuidSurvivedWindowsBoot") is True
        and fourth.get("windowsGptUnchangedAfterExt4Boot") is True
        and fourth.get("windowsBackingUnchangedAfterExt4Boot") is True
        and fourth.get("originalWindowsUefiUnchangedAfterExt4Boot") is True
        and all(x.get("cachyosInstalled") is False
                and x.get("windowsRecoveryAfterLinuxVerified") is False
                and x.get("rollbackProven") is False
                and x.get("storageWritesAuthorized") is False
                and x.get("releaseEligible") is False
                for x in (ext4, fourth)),
        "refuse COW discard without actual fourth Windows boot and exact ext4 proofs",
    )
    validate_workspace(base, nvram)
    directory = base.parent / CHECKPOINT_DIR
    require(
        directory.is_dir() and not directory.is_symlink()
        and directory.stat().st_uid == os.getuid()
        and stat.S_IMODE(directory.stat().st_mode) == 0o700,
        "foreign checkpoint directory",
    )
    overlay = directory / OVERLAY_NAME
    vars_baseline = directory / "windows-ovmf-baseline.fd"
    vars_trial = directory / "trial-ovmf-variables.fd"
    for item in (overlay, vars_baseline, vars_trial):
        owned_regular(item, directory, item.name)
    require(
        stat.S_IMODE(base.stat().st_mode) == 0o400
        and stat.S_IMODE(overlay.stat().st_mode) == 0o600
        and stat.S_IMODE(vars_baseline.stat().st_mode) == 0o400,
        "Windows baseline or ext4 overlay not protected",
    )
    fourth_serial = base.parent / "fourth-post-ext4-windows-serial.log"
    require(
        owned_regular(fourth_serial, base.parent, fourth_serial.name).st_size <= 512_000
        and audit_complete_third_serial(fourth_serial) == fourth["fourthGuestSerialSha256"],
        "fourth guest COM1 not authenticated against original evidence",
    )
    state = json.loads(subprocess.run(
        ["qemu-img", "info", "-f", "qcow2", "--output=json", str(overlay)],
        capture_output=True, text=True, check=True, timeout=30,
    ).stdout)
    require(
        state.get("format") == "qcow2"
        and state.get("virtual-size") == VIRTUAL_BYTES
        and state.get("backing-filename") == str(base)
        and state.get("backing-filename-format") == "qcow2"
        and not state.get("encrypted", False),
        "not an owned exact-chain post-ext4 overlay",
    )
    baseline_id = qcow2_file_identity(base)
    baseline_sha = sha256_file(base)
    nvhash = sha256_file(nvram)
    require(
        cow.get("uefiVarsCopySha256") == nvhash
        and sha256_file(vars_baseline) == nvhash,
        "original Windows firmware baseline inconsistent",
    )
    restored = directory / RESTORED_OVERLAY
    trial_vars = directory / RESTORED_VARS
    serial = base.parent / "fifth-after-ext4-discard-windows-serial.log"
    stderr_path = base.parent / "fifth-after-ext4-discard-qemu-stderr.log"
    require(
        all(not p.exists() and not p.is_symlink()
            for p in (restored, trial_vars, serial, stderr_path)),
        "refuse reused COW rollback/boot evidence",
    )
    with tempfile.TemporaryDirectory(prefix="gaslux-cow-before-discard-", dir=base.parent) as tmp:
        untouched_windows_gpt = gpt_windows(base, Path(tmp))
        staged_linux_gpt = gpt_windows(overlay, Path(tmp))
    require(
        untouched_windows_gpt != staged_linux_gpt
        and sha256_file(base) == baseline_sha
        and qcow2_file_identity(base) == baseline_id,
        "Linux GPT trial absent or Windows source changed",
    )

    # The trial ext4 is disposable; never delete or repair an in-place Linux installation.
    # Only our named, singly linked runner-owned private COW can be discarded.
    owned_regular(overlay, directory, OVERLAY_NAME)
    overlay.unlink()
    require(not overlay.exists(), "trial ext4 COW discard failed")
    require_unchanged_qcow2(base, baseline_id)
    require(sha256_file(base) == baseline_sha, "Windows backing changed during discard")

    # A NEW overlay permits genuine Windows guest writes without ever opening
    # the protected Windows QCOW2 for writing. No old Linux partition exists.
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
         "-b", str(base), str(restored)],
        check=True, capture_output=True, timeout=45,
    )
    owned_regular(restored, directory, RESTORED_OVERLAY)
    restored.chmod(0o600)
    require(stat.S_IMODE(restored.stat().st_mode) == 0o600,
            "restored trial disk not private")
    subprocess.run(
        ["qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
         str(base), str(restored)],
        check=True, capture_output=True, timeout=180,
    )
    with nvram.open("rb") as source, trial_vars.open("xb") as target:
        shutil.copyfileobj(source, target, length=256 * 1024)
    trial_vars.chmod(0o600)
    require(sha256_file(trial_vars) == nvhash,
            "fresh boot firmware differs from original Windows baseline")

    args = third_guest_args(original, base, nvram, restored, trial_vars, serial)
    floppy = [i for i in range(len(args) - 1)
              if args[i] == "-drive" and args[i + 1].startswith("if=floppy,")]
    require(len(floppy) <= 1, "ambiguous or foreign floppy device")
    if floppy:
        del args[floppy[0]:floppy[0] + 2]
    require(
        all(str(base) not in a and str(nvram) not in a
            and "verified_iso" not in a and "if=floppy" not in a
            and "usb-storage" not in a for a in args)
        and args.count("-boot") == 1 and args[args.index("-boot") + 1] == "order=c"
        and args.count("-monitor") == 1 and args[args.index("-monitor") + 1] == "none",
        "fifth Windows guest could use source disk, original NVRAM, DVD or USB",
    )
    with stderr_path.open("xb") as err:
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
        try:
            start = time.monotonic()
            while time.monotonic() - start < timeout:
                if serial.is_file():
                    require(
                        not serial.is_symlink() and serial.stat().st_size <= 512_000,
                        "untrusted or oversized fifth Windows COM1 log",
                    )
                    if b"GASLUX_COW_WIN10_REBOOT_FAIL=1" in serial.read_bytes():
                        raise CowRollbackError("restored Windows rejected BCD or WinRE audit")
                exit_code = process.poll()
                if exit_code is not None:
                    require(exit_code == 0, "restored Windows VM did not shut down cleanly")
                    # A complete COM1 witness is accepted only after QEMU terminates.
                    serial_digest = audit_complete_four_partition_serial(serial)
                    break
                time.sleep(3)
            else:
                raise CowRollbackError("restored Windows fifth boot timed out")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)

    with tempfile.TemporaryDirectory(prefix="gaslux-cow-after-discard-", dir=base.parent) as tmp:
        require(gpt_windows(base, Path(tmp)) == untouched_windows_gpt,
                "Windows backing GPT changed during recovered boot")
        require(gpt_windows(restored, Path(tmp)) == untouched_windows_gpt,
                "restored Windows boot did not retain exactly four GPT partitions")
    require_unchanged_qcow2(base, baseline_id)
    require(sha256_file(base) == baseline_sha,
            "Windows backing QCOW2 content mutated during restored guest boot")
    require(sha256_file(nvram) == nvhash and sha256_file(vars_baseline) == nvhash,
            "original Windows UEFI state changed during restored boot")
    owned_regular(restored, directory, RESTORED_OVERLAY)
    owned_regular(trial_vars, directory, RESTORED_VARS)
    restored.unlink()
    trial_vars.unlink()
    require(not restored.exists() and not trial_vars.exists(),
            "restored trial files not discarded after guest shutdown")

    return {
        "ownedExt4OverlayDiscarded": True,
        "windowsBaselineFourGptVerifiedAfterDiscard": True,
        "windowsFifthGuestBootAfterExt4DiscardVerified": True,
        "windowsBcdWinreEspAfterExt4DiscardVerified": True,
        "windowsGuestCleanShutdownAfterExt4DiscardVerified": True,
        "windowsBackingQcow2Sha256Unchanged": True,
        "originalWindowsUefiUnchangedAfterDiscard": True,
        "fifthGuestSerialSha256": serial_digest,
        "cachyosInstalled": False,
        "cachyosFirstBootVerified": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "windowsInPlaceRecoveryVerified": False,
        "rollbackProven": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only. No host devices, installed Linux or real rollback.")
