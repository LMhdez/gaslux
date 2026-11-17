#!/usr/bin/env python3
"""Real Windows 10 QCOW2 overlay isolation gate, hosted VM laboratory ONLY.

After a verified clean Windows shutdown, corrupt one GPT byte inside a newly
created QCOW2 *overlay*, then discard it and verify the backing Windows disk
did not change. Does not install Linux, modify BCD/ESP, or boot Windows again.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from windows_cachyos_qcow2_gpt_readonly import (
    WINDOW_BYTES, VIRTUAL_BYTES, SECTOR, GeometryError, bounded_qcow2_dd_command,
    qcow2_file_identity, require_unchanged_qcow2, inspect_gpt_windows,
    inspect_owned_qcow2,
)


def require(ok: bool, why: str) -> None:
    if not ok:
        raise GeometryError(why)


def cmd(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True,
                          check=True, timeout=90).stdout


def owned_base(base: Path) -> None:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT") ==
            "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY"
        and os.environ.get("GASLUX_WINDOWS_OVERLAY_TEST") ==
            "I_ACCEPT_NEW_QCOW2_OVERLAY_ONLY"
        and base.name == "only-disposable-windows-target.qcow2"
        and base.parent.parent == Path("/home/runner/work/_temp")
        and base.parent.name.startswith("gaslux-win-x64-")
        and base.parent.stat().st_uid == os.getuid()
        and stat.S_IMODE(base.parent.stat().st_mode) == 0o700
        and not base.is_symlink()
        and base.is_file()
        and base.stat().st_nlink == 1,
        "overlay test requires already shut-down owned Windows CI disk",
    )


def read_windows(disk: Path, scratch: Path) -> tuple[bytes, bytes]:
    result = []
    for side in ("front", "back"):
        out = scratch / (side + ".raw")
        subprocess.run(bounded_qcow2_dd_command(disk, out, side),
                       capture_output=True, check=True, timeout=90)
        data = out.read_bytes()
        require(len(data) == WINDOW_BYTES, "QCOW2 GPT window incomplete")
        out.unlink()
        result.append(data)
    return result[0], result[1]


def overlay_trial(base: Path) -> dict:
    owned_base(base)
    identity = qcow2_file_identity(base)
    original = inspect_owned_qcow2(base)
    if os.environ.get("GASLUX_WINDOWS_GUESTFS_TEST") != "I_ACCEPT_READONLY_FILESYSTEM_AUDIT":
        raise GeometryError("missing explicit read-only filesystem audit consent")
    from windows_x64_installed_gpt_ro_audit import inspect_owned_disk
    original_fs = inspect_owned_disk(base)
    require(original_fs["recoveryGptPartitionPresent"] is True
            and original_fs["winreImageOnRecoveryPresent"] is True
            and all(original_fs.get(field) for field in (
                "espBootManagerSha256", "espBcdSha256",
                "windowsLoaderSha256", "winreImageSha256")),
            "Windows EFI/BCD/WinRE offline hash baseline absent")
    require(original["candidateWindowsGptPrimaryAndBackupConsistent"] is True
            and original["storageWritesAuthorized"] is False
            and original["sameDiskDualBootVerified"] is False,
            "Windows disk prerequisite failed")
    with tempfile.TemporaryDirectory(prefix="gaslux-windows-overlay-", dir=base.parent) as temp:
        scratch = Path(temp)
        before = read_windows(base, scratch)
        require_unchanged_qcow2(base, identity)
        overlay = scratch / "discard-me.qcow2"
        require(not overlay.exists(), "overlay previously exists")
        # Never mount or expose the backing Windows QCOW2 as a writable device.
        cmd("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
            str(base), str(overlay))
        info = json.loads(cmd("qemu-img", "info", "--output=json", str(overlay)))
        require(info.get("format") == "qcow2"
                and info.get("virtual-size") == VIRTUAL_BYTES
                and info.get("full-backing-filename") == str(base),
                "overlay backing chain not pinned to Windows CI base")
        require_unchanged_qcow2(base, identity)
        # Fault injection confined to a disposable overlay: deliberately
        # corrupt the primary GPT header, so a trusted validator MUST refuse.
        cmd("qemu-io", "-f", "qcow2", "-c",
            "write -P 0xa5 512 512", str(overlay))
        damaged = read_windows(overlay, scratch)
        require(damaged[0][512:1024] != before[0][512:1024]
                and damaged[1] == before[1],
                "fault not confined to primary GPT in overlay")
        try:
            inspect_gpt_windows(*damaged)
        except GeometryError:
            pass
        else:
            raise GeometryError("corrupted GPT overlay unexpectedly accepted")
        require_unchanged_qcow2(base, identity)
        # Recovery in this first lab is *discarding the overlay*, not
        # repairing live Windows GPT/EFI/BCD/WinRE in place.
        overlay.unlink()
        require(not overlay.exists(), "discarded overlay still exists")
        after = read_windows(base, scratch)
        require(after == before, "backing Windows GPT windows changed")
        require_unchanged_qcow2(base, identity)
        again = inspect_owned_qcow2(base)
        require(again == original, "Windows backing GPT evidence not restored")
        after_fs = inspect_owned_disk(base)
        require(after_fs == original_fs,
                "Windows EFI/BCD/WinRE read-only audit changed after overlay discard")
    print("GASLUX_WINDOWS_QCOW2_OVERLAY_PRIMARY_GPT_CORRUPTION_REJECTED=1",
          flush=True)
    print("GASLUX_WINDOWS_QCOW2_OVERLAY_DISCARD_BASE_WINDOWS_GPT_UNCHANGED=1",
          flush=True)
    print("GASLUX_WINDOWS_QCOW2_OVERLAY_ESP_BCD_WINRE_HASHES_UNCHANGED=1",
          flush=True)
    print("GASLUX_WINDOWS_QCOW2_OVERLAY_BCD_WINRE_REBOOT_NOT_TESTED=1",
          flush=True)
    return {
        "overlayFaultRejected": True,
        "overlayDiscarded": True,
        "backingWindowsGptUnchanged": True,
        "offlineEspBcdWinreHashesUnchanged": True,
        "windowsRebootAfterFaultVerified": False,
        "windowsBcdWinreRestorationVerified": False,
        "linuxInstalled": False,
        "dualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only: called after verified Windows firstboot shutdown")
