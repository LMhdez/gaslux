#!/usr/bin/env python3
"""Hosted CI only: corrupt REAL Windows BCD inside disposable QCOW2 overlay.

No production disks, raw /dev nodes, or backing Windows QCOW2 writes.
The experiment tests overlay discard (COW rollback), NOT in-place BCD repair.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, qcow2_file_identity, require_unchanged_qcow2,
)
from windows_x64_installed_gpt_ro_audit import inspect_owned_disk

BCD = "/EFI/Microsoft/Boot/BCD"


def require(ok: bool, detail: str) -> None:
    if not ok:
        raise RuntimeError(detail)


def inspect_overlay_bcd(overlay: Path, *, writable: bool) -> str:
    import guestfs

    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.add_drive_opts(str(overlay), readonly=not writable, format="qcow2")
        g.launch()
        require(g.list_devices() == ["/dev/sda"]
                and g.part_get_parttype("/dev/sda") == "gpt"
                and g.blockdev_getsize64("/dev/sda") == VIRTUAL_BYTES,
                "unexpected COW guest disk identity/geometry")
        if writable:
            g.mount("/dev/sda1", "/")
        else:
            g.mount_ro("/dev/sda1", "/")
        require(g.is_file(BCD), "Microsoft BCD absent from overlay ESP")
        digest = g.checksum("sha256", BCD)
        require(len(digest) == 64, "invalid overlay BCD hash")
        if writable:
            # Deliberately damage the BCD registry-hive signature ONLY
            # inside this new COW overlay, never the Windows base image.
            signature = g.pread(BCD, 4, 0)
            require(signature == b"regf", "unexpected BCD header signature")
            written = g.pwrite(BCD, b"BAD!", 0)
            require(written == 4, "short write into overlay-only BCD")
            g.sync()
        g.umount_all()
        return digest
    finally:
        g.close()


def corrupt_and_discard_bcd_overlay(base: Path) -> dict:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT")
            == "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY"
        and os.environ.get("GASLUX_WINDOWS_BCD_OVERLAY_TEST")
            == "I_ACCEPT_BCD_WRITES_TO_NEW_OVERLAY_ONLY"
        and base.name == "only-disposable-windows-target.qcow2"
        and base.parent.parent == Path("/home/runner/work/_temp")
        and base.parent.name.startswith("gaslux-win-x64-")
        and base.parent.is_dir()
        and not base.parent.is_symlink()
        and base.parent.stat().st_uid == os.getuid()
        and stat.S_IMODE(base.parent.stat().st_mode) == 0o700
        and base.is_file() and not base.is_symlink()
        and base.stat().st_uid == os.getuid()
        and base.stat().st_nlink == 1,
        "BCD experiment requires exclusively owned installed Windows CI image",
    )
    baseline_identity = qcow2_file_identity(base)
    expected = inspect_owned_disk(base)
    require(expected["espBcdSha256"] and expected["winreImageSha256"]
            and expected["storageWritesAuthorized"] is False,
            "missing real Windows offline read-only recovery baseline")
    require_unchanged_qcow2(base, baseline_identity)

    with tempfile.TemporaryDirectory(prefix="gaslux-windows-bcd-cow-", dir=base.parent) as t:
        root = Path(t)
        overlay = root / "bcd-only-disposable.qcow2"
        require(not overlay.exists(), "refusing old overlay")
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
             "-b", str(base), str(overlay)],
            check=True, capture_output=True, timeout=45)
        require(overlay.is_file() and not overlay.is_symlink()
                and overlay.parent == root and overlay.stat().st_nlink == 1
                and overlay.stat().st_uid == os.getuid(),
                "BCD overlay escaped private workspace")
        info = json.loads(subprocess.run(
            ["qemu-img", "info", "--output=json", str(overlay)],
            check=True, capture_output=True, text=True, timeout=35).stdout)
        require(info.get("format") == "qcow2"
                and info.get("virtual-size") == VIRTUAL_BYTES
                and info.get("full-backing-filename") == str(base),
                "BCD overlay backing chain does not match owned Windows base")
        require_unchanged_qcow2(base, baseline_identity)
        original_bcd = inspect_overlay_bcd(overlay, writable=False)
        require(original_bcd == expected["espBcdSha256"],
                "overlay BCD did not match Windows base before mutation")
        require_unchanged_qcow2(base, baseline_identity)
        inspect_overlay_bcd(overlay, writable=True)
        require_unchanged_qcow2(base, baseline_identity)
        corrupt_bcd = inspect_overlay_bcd(overlay, writable=False)
        require(corrupt_bcd != original_bcd,
                "actual BCD file mutation in overlay not detected")
        require_unchanged_qcow2(base, baseline_identity)
        # Never boot this intentionally corrupt overlay. Recovery is
        # discarding the overlay, then independently auditing the base.
        overlay.unlink()
        require(not overlay.exists(), "BCD overlay failed to discard")
        require_unchanged_qcow2(base, baseline_identity)
        restored = inspect_owned_disk(base)
        require(restored == expected, "actual Windows EFI/BCD/WinRE backing hashes changed")
        require_unchanged_qcow2(base, baseline_identity)

    print("GASLUX_WINDOWS_OVERLAY_BCD_HIVE_MUTATED_ONLY_IN_COW=1", flush=True)
    print("GASLUX_WINDOWS_OVERLAY_BCD_COW_DISCARD_HASH_RESTORED=1", flush=True)
    print("GASLUX_WINDOWS_INPLACE_BCD_REPAIR_NOT_TESTED=1", flush=True)
    return {
        "bcdActuallyModifiedInsideOverlay": True,
        "overlayDiscardRestoredBaseBcdHash": True,
        "windowsBackingImageUnchanged": True,
        "windowsInPlaceBcdRestorationVerified": False,
        "windowsRebootAfterBcdOverlayDiscardVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only: hosted CI after verified Windows firstboot")
