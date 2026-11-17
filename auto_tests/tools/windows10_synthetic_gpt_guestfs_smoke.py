#!/usr/bin/env python3
"""Synthetic-only 128G sparse QCOW2 GPT/ESP/NTFS fixture for libguestfs.

Writes are ONLY to a fresh host-owned QCOW2 inside the GitHub runner's private
temporary directory. No Windows ISO, Windows guest, host device or network.
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from windows_x64_installed_gpt_ro_audit import (
    BASIC, ESP, MSR, RECOVERY, inspect_owned_disk,
)

MIB = 1024**2
GIB = 1024**3


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def exercise() -> None:
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux" and
            os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux" and
            os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp",
            "refusing synthetic filesystem operation outside GitHub hosted")
    import guestfs

    with tempfile.TemporaryDirectory(
        prefix="gaslux-win-x64-", dir="/home/runner/work/_temp",
    ) as tmp:
        workspace = Path(tmp)
        require(workspace.stat().st_mode & 0o777 == 0o700,
                "temporary Windows mock volume directory must be private")
        disk = workspace / "only-disposable-windows-target.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", str(disk), "128G"],
            check=True, stdout=subprocess.DEVNULL,
        )
        require(disk.is_file() and not disk.is_symlink(),
                "refusing foreign filesystem backing")
        g = guestfs.GuestFS(python_return_dict=True)
        try:
            # Synthetic disk provisioning uses writable guestfs ONLY here.
            # The installed-Windows auditor is a different read-only handle.
            g.add_drive_opts(str(disk), readonly=0, format="qcow2")
            g.launch()
            require(g.list_devices() == ["/dev/sda"], "unexpected guest disk")
            g.part_init("/dev/sda", "gpt")
            sections = [
                (2048, 133119, ESP),
                (133120, 165887, MSR),
                (165888, 1214463, BASIC),
                (1214464, 1476607, RECOVERY),
            ]
            for n, (start, end, kind) in enumerate(sections, 1):
                g.part_add("/dev/sda", "p", start, end)
                g.part_set_gpt_type("/dev/sda", n, kind)
            g.mkfs("vfat", "/dev/sda1")
            g.mkfs("ntfs", "/dev/sda3")
            g.mkfs("ntfs", "/dev/sda4")
            g.mount("/dev/sda1", "/")
            g.mkdir_p("/EFI/Microsoft/Boot")
            g.write("/EFI/Microsoft/Boot/bootmgfw.efi", b"SYNTHETIC_NONWINDOWS_BOOT_MANAGER")
            g.write("/EFI/Microsoft/Boot/BCD", b"SYNTHETIC_NONWINDOWS_BCD")
            g.umount_all()
            g.mount("/dev/sda3", "/")
            g.mkdir_p("/Windows/System32/config")
            g.write("/Windows/System32/winload.efi", b"SYNTHETIC_NONWINDOWS_LOADER")
            g.write("/Windows/System32/config/SYSTEM", b"SYNTHETIC_NONWINDOWS_HIVE")
            g.umount_all()
        finally:
            g.close()
        if os.environ.get("GASLUX_SYNTHETIC_OVERSIZED_WINDOWS_PMBR") == "1":
            # Deliberately reproduce the *known* Microsoft Windows 10 lab PMBR
            # count on this SYNTHETIC private QCOW2 only. Windows/CachyOS
            # PR #131 observed 0xFFFFFFFF on a 128-GiB disk. Preserve every
            # other MBR byte, then prove overlay staging doesn't rewrite it.
            g = guestfs.GuestFS(python_return_dict=True)
            try:
                g.add_drive_opts(str(disk), readonly=0, format="qcow2")
                g.launch()
                require(g.list_devices() == ["/dev/sda"], "unexpected synthetic disk")
                written = g.pwrite_device(
                    "/dev/sda", struct.pack("<I", 0xFFFFFFFF), 446 + 12
                )
                require(written == 4, "synthetic MBR patch was incomplete")
                g.sync()
            finally:
                g.close()
        report = inspect_owned_disk(disk)
        require(report["partitionCount"] == 4 and
                report["espBootManagerPresent"] is True and
                report["espBcdPresent"] is True and
                report["ntfsWindowsLoaderPresent"] is True and
                report["sameDiskDualBootVerified"] is False and
                report["stable"] is False and
                report["storageWritesAuthorized"] is False,
                "synthetic postboot GPT audit did not preserve fail-closed flags")
        if os.environ.get("GASLUX_RUN_SYNTHETIC_POP_OVERLAY_STAGE") == "1":
            from windows10_popos_same_disk_overlay_stage import stage_owned_overlay

            evidence = Path(os.environ["GITHUB_WORKSPACE"]) / "windows-x64-tcg-evidence"
            require(evidence.is_dir() and not evidence.is_symlink(),
                    "owned evidence directory missing")
            proof = stage_owned_overlay(disk, evidence)
            require(
                proof["sameDiskLinuxPartitionCreatedInCOWOverlay"]
                and proof["windowsOfflineGptEspBcdNtfsReconciled"]
                and proof["linuxSystemInstalled"] is False
                and proof["windowsBootAfterPartitionStageVerified"] is False,
                "synthetic COW partition stage unexpectedly claimed boot",
            )
            print("GASLUX_SYNTHETIC_WIN10_POP_COW_GPT_STAGE_PASS=1", flush=True)
        print("GASLUX_SYNTHETIC_WIN10_QCOW2_GPT_READONLY_PASS=1", flush=True)
        print("GASLUX_REAL_WINDOWS_GUEST_BOOT_VERIFIED=0", flush=True)


if __name__ == "__main__":
    exercise()
