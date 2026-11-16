#!/usr/bin/env python3
"""VM-only, non-executable Pop!_OS distinst argument preview.

Never an authorization for Windows/shared-disk mutation. Native distinst's
--use PART:fat32 formats FAT; --use PART:reuse does not request formatting.
This preview deliberately pins only a synthetic QEMU virtio disk identity.
"""

from __future__ import annotations

import re

SHA256 = re.compile(r"[a-f0-9]{64}\Z")
RUN = re.compile(r"lab-pop-[a-z0-9-]{8,64}\Z")
KEYS = frozenset(
    {
        "runId",
        "operation",
        "guestOnly",
        "firmwareLayout",
        "targetDiskPath",
        "rootPartitionNumber",
        "espPartitionNumber",
        "rootTransactionOwned",
        "windowsEspPreserved",
        "secureBoot",
        "isoSha256",
        "distinstSha256",
        "windowsBootProofSha256",
    }
)
TARGET = "/dev/disk/by-id/virtio-GASLUXPOPTARGET"


class PopDistinstPlanRefusal(ValueError):
    """Reject unsafe or unverified candidate native installer plans."""


def preview_native_distinst(request: object) -> dict:
    """Return inert arguments. Never run a command, disk writer or mount."""
    if type(request) is not dict or set(request) != KEYS:
        raise PopDistinstPlanRefusal("Unknown or missing candidate plan properties")
    if request["operation"] != "preview-only" or request["guestOnly"] is not True:
        raise PopDistinstPlanRefusal("Only read-only disposable VM previews are allowed")
    if request["firmwareLayout"] != "uefi/gpt":
        raise PopDistinstPlanRefusal("UEFI/GPT only until BIOS and MBR are proven")
    if request["targetDiskPath"] != TARGET:
        raise PopDistinstPlanRefusal("Only the uniquely tagged disposable virtio lab disk")
    if request["rootTransactionOwned"] is not True:
        raise PopDistinstPlanRefusal("Linux root ownership not proven by candidate")
    if request["windowsEspPreserved"] is not True:
        raise PopDistinstPlanRefusal("Cannot preserve Windows ESP")
    if request["secureBoot"] != "disabled":
        raise PopDistinstPlanRefusal("Secure Boot must be disabled and verified")
    if type(request["runId"]) is not str or not RUN.fullmatch(request["runId"]):
        raise PopDistinstPlanRefusal("Unknown disposable run")
    for key in ("isoSha256", "distinstSha256", "windowsBootProofSha256"):
        val = request[key]
        if type(val) is not str or not SHA256.fullmatch(val):
            raise PopDistinstPlanRefusal(f"Missing independently verified {key}")
    root = request["rootPartitionNumber"]
    esp = request["espPartitionNumber"]
    for index in (root, esp):
        if type(index) is not int or not 1 <= index <= 128:
            raise PopDistinstPlanRefusal("Invalid exact partition index")
    if root == esp:
        raise PopDistinstPlanRefusal("Linux root cannot be the Windows ESP")
    if root < 2:
        raise PopDistinstPlanRefusal("Reserved first partition cannot become Linux root")

    # Upstream pop-os/distinst/cli/src/configure/reuse.rs:
    # fs="reuse" does NOT call partition.format_with(...).
    # fs="fat32" DOES call partition.format_with(FileSystem::Fat32).
    esp_arg = f"{TARGET}:{esp}:reuse:mount=/boot/efi"
    linux_arg = f"{TARGET}:{root}:ext4:mount=/"
    args = [
        "/usr/bin/distinst",
        "--squashfs",
        "<verified-pop-squashfs>",
        "--remove",
        "<verified-pop-manifest-remove>",
        "--hostname",
        "gaslux-pop-lab",
        "--keyboard",
        "us",
        "--lang",
        "en_US.UTF-8",
        "--block",
        TARGET,
        "--use",
        esp_arg,
        "--use",
        linux_arg,
        "--no-efi-vars",
    ]
    return {
        "installationAuthorized": False,
        "operation": "preview-only",
        "guestOnly": True,
        "bootloader": "systemd-boot",
        "disposableTargetPath": TARGET,
        "windowsEspReuseRequestedWithoutFormat": True,
        "rootPartitionFormatRequested": True,
        "args": args,
        "requiresIndependentDiskProof": True,
        "requiresVmWriteIsolation": True,
        "requiresFirstBootAndWindowsRecovery": True,
    }
