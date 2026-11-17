#!/usr/bin/env python3
"""Read-only Archiso guest preflight of signed Windows-containing GPT COW.

This is a proposed VM-only handoff boundary, NOT an installer or a reliable
hardware-disk identity attestation. It performs no mkfs, pacstrap, mounts,
partition writing, bootloader change or physical-disk operation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
import subprocess
from typing import Any

from cachyos_windows_shared_archiso_handoff import (
    SharedDiskHandoffRejected, SERIAL, SECTOR_BYTES, VIRTUAL_BYTES,
    validate_plan, verify, require,
)
from cachyos_windows_shared_gpt_raw_audit import (
    inspect_bound_gpt_windows, read_guest_disk_windows_readonly,
)


def valid_mountpoints(value: Any) -> bool:
    return value in (None, [], [None], [""])


def validate_lsblk_readonly(plan: dict, observed: Any) -> dict[str, bool]:
    """Bind five observed /sysfs-provided partition GUIDs to signed intent.

    This is a *reported-layout* check, not proof of GPT CRCs, true disk
    provenance, or authorization to use pacstrap. All writes remain denied.
    """
    validate_plan(plan)
    require(type(observed) is dict and set(observed) == {"blockdevices"},
            "unexpected lsblk response")
    disks = observed["blockdevices"]
    require(type(disks) is list and len(disks) >= 1,
            "no disk topology")
    matching = [x for x in disks if type(x) is dict and
                x.get("type") == "disk" and x.get("serial") == SERIAL]
    require(len(matching) == 1, "ambiguous or missing bound QEMU virtio disk")
    disk = matching[0]
    require(type(disk.get("size")) is int and
            disk["size"] == VIRTUAL_BYTES and
            type(disk.get("log-sec")) is int and
            disk["log-sec"] == SECTOR_BYTES and
            isinstance(disk.get("path"), str) and
            disk["path"].startswith("/dev/") and
            not any(c.isspace() for c in disk["path"]),
            "unexpected guest-reported block device geometry")
    children = disk.get("children")
    require(type(children) is list and len(children) == 5,
            "foreign/missing Windows or Linux GPT child partition")
    seen: set[str] = set()
    for number, (planned, actual) in enumerate(zip(plan["partitions"], children), 1):
        require(type(actual) is dict and actual.get("type") == "part",
                "non-partition object on chosen Windows disk")
        require(actual.get("path") == f"{disk['path']}{number}"
                and actual.get("name") == f"{disk['path'][5:]}{number}",
                "guest partition device path differs from selected disk")
        for key in ("partuuid", "parttype", "fstype", "uuid"):
            require(actual.get(key) is None or isinstance(actual[key], str),
                    "malformed observed partition metadata")
        guid = (actual.get("partuuid") or "").lower()
        kind = (actual.get("parttype") or "").lower()
        require(guid == planned["uniqueGuid"]
                and kind == planned["typeGuid"]
                and guid not in seen,
                "guest partition GUID or GPT type differs from signed plan")
        seen.add(guid)
        sectors = planned["lastLba"] - planned["firstLba"] + 1
        require(type(actual.get("start")) is int and
                actual["start"] == planned["firstLba"]
                and type(actual.get("size")) is int
                and actual["size"] == sectors * SECTOR_BYTES,
                "guest partition sector offset/size differs from signed plan")
        require(valid_mountpoints(actual.get("mountpoints")),
                "target Windows or root filesystem mounted before preflight")
    types = [((x.get("fstype") or "").lower()) for x in children]
    require(types[0] in ("vfat", "fat")
            and types[1] in ("", "unknown")
            and types[2] in ("ntfs", "ntfs3")
            and types[3] in ("ntfs", "ntfs3")
            and types[4] == "ext4",
            "unexpected Windows ESP/MSR/NTFS/Recovery or Linux ext4 filesystem")
    require((children[4].get("uuid") or "").lower() == plan["rootFsUuid"],
            "ext4 root filesystem UUID differs from signed transaction")
    return {
        "observedFivePartitionLayoutMatchesSignedPlan": True,
        "guestDiskOriginAuthenticated": False,
        "gptPrimaryAndBackupCrcsIndependentlyVerified": False,
        "windowsEfiBcdWinreContentRestorationVerified": False,
        "pacstrapAuthorized": False,
        "storageWritesAuthorized": False,
        "sameDiskDualBootVerified": False,
        "releaseEligible": False,
    }


def efi_mode_readonly() -> None:
    """Require UEFI no-key OVMF before any guest-mode proof is accepted."""
    path = Path("/sys/firmware/efi/efivars")
    identifier = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
    def flag(name: str) -> int:
        file = path / (name + "-" + identifier)
        require(file.is_file() and not file.is_symlink(),
                "missing trustworthy Secure Boot / Setup Mode flag")
        value = file.read_bytes()
        require(len(value) == 5, "unexpected EFI variable length")
        return value[4]
    require(flag("SecureBoot") == 0 and flag("SetupMode") == 1,
            "active or unverifiable Secure Boot/Setup Mode rejected")


def require_live_archiso() -> None:
    require(os.geteuid() == 0
            and os.environ.get("GASLUX_SHARED_COW_READONLY_CONSENT") ==
                "I_ACCEPT_GITHUB_HOSTED_READONLY_ARCHISO_LAYOUT_ONLY",
            "explicit root and hosted VM read-only consent required")
    detector = subprocess.run(
        ["systemd-detect-virt", "--vm"], check=False, capture_output=True,
        text=True, timeout=10,
    )
    require(detector.returncode == 0
            and detector.stdout.strip() in ("qemu", "kvm"),
            "read-only probe cannot run outside a QEMU/KVM guest")
    release = Path("/etc/os-release")
    require(release.is_file() and not release.is_symlink()
            and Path("/run/archiso").is_dir(),
            "running root is not a genuine live Archiso")
    lines = {}
    for line in release.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        lines[key] = value.strip("'\"")
    require(lines.get("ID") == "cachyos"
            and "arch" in lines.get("ID_LIKE", "").split(),
            "running Archiso is not CachyOS")


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--plan", type=Path, required=True)
    cli.add_argument("--signature", type=Path, required=True)
    cli.add_argument("--public-key", type=Path, required=True)
    cli.add_argument("--expected-run-id", required=True)
    cli.add_argument("--expected-root-uuid", required=True)
    opt = cli.parse_args()
    try:
        require_live_archiso()
        efi_mode_readonly()
        cmdline = Path("/proc/cmdline").read_text(encoding="utf-8")
        signed = verify(
            opt.plan, opt.signature, opt.public_key, cmdline,
            independent_run_id=opt.expected_run_id,
            independent_root_uuid=opt.expected_root_uuid,
        )
        require(signed["pacstrapAuthorized"] is False
                and signed["storageWritesAuthorized"] is False,
                "signed plan claims disk write authorization")
        # After signature verification, load only canonical signed bytes.
        plan = json.loads(opt.plan.read_bytes())
        lsblk = subprocess.run([
            "lsblk", "--json", "--tree", "--bytes",
            "--output", "NAME,TYPE,PATH,SERIAL,SIZE,LOG-SEC,START,PARTTYPE,PARTUUID,FSTYPE,UUID,MOUNTPOINTS",
        ], capture_output=True, text=True, check=False, timeout=15)
        require(lsblk.returncode == 0 and len(lsblk.stdout) < 32768,
                "unable to read bounded block topology from guest")
        disk = json.loads(lsblk.stdout)
        verdict = validate_lsblk_readonly(plan, disk)
        matched = [x for x in disk["blockdevices"] if
                   type(x) is dict and x.get("serial") == SERIAL and
                   x.get("type") == "disk"]
        require(len(matched) == 1,
                "cannot bind a unique guest disk to signed preflight")
        primary, backup = read_guest_disk_windows_readonly(
            Path(matched[0]["path"]))
        raw_gpt = inspect_bound_gpt_windows(primary, backup, plan)
        require(raw_gpt["pacstrapAuthorized"] is False
                and raw_gpt["storageWritesAuthorized"] is False,
                "raw guest GPT inspector claimed storage write authority")
        print(json.dumps({**signed, **verdict, **raw_gpt}, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired) as error:
        print(json.dumps({
            "observedFivePartitionLayoutMatchesSignedPlan": False,
            "pacstrapAuthorized": False, "storageWritesAuthorized": False,
            "releaseEligible": False, "error": str(error)}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
