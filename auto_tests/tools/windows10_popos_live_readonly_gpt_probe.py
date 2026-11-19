#!/usr/bin/env python3
"""Read-only six-entry Windows/Pop GPT measurement for a disposable Linux guest.

This is a PREWRITE DIAGNOSTIC, not an installer or authenticated transaction.
The data source must be the exact QEMU virtio disk's read-only file descriptor;
no /dev/sda, disk enumeration order, shell, format, mount or EFI write is used.
Only supports the 128-GiB/512-byte-sector disposable Windows-10 COW fixture.
"""
from __future__ import annotations

import array
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable

from windows10_popos_gpt_mirror_gate import (
    SECTOR, TOTAL_BYTES, WINDOW_BYTES, parse_windows_pop_gpt,
)
from windows10_popos_independent_esp_root_stage import reconcile_owned_pair
from windows10_popos_native_readonly_handoff_candidate import (
    LAB_VIRTIO_SERIAL, preview_native_handoff,
)
from windows_x64_installed_gpt_ro_audit import DiskAuditError, require

# Linux x86_64 ioctl values, used only after verifying both QEMU provenance
# and the block device bound to the exact 20-character virtio serial.
BLKSSZGET = 0x1268
BLKGETSIZE64 = 0x80081272
VM_ONLY_CONSENT = "I_ACCEPT_DISPOSABLE_GUEST_GPT_READ_ONLY"
VM_DISK_LINK = Path("/dev/disk/by-id/virtio-" + LAB_VIRTIO_SERIAL)
QEMU_BLOCK_RE = re.compile(r"vd[a-z]{1,2}\Z")


def require_stage_report(report: dict) -> None:
    """Prior successful Windows boot alone never authorizes a Linux writer."""
    require(
        type(report) is dict
        and report.get("independentWindowsPostStageBootVerified") is True
        and report.get("windowsGuestPostPairBootAndGptReconciled") is True
        and report.get("windowsBackingQcow2Sha256Unchanged") is True
        and report.get("ownedPopEspAndRootGptEntriesStagedInCOW") is True
        and report.get("popEspFormatted") is False
        and report.get("popRootFormatted") is False
        and report.get("productionInstallationAuthorized") is False,
        "post-pair genuine Windows boot/stage proof missing",
    )


def measure_six_gpt_windows(
    read_at: Callable[[int, int], bytes],
    capacity: int, logical_sector: int,
    before: dict, after: dict, plan: dict,
    stage_report: dict,
) -> dict:
    """Decode only exact bounded primary and backup GPT windows.

    The callback is abstract for synthetic unit tests; the live entrypoint
    below passes only os.pread on an O_RDONLY opened, verified QEMU block FD.
    """
    require(callable(read_at), "no read-only block reader")
    require(type(capacity) is int and capacity == TOTAL_BYTES
            and type(logical_sector) is int and logical_sector == SECTOR,
            "foreign disk size or logical sector geometry",
    )
    require_stage_report(stage_report)
    reconcile_owned_pair(before, after, plan)
    front = read_at(0, WINDOW_BYTES)
    back = read_at(capacity - WINDOW_BYTES, WINDOW_BYTES)
    require(type(front) is bytes and type(back) is bytes
            and len(front) == WINDOW_BYTES and len(back) == WINDOW_BYTES,
            "truncated or inconsistent guest GPT read",
    )
    measured = parse_windows_pop_gpt(front, back, expected_count=6)
    reconcile_owned_pair(before, measured, plan)
    # Compare selected six-entry state with the exact pre-guest stage,
    # not with the device name or a guest-controlled partition listing.
    for field in (
        "diskGuid", "windowsEntryHex", "windowsPartitions", "mbrSha256",
        "popEsp", "linuxRoot", "firstUsableLba", "lastUsableLba",
        "protectiveMbrCanonical", "oversizedWindowsPmbrLabOnly",
    ):
        require(measured[field] == after[field],
                "live guest GPT differs from owned COW: " + field)
    return {
        "schemaVersion": 1,
        "scenario": "windows10_pop_hosted_guest_six_gpt_readonly",
        "diskGuid": measured["diskGuid"],
        "diskSizeBytes": capacity,
        "logicalSectorSize": logical_sector,
        "windowsPartitionEntriesUnchanged": True,
        "ownedPopEspGuid": measured["popEsp"]["guid"],
        "ownedPopRootGuid": measured["linuxRoot"]["guid"],
        "observedPartitionEntries": [
            {
                "index": row["number"],
                "guid": row["guid"],
                "typeGuid": row["type"],
                "firstLba": row["startLba"],
                "lastLba": row["endLba"],
            }
            for row in (measured["windowsPartitions"]
                        + [measured["popEsp"], measured["linuxRoot"]])
        ],
        "primaryAndBackupGptCrcVerified": True,
        "gptPrimaryWindowSha256": hashlib.sha256(front).hexdigest(),
        "gptBackupWindowSha256": hashlib.sha256(back).hexdigest(),
        "diskWritePerformed": False,
        "hostedGuestIdentityAttested": False,
        "authenticatedWindowsToLiveHandoffVerified": False,
        "durableRecoveryCheckpointVerified": False,
        "distinstExecutionAuthorized": False,
        "productionInstallationAuthorized": False,
        "sameDiskDualBootVerified": False,
        "stable": False,
    }


def _run_readonly(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Fixed-argument allowlisted read-only guest diagnostics; no shell."""
    require(
        (len(argv) == 5 and argv[:4] == [
            "lsblk", "-dn", "-o", "SERIAL",
        ]) or
        argv == ["systemd-detect-virt", "--vm"],
        "unexpected guest diagnostic command",
    )
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=10, check=False,
    )


def _test_qemu_readonly_guest_environment() -> None:
    require(
        os.geteuid() == 0
        and os.environ.get("GASLUX_POP_LIVE_GPT_RO_CONSENT") == VM_ONLY_CONSENT
        and Path("/sys/firmware/efi/efivars").is_dir(),
        "not explicitly authorized disposable root UEFI guest",
    )
    detected = _run_readonly(["systemd-detect-virt", "--vm"])
    require(detected.returncode == 0
            and detected.stdout.strip() in ("kvm", "qemu"),
            "read-only probe must run in QEMU/KVM",
    )
    for name, expected in (("SecureBoot", 0), ("SetupMode", 1)):
        path = Path("/sys/firmware/efi/efivars") / (
            name + "-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        )
        require(path.is_file() and not path.is_symlink()
                and len(path.read_bytes()) == 5
                and path.read_bytes()[4] == expected,
                "untrusted virtual UEFI SecureBoot/SetupMode",
        )


def _block_geometry(fd: int) -> tuple[int, int]:
    sector = array.array("I", [0])
    size = array.array("Q", [0])
    fcntl.ioctl(fd, BLKSSZGET, sector, True)
    fcntl.ioctl(fd, BLKGETSIZE64, size, True)
    return size[0], sector[0]


def _probe_unformatted_owned_partitions(
    disk_name: str, partitions: list[dict],
) -> None:
    """No filesystem signatures or mount points on owned parts 5 and 6.

    Windows partitions must also remain unmounted; the Pop guest must not
    inherit a live installer mount of ESP/NTFS with write access.
    """
    mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    mounted = {line.split()[2] for line in mountinfo.splitlines()
               if len(line.split()) >= 3}
    require(
        type(partitions) is list and len(partitions) == 6
        and [p["index"] for p in partitions] == list(range(1, 7)),
        "invalid Linux partition inventory identity",
    )
    sys_block = Path("/sys/class/block")
    actual = {
        p.name for p in sys_block.iterdir()
        if re.fullmatch(re.escape(disk_name) + r"[0-9]+", p.name)
    }
    require(actual == {f"{disk_name}{n}" for n in range(1, 7)},
            "Linux kernel partition count differs from six-GPT plan")
    for index in range(1, 7):
        path = Path("/dev") / f"{disk_name}{index}"
        require(path.exists() and not path.is_symlink()
                and stat.S_ISBLK(path.stat().st_mode),
                "missing or untrusted Windows/Pop partition block device",
        )
        real = os.stat(path)
        sys_part = sys_block / f"{disk_name}{index}"
        row = partitions[index - 1]
        require(
            (sys_part / "partition").read_text().strip() == str(index)
            and int((sys_part / "start").read_text()) == row["firstLba"]
            and int((sys_part / "size").read_text())
            == row["lastLba"] - row["firstLba"] + 1,
            "kernel partition geometry differs from primary/backup GPT",
        )
        require(f"{os.major(real.st_rdev)}:{os.minor(real.st_rdev)}"
                not in mounted,
                "Windows/Pop partition unexpectedly mounted in live guest",
        )
        if index in (5, 6):
            detected = subprocess.run(
                ["blkid", "-p", "-s", "TYPE", "-o", "value", str(path)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            require(detected.returncode == 2
                    and detected.stdout == "",
                    "owned Pop partition %d signature probe refused: "
                    "blkid exit=%d type=%r stderr=%r" % (
                        index, detected.returncode,
                        detected.stdout.strip()[:80],
                        detected.stderr.strip()[:120],
                    ),
            )
    require(not (Path("/dev") / f"{disk_name}7").exists(),
            "unexpected extra seventh partition")


def probe_linux_guest_gpt(
    before: dict, after: dict, plan: dict,
    report: dict, media: dict, guest: dict,
) -> dict:
    """Collect direct guest block GPT evidence, NEVER launch distinst.

    The media and host-provenance booleans remain untrusted caller claims;
    consequently neither this read-only probe nor its JSON results can grant
    write authorization or attest authentication.
    """
    _test_qemu_readonly_guest_environment()
    require(VM_DISK_LINK.is_symlink(), "expected single virtio disk link missing")
    resolved = VM_DISK_LINK.resolve(strict=True)
    require(resolved.parent == Path("/dev")
            and QEMU_BLOCK_RE.fullmatch(resolved.name) is not None
            and resolved.exists() and stat.S_ISBLK(resolved.stat().st_mode),
            "disk is not exact approved QEMU virtio whole block device",
    )
    identity = _run_readonly(["lsblk", "-dn", "-o", "SERIAL", str(resolved)])
    require(identity.returncode == 0
            and identity.stdout.strip() == LAB_VIRTIO_SERIAL,
            "QEMU disk serial disagrees with measured by-id identity",
    )
    fd = os.open(
        str(resolved), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        require(mode == os.O_RDONLY and stat.S_ISBLK(os.fstat(fd).st_mode),
                "guest disk descriptor is not read-only block device",
        )
        capacity, logical_sector = _block_geometry(fd)
        measured = measure_six_gpt_windows(
            lambda offset, n: os.pread(fd, n, offset),
            capacity, logical_sector, before, after, plan, report,
        )
        _probe_unformatted_owned_partitions(
            resolved.name, measured["observedPartitionEntries"],
        )
    finally:
        os.close(fd)
    # Use the already validated candidate; overwrite claims that the guest
    # itself can now measure. Host backing/QEMU provenance remains UNATTESTED.
    observed = dict(guest)
    observed.update({
        "diskSerial": LAB_VIRTIO_SERIAL,
        "diskGuid": measured["diskGuid"],
        "partitionEntries": measured["observedPartitionEntries"],
        "popEspFilesystem": None,
        "popRootFilesystem": None,
        "windowsEspMounted": False,
        "windowsNtfsMounted": False,
        "secureBootEnabled": False,
    })
    candidate = preview_native_handoff(before, after, plan, media, observed)
    require(candidate["distinstExecutionAuthorized"] is False,
            "guest proof must never authorize a native writer")
    return {**measured, "candidate": candidate}
