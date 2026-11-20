#!/usr/bin/env python3
"""Fail-closed write-set observer for Pop distinst on a synthetic-only QEMU disk.

QEMU host trace is the independent block-write source. Guest tracefs supplies
process attribution; neither source grants Windows or production writer access.
"""
from __future__ import annotations

import hashlib
import re

from windows_x64_installed_gpt_ro_audit import DiskAuditError, require

SECTOR = 512
DISK_SIZE = 8 * 1024**3
DISK_SECTORS = DISK_SIZE // SECTOR
DISK_GUID = "7d6e5c4b-3a29-4876-9abc-def012345678"
DISK_SERIAL = "GASLUX_POP_DIST"
ESP_PARTUUID = "1a2b3c4d-5e6f-4789-8abc-def012345678"
ROOT_PARTUUID = "2b3c4d5e-6f70-489a-bcde-f0123456789a"
ESP_START = 2048
ESP_COUNT = 1_048_576
ROOT_START = 1_052_672
ROOT_COUNT = 8 * 1024 * 1024
PINNED_DISTINST_SHA256 = (
    "8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5"
)
SHA = re.compile(r"[a-f0-9]{64}\Z")
GUID = re.compile(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\Z")
QEMU_WRITE = re.compile(
    r"\bvirtio_blk_handle_write\b.*\bsector\s+(?P<sector>\d+)"
    r"\s+nsectors\s+(?P<count>\d+)"
)
UNSUPPORTED_WRITE = re.compile(
    r"\b(?:virtio_blk_handle_discard|virtio_blk_handle_write_zeroes|"
    r"blk_co_pwritev|bdrv_co_pwritev|bdrv_co_pwrite_zeroes)\b"
)


def synthetic_distinst_plan(base_sha256: str, child_name: str) -> dict:
    """Describe only two pre-created partitions on an entirely synthetic disk."""
    require(type(base_sha256) is str and SHA.fullmatch(base_sha256) is not None
            and child_name == "gaslux-pop-synthetic-distinst-child.qcow2",
            "synthetic distinst backing identity missing")
    return {
        "schemaVersion": 1,
        "scenario": "pop-synthetic-distinst-partition-test",
        "disk": {
            "guid": DISK_GUID,
            "serial": DISK_SERIAL,
            "sizeBytes": DISK_SIZE,
            "logicalSectorBytes": SECTOR,
            "partitionStyle": "GPT",
        },
        "backing": {"baseSha256": base_sha256, "childName": child_name},
        "partitions": [
            {
                "number": 1, "partuuid": ESP_PARTUUID,
                "startLba": ESP_START, "sectorCount": ESP_COUNT,
                "filesystem": "fat32", "mount": "/boot/efi",
                "allowedOperations": ["format", "mount"],
            },
            {
                "number": 2, "partuuid": ROOT_PARTUUID,
                "startLba": ROOT_START, "sectorCount": ROOT_COUNT,
                "filesystem": "ext4", "mount": "/",
                "allowedOperations": ["format", "mount"],
            },
        ],
        "expectedDistinstPhase": "partition-format-mount-test",
        "distinstExecutionAuthorized": False,
        "diskWritesAuthorizedForWindows": False,
        "windowsEspWritesAuthorized": False,
        "productionInstallationAuthorized": False,
    }


def _flag_value(argv: list[str], flag: str) -> str:
    require(argv.count(flag) == 1 and argv.index(flag) + 1 < len(argv),
            "distinst argv missing or duplicates " + flag)
    return argv[argv.index(flag) + 1]


def _validate_identity(plan: dict, guest: dict) -> None:
    require(type(guest) is dict
            and guest.get("guestVmType") in ("qemu", "kvm")
            and guest.get("diskSerial") == DISK_SERIAL
            and guest.get("diskGuid") == DISK_GUID
            and guest.get("diskSizeBytes") == DISK_SIZE
            and guest.get("logicalSectorBytes") == SECTOR
            and guest.get("espPartuuid") == ESP_PARTUUID
            and guest.get("rootPartuuid") == ROOT_PARTUUID
            and guest.get("targetDevice") == "/dev/vdc",
            "synthetic target serial/GUID/geometry/PARTUUID mismatch")
    process = guest.get("distinstProcess")
    require(type(process) is dict
            and type(process.get("pid")) is int and process["pid"] > 1
            and process.get("exePath") == "/usr/bin/distinst"
            and process.get("exeSha256") == PINNED_DISTINST_SHA256
            and process.get("exitCode") == 0
            and type(process.get("argv")) is list
            and all(type(x) is str for x in process["argv"]),
            "authentic distinst process identity/exit evidence missing")
    argv = process["argv"]
    require(argv and argv[0] == "/usr/bin/distinst"
            and "--test" in argv and "--no-efi-vars" in argv
            and "--modify-boot" not in argv and "--new-table" not in argv
            and "--new" not in argv and "--delete" not in argv
            and "--move" not in argv
            and _flag_value(argv, "--block") == "/dev/vdc"
            and _flag_value(argv, "--hostname") == "gaslux-pop-synth"
            and _flag_value(argv, "--squashfs").startswith("/cdrom/")
            and _flag_value(argv, "--squashfs").endswith("filesystem.squashfs")
            and _flag_value(argv, "--remove").startswith("/cdrom/")
            and _flag_value(argv, "--remove").endswith("filesystem.manifest-remove"),
            "distinst argv contains a writer mode or foreign target")
    uses = [argv[i + 1] for i, value in enumerate(argv[:-1]) if value == "--use"]
    require(uses == [
        "/dev/vdc:1:fat32:mount=/boot/efi:flags=esp",
        "/dev/vdc:2:ext4:mount=/",
    ], "distinst --use list is incomplete, reordered or targets another disk")
    require(guest.get("gptPrimaryBackupVerified") is True
            and guest.get("filesystemsAfter") == {"1": "vfat", "2": "ext4"}
            and guest.get("distinstPhase") == "partition-format-mount-test",
            "post-distinst GPT/filesystem/phase witness missing")


def _intervals(items: list[dict], *, source: str) -> list[tuple[int, int]]:
    out = []
    for item in items:
        require(type(item) is dict and item.get("major") is not None
                and item.get("minor") is not None
                and type(item.get("sector")) is int
                and type(item.get("count")) is int
                and item["count"] > 0
                and type(item.get("pid")) is int and item["pid"] > 1
                and type(item.get("comm")) is str and item["comm"]
                and type(item.get("rwbs")) is str
                and "W" in item["rwbs"]
                and not any(flag in item["rwbs"] for flag in ("D", "Z")),
                source + " contains incomplete/non-write/discard event")
        start = item["sector"]
        end = start + item["count"]
        require(0 <= start < end <= DISK_SECTORS,
                source + " sector interval outside synthetic disk")
        out.append((start, end))
    require(out, source + " contains no target write events")
    return out


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result: list[list[int]] = []
    for start, end in sorted(intervals):
        if result and start <= result[-1][1]:
            result[-1][1] = max(result[-1][1], end)
        else:
            result.append([start, end])
    return [(a, b) for a, b in result]


def _same_coverage(left: list[tuple[int, int]],
                   right: list[tuple[int, int]]) -> bool:
    return _merge(left) == _merge(right)


def classify_distinst_writes(
    plan: dict,
    qemu_trace: str,
    guest: dict,
    tracefs: dict,
    *,
    base_sha_after: str,
    nvram_sha_before_distinst: str,
    nvram_sha_after_distinst: str,
    gpt_primary_backup_unchanged: bool,
    child_discarded: bool,
    qemu_clean_poweroff: bool,
) -> dict:
    """Correlate QEMU block writes with guest tracefs and confine to two partitions.

    This is observational evidence only. It never authorizes a Windows writer.
    """
    require(type(plan) is dict and plan.get("schemaVersion") == 1
            and plan.get("scenario") == "pop-synthetic-distinst-partition-test"
            and plan.get("distinstExecutionAuthorized") is False
            and plan.get("diskWritesAuthorizedForWindows") is False
            and plan.get("windowsEspWritesAuthorized") is False
            and plan.get("productionInstallationAuthorized") is False,
            "synthetic distinst plan missing or contradictory")
    require(type(qemu_trace) is str and 0 < len(qemu_trace) <= 16_000_000,
            "QEMU trace missing or oversized")
    require(type(base_sha_after) is str
            and base_sha_after == plan["backing"]["baseSha256"]
            and type(nvram_sha_before_distinst) is str
            and SHA.fullmatch(nvram_sha_before_distinst) is not None
            and type(nvram_sha_after_distinst) is str
            and nvram_sha_before_distinst == nvram_sha_after_distinst
            and gpt_primary_backup_unchanged is True
            and child_discarded is True and qemu_clean_poweroff is True,
            "backing/GPT/NVRAM/child/shutdown checkpoint mismatch")
    _validate_identity(plan, guest)

    qemu_intervals = []
    qemu_events = []
    for line in qemu_trace.splitlines():
        require(UNSUPPORTED_WRITE.search(line) is None,
                "QEMU trace contains discard/write-zeroes/unmapped block event")
        if not QEMU_WRITE.search(line):
            continue
        match = QEMU_WRITE.search(line)
        sector, count = int(match["sector"]), int(match["count"])
        require(count > 0 and count <= DISK_SECTORS
                and 0 <= sector < DISK_SECTORS
                and sector + count <= DISK_SECTORS,
                "QEMU write interval outside synthetic disk")
        end = sector + count
        partition = next((p for p in plan["partitions"]
                          if p["startLba"] <= sector
                          and end <= p["startLba"] + p["sectorCount"]), None)
        require(partition is not None,
                "QEMU write touches GPT, unallocated space or outside Pop partitions")
        qemu_intervals.append((sector, end))
        qemu_events.append({
            "partitionIndex": partition["number"],
            "partuuid": partition["partuuid"],
            "filesystem": partition["filesystem"],
            "sector": sector,
            "sectorCount": count,
            "offsetBytes": sector * SECTOR,
            "lengthBytes": count * SECTOR,
            "source": "external-qemu-virtio-blk-trace",
        })
    require(qemu_events, "QEMU trace contains no actual distinst target writes")
    for partition in plan["partitions"]:
        require(any(item["partitionIndex"] == partition["number"]
                    for item in qemu_events),
                "distinst did not produce observed writes to partition "
                + str(partition["number"]))

    require(type(tracefs) is dict and tracefs.get("available") is True
            and type(tracefs.get("targetMajorMinor")) is str
            and re.fullmatch(r"\d+:\d+", tracefs["targetMajorMinor"]) is not None
            and type(tracefs.get("blockBioQueue")) is list
            and type(tracefs.get("blockRqIssue")) is list
            and type(tracefs.get("execs")) is list,
            "guest block tracefs/process witness unavailable")
    major, minor = (int(x) for x in tracefs["targetMajorMinor"].split(":"))
    bio = tracefs["blockBioQueue"]
    rq = tracefs["blockRqIssue"]
    for event in bio + rq:
        require(event.get("major") == major and event.get("minor") == minor,
                "guest tracefs event belongs to a different block device")
    bio_intervals = _intervals(bio, source="block_bio_queue")
    rq_intervals = _intervals(rq, source="block_rq_issue")
    require(_same_coverage(qemu_intervals, bio_intervals)
            and _same_coverage(qemu_intervals, rq_intervals),
            "independent QEMU and guest tracefs write intervals diverge")
    for start, end in bio_intervals + rq_intervals:
        require(any(p["startLba"] <= start
                    and end <= p["startLba"] + p["sectorCount"]
                    for p in plan["partitions"]),
                "guest tracefs write escapes allowed ESP/root partition ranges")

    process = guest["distinstProcess"]
    execs = tracefs["execs"]
    require(any(x.get("pid") == process["pid"]
                and x.get("filename") == "/usr/bin/distinst" for x in execs),
            "tracefs did not independently observe the pinned distinst exec")
    child_tools = {
        str(x.get("filename", "")).rsplit("/", 1)[-1]
        for x in execs if type(x) is dict
    }
    require(any(name in child_tools for name in ("mkfs.fat", "mkfs.vfat"))
            and any(name in child_tools for name in ("mkfs.ext4", "mke2fs")),
            "tracefs did not observe both FAT32 and ext4 formatter processes")

    return {
        "schemaVersion": 1,
        "scenario": plan["scenario"],
        "distinstElfSha256": PINNED_DISTINST_SHA256,
        "distinstProcessPid": process["pid"],
        "distinstProcessIdentityVerified": True,
        "distinstChildFormatterExecsObserved": True,
        "qemuWriteEventCount": len(qemu_events),
        "qemuWriteBytes": sum(x["lengthBytes"] for x in qemu_events),
        "guestBlockBioQueueEventCount": len(bio),
        "guestBlockRqIssueEventCount": len(rq),
        "qemuGuestWriteCoverageCorrelated": True,
        "partitionWriteEventCounts": {
            str(p["number"]): sum(1 for x in qemu_events
                                  if x["partitionIndex"] == p["number"])
            for p in plan["partitions"]
        },
        "allObservedWritesWithinSyntheticPopPartitions": True,
        "gptPrimaryBackupUnchanged": True,
        "nvramPersistentStateUnchangedDuringDistinst": True,
        "nvramTransientWritesProvenAbsent": False,
        "baseImageUnchanged": True,
        "privateChildDiscarded": True,
        "qemuCleanPoweroff": True,
        "allWritesObserved": False,
        "unobservedClasses": [
            "transient NVRAM changes restored before final hash",
            "guest userspace syscalls outside tracefs event coverage",
        ],
        "distinstExecutionAuthorized": False,
        "diskWritesAuthorizedForWindows": False,
        "windowsEspWritesAuthorized": False,
        "productionInstallationAuthorized": False,
        "rollbackAfterNativeInstallVerified": False,
    }
