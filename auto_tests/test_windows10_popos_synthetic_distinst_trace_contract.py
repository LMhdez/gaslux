#!/usr/bin/env python3
from __future__ import annotations

import copy
import unittest

from tools.windows10_popos_synthetic_distinst_trace_contract import (
    DISK_GUID, DISK_SERIAL, DISK_SIZE, ESP_PARTUUID, ROOT_PARTUUID,
    PINNED_DISTINST_SHA256, synthetic_distinst_plan, classify_distinst_writes,
)
from tools.windows_x64_installed_gpt_ro_audit import DiskAuditError

ARGV = [
    "/usr/bin/distinst",
    "--squashfs",
    "/cdrom/casper_pop-os_24.04_amd64_intel_20/filesystem.squashfs",
    "--remove",
    "/cdrom/casper_pop-os_24.04_amd64_intel_20/filesystem.manifest-remove",
    "--hostname", "gaslux-pop-synth",
    "--block", "/dev/vdc",
    "--use", "/dev/vdc:1:fat32:mount=/boot/efi:flags=esp",
    "--use", "/dev/vdc:2:ext4:mount=/",
    "--no-efi-vars", "--test",
]


def fixtures():
    plan = synthetic_distinst_plan("a" * 64,
                                   "gaslux-pop-synthetic-distinst-child.qcow2")
    guest = {
        "guestVmType": "kvm",
        "diskSerial": DISK_SERIAL,
        "diskGuid": DISK_GUID,
        "diskSizeBytes": DISK_SIZE,
        "logicalSectorBytes": 512,
        "espPartuuid": ESP_PARTUUID,
        "rootPartuuid": ROOT_PARTUUID,
        "targetDevice": "/dev/vdc",
        "gptPrimaryBackupVerified": True,
        "filesystemsAfter": {"1": "vfat", "2": "ext4"},
        "distinstPhase": "partition-format-mount-test",
        "distinstProcess": {
            "pid": 1234,
            "exePath": "/usr/bin/distinst",
            "exeSha256": PINNED_DISTINST_SHA256,
            "argv": list(ARGV),
            "exitCode": 0,
        },
    }
    trace = (
        "virtio_blk_handle_write vdev 0x10 req 0x20 "
        "sector 2048 nsectors 8\n"
        "virtio_blk_handle_write vdev 0x10 req 0x21 "
        "sector 262144 nsectors 8\n"
    )
    tracefs = {
        "available": True,
        "targetMajorMinor": "253:16",
        "blockBioQueue": [
            {"major": 253, "minor": 16, "rwbs": "W", "sector": 2048,
             "count": 8, "comm": "mkfs.fat", "pid": 1235},
            {"major": 253, "minor": 16, "rwbs": "W", "sector": 262144,
             "count": 8, "comm": "mke2fs", "pid": 1236},
        ],
        "blockRqIssue": [
            {"major": 253, "minor": 16, "rwbs": "W", "sector": 2048,
             "count": 8, "comm": "mkfs.fat", "pid": 1235},
            {"major": 253, "minor": 16, "rwbs": "W", "sector": 262144,
             "count": 8, "comm": "mke2fs", "pid": 1236},
        ],
        "execs": [
            {"pid": 1234, "filename": "/usr/bin/distinst"},
            {"pid": 1235, "filename": "/usr/sbin/mkfs.fat"},
            {"pid": 1236, "filename": "/usr/sbin/mke2fs"},
        ],
    }
    return plan, guest, trace, tracefs


def observe(plan=None, guest=None, trace=None, tracefs=None, **overrides):
    p, g, q, t = fixtures()
    result = classify_distinst_writes(
        plan if plan is not None else p,
        trace if trace is not None else q,
        guest if guest is not None else g,
        tracefs if tracefs is not None else t,
        base_sha_after=overrides.get("base_sha_after", "a" * 64),
        nvram_sha_before_distinst=overrides.get("nvram_sha_before_distinst", "b" * 64),
        nvram_sha_after_distinst=overrides.get("nvram_sha_after_distinst", "b" * 64),
        gpt_primary_backup_unchanged=overrides.get("gpt_primary_backup_unchanged", True),
        child_discarded=overrides.get("child_discarded", True),
        qemu_clean_poweroff=overrides.get("qemu_clean_poweroff", True),
    )
    return result


class SyntheticDistinstWriteContractTests(unittest.TestCase):
    def test_two_partition_distinst_writes_correlate_and_never_authorize_windows(self):
        result = observe()
        self.assertTrue(result["distinstProcessIdentityVerified"])
        self.assertTrue(result["distinstChildFormatterExecsObserved"])
        self.assertTrue(result["qemuGuestWriteCoverageCorrelated"])
        self.assertTrue(result["allObservedWritesWithinSyntheticPopPartitions"])
        self.assertEqual(result["partitionWriteEventCounts"], {"1": 1, "2": 1})
        self.assertFalse(result["allWritesObserved"])
        self.assertFalse(result["distinstExecutionAuthorized"])
        self.assertFalse(result["diskWritesAuthorizedForWindows"])
        self.assertFalse(result["windowsEspWritesAuthorized"])
        self.assertFalse(result["productionInstallationAuthorized"])

    def test_gpt_gap_backup_gpt_and_out_of_disk_writes_are_refused(self):
        bad = [
            "virtio_blk_handle_write vdev 0x10 req 0x22 sector 1 nsectors 8\n",
            "virtio_blk_handle_write vdev 0x10 req 0x22 sector 196608 nsectors 8\n",
            f"virtio_blk_handle_write vdev 0x10 req 0x22 sector {DISK_SIZE // 512 - 33} nsectors 8\n",
            f"virtio_blk_handle_write vdev 0x10 req 0x22 sector {DISK_SIZE // 512 - 2} nsectors 8\n",
        ]
        for line in bad:
            with self.subTest(line=line), self.assertRaises(DiskAuditError):
                observe(trace=fixtures()[2] + line)

    def test_discard_write_zeroes_and_unmapped_block_backend_events_are_refused(self):
        for line in (
            "virtio_blk_handle_discard vdev 0x10 sector 2048 nsectors 8\n",
            "virtio_blk_handle_write_zeroes vdev 0x10 sector 2048 nsectors 8\n",
            "blk_co_pwritev blk 0x10 bs 0x20 offset 1048576 bytes 4096 flags 0\n",
        ):
            with self.subTest(line=line), self.assertRaises(DiskAuditError):
                observe(trace=fixtures()[2] + line)

    def test_wrong_disk_serial_guid_partuuid_target_or_elf_is_refused(self):
        for field, value in (
            ("diskSerial", "OTHER-DISK"),
            ("diskGuid", "b" * 36),
            ("espPartuuid", "c" * 36),
            ("rootPartuuid", "d" * 36),
            ("targetDevice", "/dev/vdb"),
        ):
            _, guest, _, _ = fixtures()
            guest[field] = value
            with self.subTest(field=field), self.assertRaises(DiskAuditError):
                observe(guest=guest)
        _, guest, _, _ = fixtures()
        guest["distinstProcess"]["exeSha256"] = "0" * 64
        with self.assertRaises(DiskAuditError):
            observe(guest=guest)

    def test_writer_argv_process_exit_and_child_formatter_identity_are_required(self):
        _, guest, _, tracefs = fixtures()
        guest["distinstProcess"]["argv"].remove("--test")
        with self.assertRaises(DiskAuditError):
            observe(guest=guest)
        _, guest, _, _ = fixtures()
        guest["distinstProcess"]["exitCode"] = 1
        with self.assertRaises(DiskAuditError):
            observe(guest=guest)
        _, guest, _, tracefs = fixtures()
        tracefs["execs"] = tracefs["execs"][:1]
        with self.assertRaises(DiskAuditError):
            observe(tracefs=tracefs)

    def test_guest_tracefs_device_interval_and_qemu_coverage_must_match(self):
        _, _, _, tracefs = fixtures()
        tracefs["targetMajorMinor"] = "253:17"
        with self.assertRaises(DiskAuditError):
            observe(tracefs=tracefs)
        _, _, _, tracefs = fixtures()
        tracefs["blockBioQueue"][0]["sector"] = 1
        with self.assertRaises(DiskAuditError):
            observe(tracefs=tracefs)
        _, _, _, tracefs = fixtures()
        tracefs["blockRqIssue"][0]["count"] = 7
        with self.assertRaises(DiskAuditError):
            observe(tracefs=tracefs)

    def test_missing_tracefs_or_nvram_or_backing_recovery_proof_is_refused(self):
        _, _, _, tracefs = fixtures()
        tracefs["available"] = False
        with self.assertRaises(DiskAuditError):
            observe(tracefs=tracefs)
        with self.assertRaises(DiskAuditError):
            observe(nvram_sha_after_distinst="c" * 64)
        with self.assertRaises(DiskAuditError):
            observe(base_sha_after="c" * 64)
        with self.assertRaises(DiskAuditError):
            observe(child_discarded=False)
        with self.assertRaises(DiskAuditError):
            observe(gpt_primary_backup_unchanged=False)
        with self.assertRaises(DiskAuditError):
            observe(qemu_clean_poweroff=False)

    def test_plan_is_synthetic_and_inert(self):
        plan, _, _, _ = fixtures()
        self.assertFalse(plan["distinstExecutionAuthorized"])
        self.assertFalse(plan["diskWritesAuthorizedForWindows"])
        self.assertFalse(plan["windowsEspWritesAuthorized"])
        self.assertFalse(plan["productionInstallationAuthorized"])


if __name__ == "__main__":
    unittest.main()
