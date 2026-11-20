#!/usr/bin/env python3
from __future__ import annotations

import copy
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / "tools"))

from tools.windows10_popos_synthetic_distinst_trace_contract import (
    DISK_GUID, DISK_SERIAL, DISK_SIZE, ESP_PARTUUID, ROOT_PARTUUID,
    PINNED_DISTINST_SHA256, ROOT_START, synthetic_distinst_plan,
    classify_distinst_writes, diagnose_qemu_write_set,
)
from windows_x64_installed_gpt_ro_audit import DiskAuditError

ARGV = [
    "/usr/bin/distinst",
    "--squashfs",
    "/cdrom/casper_pop-os_24.04_amd64_intel_20/filesystem.squashfs",
    "--remove",
    "/cdrom/casper_pop-os_24.04_amd64_intel_20/filesystem.manifest-remove",
    "--hostname", "gaslux-pop-synth",
    "--block", "/dev/vdc",
    "--use", "/dev/vdc:1:reuse:mount=/boot/efi",
    "--use", "/dev/vdc:2:reuse:mount=/",
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
        "distinstPhase": "partition-reuse-test",
        "syntheticPreformat": {
            "onlySyntheticOwnedPartitions": True,
            "performedBeforeDistinst": True,
            "gptByteIdentical": True,
            "filesystemsBefore": {"1": None, "2": None},
            "filesystemsAfter": {"1": "vfat", "2": "ext4"},
            "formatterCommands": [
                ["mkfs.fat", "-F", "32", "-n", "POPSYN", "/dev/vdc1"],
                ["mkfs.ext4", "-F", "-q", "/dev/vdc2"],
            ],
            "gptRegionHashesBefore": {"pmbrAndPrimary": "c" * 64,
                                      "secondary": "d" * 64},
            "gptRegionHashesAfter": {"pmbrAndPrimary": "c" * 64,
                                     "secondary": "d" * 64},
        },
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
        f"sector {ROOT_START} nsectors 8\n"
    )
    tracefs = {
        "available": True,
        "targetMajorMinor": "253:16",
        "blockBioQueue": [
            {"major": 253, "minor": 16, "rwbs": "W", "sector": 2048,
             "count": 8, "comm": "mkfs.fat", "pid": 1235},
            {"major": 253, "minor": 16, "rwbs": "W", "sector": ROOT_START,
             "count": 8, "comm": "mke2fs", "pid": 1236},
        ],
        "blockBioComplete": [
            {"major": 253, "minor": 16, "rwbs": "W", "sector": 2048,
             "count": 8, "comm": "kworker/0:0", "pid": 1240, "ioError": 0},
            {"major": 253, "minor": 16, "rwbs": "W", "sector": ROOT_START,
             "count": 8, "comm": "kworker/0:0", "pid": 1240, "ioError": 0},
        ],
        "blockRqIssue": [
            {"major": 253, "minor": 16, "rwbs": "W", "sector": 2048,
             "count": 8, "comm": "mkfs.fat", "pid": 1235},
            {"major": 253, "minor": 16, "rwbs": "W", "sector": ROOT_START,
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
        self.assertFalse(result["distinstChildFormatterExecsObserved"])
        self.assertTrue(result["syntheticPreformatFormatterExecsObserved"])
        self.assertTrue(result["distinstReuseModeObserved"])
        self.assertTrue(result["qemuGuestWriteCoverageCorrelated"])
        self.assertTrue(result["guestCompletedBioSuccessVerified"])
        self.assertTrue(result["allObservedWritesWithinSyntheticPopPartitions"])
        self.assertEqual(result["partitionWriteEventCounts"], {"1": 1, "2": 1})
        self.assertFalse(result["allWritesObserved"])
        self.assertFalse(result["distinstExecutionAuthorized"])
        self.assertFalse(result["diskWritesAuthorizedForWindows"])
        self.assertFalse(result["windowsEspWritesAuthorized"])
        self.assertFalse(result["productionInstallationAuthorized"])

    def test_reuse_preformat_attestation_is_fail_closed(self):
        for mutation in (
            lambda g: g.pop("syntheticPreformat"),
            lambda g: g["syntheticPreformat"].update(gptByteIdentical=False),
            lambda g: g["syntheticPreformat"]["gptRegionHashesAfter"].update(
                secondary="e" * 64),
            lambda g: g["syntheticPreformat"].update(
                formatterCommands=[["mkfs.fat", "-F", "32", "/dev/vda1"]]),
            lambda g: g["syntheticPreformat"].update(
                filesystemsAfter={"1": "ntfs", "2": "ext4"}),
        ):
            _, guest, _, _ = fixtures()
            mutation(guest)
            with self.subTest(mutation=str(mutation)), self.assertRaises(DiskAuditError):
                observe(guest=guest)

    def test_old_formatting_cli_and_relabelled_partition_are_refused(self):
        _, guest, _, _ = fixtures()
        argv = guest["distinstProcess"]["argv"]
        argv[argv.index("/dev/vdc:1:reuse:mount=/boot/efi")] = (
            "/dev/vdc:1:fat32:mount=/boot/efi:flags=esp")
        with self.assertRaises(DiskAuditError):
            observe(guest=guest)
        _, guest, _, _ = fixtures()
        guest["rootPartuuid"] = "00000000-0000-0000-0000-000000000000"
        with self.assertRaises(DiskAuditError):
            observe(guest=guest)

    def test_gpt_gap_backup_gpt_and_out_of_disk_writes_are_refused(self):
        bad = [
            "virtio_blk_handle_write vdev 0x10 req 0x22 sector 1 nsectors 8\n",
            "virtio_blk_handle_write vdev 0x10 req 0x22 sector 1050624 nsectors 8\n",
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
        _, _, _, tracefs = fixtures()
        tracefs["blockBioComplete"][0]["count"] = 7
        with self.assertRaises(DiskAuditError):
            observe(tracefs=tracefs)

    def test_flush_does_not_count_as_sector_write_but_bad_events_are_refused(self):
        _, _, _, tracefs = fixtures()
        flush = {"major": 253, "minor": 16, "rwbs": "FWS",
                 "sector": 0, "count": 0, "comm": "distinst", "pid": 1234}
        tracefs["blockBioQueue"].append(dict(flush))
        tracefs["blockBioComplete"].append(dict(flush, ioError=0))
        result = observe(tracefs=tracefs)
        self.assertTrue(result["qemuGuestWriteCoverageCorrelated"])
        for mutation in (
            {"rwbs": "WS", "count": 0},
            {"rwbs": "FWS", "sector": 1},
            {"rwbs": "D", "sector": 2048, "count": 8},
            {"rwbs": "Z", "sector": 2048, "count": 8},
        ):
            _, _, _, bad = fixtures()
            bad["blockBioQueue"].append(dict(flush, **mutation))
            with self.subTest(mutation=mutation), self.assertRaises(DiskAuditError):
                observe(tracefs=bad)

    def test_failed_or_missing_completed_bio_is_refused(self):
        for mutation in (
            lambda t: t.pop("blockBioComplete"),
            lambda t: t.update(blockBioComplete=[]),
            lambda t: t["blockBioComplete"][0].update(ioError=-5),
            lambda t: t["blockBioComplete"][0].pop("ioError"),
            lambda t: t["blockBioComplete"][0].update(sector=1),
        ):
            _, _, _, t = fixtures()
            mutation(t)
            with self.subTest(mutation=str(mutation)), self.assertRaises(DiskAuditError):
                observe(tracefs=t)

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

    def test_qemu_readonly_is_a_drive_backend_property_not_device_property(self):
        source = (Path(__file__).parent / "tools" /
                  "windows10_popos_synthetic_qemu_write_smoke.py").read_text(
                      encoding="utf-8")
        device_args = re.findall(r'"-device",\s*f?"([^"]+)"', source)
        self.assertGreaterEqual(len(device_args), 5)
        self.assertTrue(all("readonly=" not in arg for arg in device_args))
        self.assertIn('"-nodefaults"', source)
        self.assertNotIn('"-no-shutdown"', source)
        self.assertIn('if=none,id=distcontrol,format=raw,readonly=on,file={control}',
                      source)
        self.assertIn('if=none,id=popiso,format=raw,readonly=on,file={iso}',
                      source)
        self.assertIn('drive=syntarget,serial={DISTINST_SERIAL},bootindex=3,discard=off,write-zeroes=off',
                      source)

    def test_qemu_trace_diagnostic_refuses_primary_and_backup_gpt_writes_against_pr232(self):
        plan, guest, trace, tracefs = fixtures()
        guest["tracefs"] = tracefs
        guest["distinstProcess"]["packageVersion"] = (
            "0.3.2~1758837686~24.04~e395b7c")
        guest["distinstProcess"]["sourceRevisionHint"] = "e395b7c"
        gpt_writes = (
            "virtio_blk_handle_write vdev 0x10 req 0x30 sector 0 nsectors 40\n"
            f"virtio_blk_handle_write vdev 0x10 req 0x31 sector "
            f"{DISK_SIZE // 512 - 40} nsectors 40\n"
        )
        result = diagnose_qemu_write_set(plan, trace + gpt_writes, guest)
        self.assertFalse(result["writeSetMatch"])
        self.assertEqual(result["decision"], "REFUSE_OUT_OF_WRITESET")
        self.assertEqual(result["qemuWriteEventCount"], 4)
        self.assertEqual(result["outOfSetEventCount"], 2)
        self.assertEqual(set(result["outOfSetRegions"]),
                         {"primary-mbr-gpt", "backup-gpt"})
        projection = result["pr232Projection"]
        self.assertEqual(len(projection["expectedOperations"]), 6)
        self.assertEqual(len(projection["partitionPhaseOperations"]), 4)
        self.assertEqual(len(projection["notReachedByDistinstTest"]), 2)
        self.assertTrue(projection["espFormatObserved"])
        self.assertTrue(projection["rootFormatObserved"])
        self.assertFalse(projection["mountSyscallsIndependentlyObserved"])
        self.assertFalse(projection["upstreamMountAllTargetsReached"])
        self.assertFalse(projection["mountSyscallsIndependentlyObserved"])
        self.assertFalse(projection["mountSyscallTargetsResolved"])
        self.assertTrue(projection["upstreamCandidateSequenceCallsMountAllTargetsBeforeTestReturn"])
        self.assertFalse(result["distinstExecutionAuthorized"])
        self.assertFalse(result["diskWritesAuthorizedForWindows"])
        self.assertFalse(result["windowsEspWritesAuthorized"])

    def test_qemu_trace_diagnostic_accepts_only_precreated_partition_ranges(self):
        plan, guest, trace, tracefs = fixtures()
        guest["tracefs"] = tracefs
        result = diagnose_qemu_write_set(plan, trace, guest)
        self.assertTrue(result["writeSetMatch"])
        self.assertEqual(result["decision"], "MATCH_SYNTHETIC_PARTITION_WRITESET")
        self.assertEqual(result["outOfSetEventCount"], 0)
        self.assertEqual(result["writesBySyntheticPartition"][1]["eventCount"], 1)
        self.assertEqual(result["writesBySyntheticPartition"][2]["eventCount"], 1)

    def test_missing_rq_issue_requires_independent_completed_bio_witness(self):
        plan, guest, trace, tracefs = fixtures()
        tracefs["blockRqIssue"] = []
        guest["tracefs"] = tracefs
        result = diagnose_qemu_write_set(plan, trace, guest)
        self.assertTrue(result["writeSetMatch"])
        self.assertTrue(result["observationComplete"])
        self.assertTrue(result["guestTracefsBioQueueCorroboratesQemu"])
        self.assertTrue(result["guestTracefsBioCompleteCorroboratesQemu"])
        self.assertFalse(result["guestTracefsRqIssueCorroboratesQemu"])
        self.assertFalse(result["guestRqIssueWitnessAvailable"])
        self.assertTrue(result["guestTracefsCorroboratesQemu"])
        self.assertEqual(result["decision"], "MATCH_SYNTHETIC_PARTITION_WRITESET")
        self.assertFalse(result["distinstExecutionAuthorized"])

    def test_missing_completed_bio_is_incomplete_not_approved(self):
        plan, guest, trace, tracefs = fixtures()
        tracefs["blockRqIssue"] = []
        tracefs["blockBioComplete"] = []
        guest["tracefs"] = tracefs
        result = diagnose_qemu_write_set(plan, trace, guest)
        self.assertFalse(result["observationComplete"])
        self.assertFalse(result["guestTracefsBioCompleteCorroboratesQemu"])
        self.assertEqual(result["decision"], "REFUSE_INCOMPLETE_OBSERVATION")
        self.assertFalse(result["distinstExecutionAuthorized"])

    def test_mount_syscall_evidence_is_separate_from_upstream_source_hint(self):
        plan, guest, trace, tracefs = fixtures()
        guest["tracefs"] = tracefs
        guest["distinstProcess"]["sourceRevisionHint"] = "e395b7c"
        guest["mountObservations"] = {
            "distinstProcessEventCount": 2,
            "successfulMountExitCount": 1,
            "targetArgumentsResolved": False,
        }
        result = diagnose_qemu_write_set(plan, trace, guest)
        projection = result["pr232Projection"]
        self.assertTrue(projection["mountSyscallsIndependentlyObserved"])
        self.assertFalse(projection["mountSyscallTargetsResolved"])
        self.assertFalse(projection["upstreamMountAllTargetsReached"])
        self.assertTrue(
            projection["upstreamCandidateSequenceCallsMountAllTargetsBeforeTestReturn"]
        )
        self.assertEqual(result["guestMountSyscallEventCount"], 2)
        self.assertEqual(result["guestMountSyscallSuccessfulExitCount"], 1)

    def test_qemu_trace_diagnostic_rejects_unparseable_or_missing_write_events(self):
        plan, guest, _, _ = fixtures()
        with self.assertRaises(DiskAuditError):
            diagnose_qemu_write_set(
                plan, "virtio_blk_handle_write malformed\n", guest)
        with self.assertRaises(DiskAuditError):
            diagnose_qemu_write_set(plan, "pflash_data_write system.flash1\n", guest)

    def test_plan_is_synthetic_and_inert(self):
        plan, _, _, _ = fixtures()
        self.assertFalse(plan["distinstExecutionAuthorized"])
        self.assertFalse(plan["diskWritesAuthorizedForWindows"])
        self.assertFalse(plan["windowsEspWritesAuthorized"])
        self.assertFalse(plan["productionInstallationAuthorized"])


if __name__ == "__main__":
    unittest.main()
