"""No-disk regressions for live Pop GPT probe before any System76 write.

All GPT bytes are synthesized in memory. Tests MUST NOT launch a guest, open
block devices, execute distinst or format partitions.
"""
from __future__ import annotations

import copy
import os
import pathlib
from subprocess import CompletedProcess
import sys
import unittest
import uuid
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).parent / "tools"
sys.path.insert(0, str(TOOLS))

from test_windows10_popos_independent_esp_root_stage import staged_fixture
from windows_x64_installed_gpt_ro_audit import DiskAuditError
from windows10_popos_gpt_mirror_gate import SECTOR, TOTAL_BYTES, WINDOW_BYTES
from windows10_popos_live_readonly_gpt_probe import (
    measure_six_gpt_windows, probe_linux_guest_gpt,
    require_stage_report, _run_readonly,
    _require_unformatted_owned_partition,
)


def fixture():
    _, _, front, back, before, after, plan = staged_fixture()
    report = {
        "independentWindowsPostStageBootVerified": True,
        "windowsGuestPostPairBootAndGptReconciled": True,
        "windowsBackingQcow2Sha256Unchanged": True,
        "ownedPopEspAndRootGptEntriesStagedInCOW": True,
        "popEspFormatted": False,
        "popRootFormatted": False,
        "productionInstallationAuthorized": False,
    }
    calls = []
    def reader(offset: int, count: int) -> bytes:
        calls.append((offset, count))
        if count != WINDOW_BYTES:
            raise AssertionError("unexpected GPT sample read length")
        if offset == 0:
            return front
        if offset == TOTAL_BYTES - WINDOW_BYTES:
            return back
        raise AssertionError("unexpected GPT sample offset")
    return reader, calls, before, after, plan, report, front, back


class WindowsPopLiveGptReadOnlyContracts(unittest.TestCase):
    def test_exact_six_roles_and_crc_with_only_two_bounded_reads(self):
        reader, calls, before, after, plan, report, _, _ = fixture()
        observed = measure_six_gpt_windows(
            reader, TOTAL_BYTES, SECTOR, before, after, plan, report,
        )
        self.assertEqual(
            calls, [(0, WINDOW_BYTES),
                    (TOTAL_BYTES - WINDOW_BYTES, WINDOW_BYTES)],
        )
        self.assertEqual(
            [x["index"] for x in observed["observedPartitionEntries"]],
            [1, 2, 3, 4, 5, 6],
        )
        self.assertEqual(observed["ownedPopEspGuid"], plan["partitions"][0]["uniqueGuid"])
        self.assertEqual(observed["ownedPopRootGuid"], plan["partitions"][1]["uniqueGuid"])
        self.assertTrue(observed["primaryAndBackupGptCrcVerified"])
        for key in ("diskWritePerformed", "hostedGuestIdentityAttested",
                    "authenticatedWindowsToLiveHandoffVerified",
                    "durableRecoveryCheckpointVerified",
                    "distinstExecutionAuthorized",
                    "productionInstallationAuthorized",
                    "sameDiskDualBootVerified", "stable"):
            self.assertIs(observed[key], False)

    def test_missing_or_cancelled_windows_post_stage_proof_rejected_without_read(self):
        _, _, before, after, plan, report, _, _ = fixture()
        for key in sorted(report):
            with self.subTest(field=key):
                bad = dict(report)
                bad[key] = not report[key]
                def must_not_read(_offset, _count):
                    self.fail("GPT read attempted without Windows postboot proof")
                with self.assertRaises(DiskAuditError):
                    measure_six_gpt_windows(
                        must_not_read, TOTAL_BYTES, SECTOR, before,
                        after, plan, bad,
                    )
        with self.assertRaises(DiskAuditError):
            require_stage_report(None)

    def test_refuse_wrong_capacity_or_sector_before_any_disk_read(self):
        reader, calls, before, after, plan, report, _, _ = fixture()
        for capacity, sector in (
            (TOTAL_BYTES - SECTOR, SECTOR),
            (TOTAL_BYTES + SECTOR, SECTOR),
            (TOTAL_BYTES, 4096),
            (TOTAL_BYTES, 0),
        ):
            with self.subTest(capacity=capacity, sector=sector):
                with self.assertRaises(DiskAuditError):
                    measure_six_gpt_windows(
                        reader, capacity, sector, before, after, plan, report,
                    )
        self.assertEqual(calls, [])

    def test_primary_backup_corruption_detected_without_any_write(self):
        _, _, before, after, plan, report, front, back = fixture()
        corruption = [
            (bytes(bytearray(front[:SECTOR]) + b"\0"*0), back),
            (front[:-1], back),
            (front, back[:-1]),
        ]
        damaged = bytearray(front)
        damaged[SECTOR + 72] ^= 1  # GPT header CRC fails
        corruption.append((bytes(damaged), back))
        damaged = bytearray(back)
        damaged[-SECTOR + 56] ^= 1  # backup GPT header CRC fails
        corruption.append((front, bytes(damaged)))
        for f, b in corruption:
            with self.subTest(front_len=len(f), back_len=len(b),
                              fsha=hash(f), bsha=hash(b)):
                with self.assertRaises(DiskAuditError):
                    measure_six_gpt_windows(
                        lambda off, n: f if off == 0 else b,
                        TOTAL_BYTES, SECTOR, before, after, plan, report,
                    )

    def test_refuse_forged_owned_partition_or_original_windows_geometry(self):
        reader, _, before, after, plan, report, _, _ = fixture()
        cases = []
        for field in ("diskGuid", "mbrSha256", "windowsEntryHex"):
            other = copy.deepcopy(after)
            other[field] = (
                str(uuid.uuid4()) if field == "diskGuid"
                else "0"*64 if field == "mbrSha256"
                else ["ff"*128]*4
            )
            cases.append(("after_" + field, before, other, plan))
        mutated = copy.deepcopy(plan)
        mutated["partitions"][0]["uniqueGuid"] = str(uuid.uuid4())
        cases.append(("plan_pop_guid", before, after, mutated))
        for desc, b, a, p in cases:
            with self.subTest(desc=desc), self.assertRaises(DiskAuditError):
                measure_six_gpt_windows(
                    reader, TOTAL_BYTES, SECTOR, b, a, p, report,
                )

    def test_live_entrypoint_refuses_host_and_arbitrary_probe_commands(self):
        reader, _, before, after, plan, report, _, _ = fixture()
        self.assertTrue(callable(reader))
        with patch.dict(os.environ, {"GASLUX_POP_LIVE_GPT_RO_CONSENT": ""},
                        clear=True):
            with self.assertRaises(DiskAuditError):
                probe_linux_guest_gpt(before, after, plan, report, {}, {})
        for argv in (
            ["sh", "-c", "blkid"],
            ["mkfs.ext4", "/dev/vda6"],
            ["lsblk", "-dn", "-o", "SERIAL", "/dev/sda", "extra"],
            ["blkid", "-p", "-s", "TYPE", "-o", "value", "/dev/sda"],
        ):
            with self.subTest(argv=argv), self.assertRaises(DiskAuditError):
                _run_readonly(argv)


    def test_unformatted_blkid_exit_zero_without_type_requires_empty_wipefs(self):
        # Observed on genuine Pop 24.04 live on Windows 10 six-GPT COW:
        # blkid exits 0 with no TYPE on the newly staged unformatted ESP.
        for rc in (0, 2):
            with self.subTest(blkid_rc=rc):
                with patch(
                    "windows10_popos_live_readonly_gpt_probe.subprocess.run",
                    side_effect=[
                        CompletedProcess([], rc, stdout="", stderr=""),
                        CompletedProcess([], 0, stdout='{"signatures": []}', stderr=""),
                    ],
                ) as runner:
                    _require_unformatted_owned_partition(pathlib.Path("/dev/vda5"), 5)
                self.assertEqual(runner.call_count, 2)
                self.assertEqual(
                    runner.call_args_list[0].args[0],
                    ["blkid", "-p", "-s", "TYPE", "-o", "value", "/dev/vda5"],
                )
                self.assertEqual(
                    runner.call_args_list[1].args[0],
                    ["wipefs", "--no-act", "--json", "/dev/vda5"],
                )

    def test_reject_existing_signatures_and_unknown_blkid_results(self):
        invalid_blkid = [
            (0, "vfat\\n", ""),
            (0, "ext4\\n", ""),
            (0, "crypto_LUKS\\n", ""),
            (0, "", "unexpected diagnostic error"),
            (1, "", ""),
            (4, "", ""),
            (2, "vfat\\n", ""),
        ]
        for rc, stdout, stderr in invalid_blkid:
            with self.subTest(rc=rc, stdout=stdout, stderr=stderr):
                with patch(
                    "windows10_popos_live_readonly_gpt_probe.subprocess.run",
                    return_value=CompletedProcess([], rc, stdout=stdout, stderr=stderr),
                ) as runner:
                    with self.assertRaises(DiskAuditError):
                        _require_unformatted_owned_partition(pathlib.Path("/dev/vda6"), 6)
                self.assertEqual(runner.call_count, 1, "wipefs must not mask blkid refusal")

        invalid_wipefs = [
            (0, '{"signatures":[{"type":"vfat","offset":"0x52"}]}', ""),
            (0, '{"signatures":[{"type":"ext4"}]}', ""),
            (0, '{"signatures":[{"type":"crypto_LUKS"}]}', ""),
            (0, '{"other":[]}', ""),
            (0, '{"signatures":[],"unexpected":true}', ""),
            (0, '{malformed', ""),
            (0, "", ""),
            (1, '{"signatures":[]}', ""),
            (0, '{"signatures":[]}', "probe warning"),
        ]
        for rc, stdout, stderr in invalid_wipefs:
            with self.subTest(wipefs_rc=rc, inventory=stdout, stderr=stderr):
                with patch(
                    "windows10_popos_live_readonly_gpt_probe.subprocess.run",
                    side_effect=[
                        CompletedProcess([], 0, stdout="", stderr=""),
                        CompletedProcess([], rc, stdout=stdout, stderr=stderr),
                    ],
                ) as runner:
                    with self.assertRaises(DiskAuditError):
                        _require_unformatted_owned_partition(pathlib.Path("/dev/vda5"), 5)
                self.assertEqual(runner.call_count, 2)

    def test_reject_foreign_partition_path_before_any_subprocess(self):
        for path, index in [
            ("/dev/sda5", 5),
            ("/dev/vda1", 1),
            ("/dev/vda6", 5),
            ("/tmp/vda5", 5),
            ("/dev/vda7", 7),
        ]:
            with self.subTest(path=path, index=index):
                with patch("windows10_popos_live_readonly_gpt_probe.subprocess.run") as runner:
                    with self.assertRaises(DiskAuditError):
                        _require_unformatted_owned_partition(pathlib.Path(path), index)
                    runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
