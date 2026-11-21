"""No-disk fail-closed contracts for Pop native six-GPT write-set.

All partition tables are generated in memory. No disk, QEMU, ISO or installer
is opened. Positive means an inert proposal, NEVER authorization for writing.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).parent / "tools"))

from test_windows10_popos_native_readonly_handoff_candidate import fixtures
from windows_x64_installed_gpt_ro_audit import DiskAuditError
from windows10_popos_native_write_set import (
    _digest, expected_pop_operations, propose_native_write_set,
    check_observed_write_events,
)


def lab_fixture():
    before, after, plan, media, guest = fixtures()
    checkpoint = {
        "schemaVersion": 1,
        "scenario": "genuine_win10_pop_owned_native_child_checkpoint",
        "snapshotOfGenuineWindowsParentSha256": "1" * 64,
        "snapshotOfSixGptWindowsStageSha256": "2" * 64,
        "writerMayUseOnlyPrivateNativeChild": True,
        "authenticatedNativeInstallHandoffVerified": False,
        "distinstExecutionAuthorized": False,
        "rollbackVerified": False,
        "productionInstallationAuthorized": False,
    }
    txid = "e2f23d29-1440-4338-8fe0-f357adae2fa2"
    transaction = {
        "transactionId": txid,
        "handoffSha256": _digest({
            "before": before, "after": after, "plan": plan,
            "media": media, "guest": guest, "checkpoint": checkpoint,
            "transactionId": txid,
        }),
        "handoffSignatureVerified": True,  # synthetic claim, NOT real auth
        "identityGatePassed": True,          # synthetic claim, NOT Safety attestation
        "recoveryCheckpointPrepared": True,  # synthetic claim, NOT rollback
    }
    return [before, after, plan, media, guest, transaction, checkpoint,
            expected_pop_operations(after)]


class PopNativeWriteSetTests(unittest.TestCase):
    def setUp(self):
        self.inputs = lab_fixture()

    def assert_refused(self, inputs):
        with self.assertRaises(DiskAuditError):
            propose_native_write_set(*inputs)

    def test_native_guest_writer_denies_before_any_formatter_or_distinst(self):
        shell = (Path(__file__).parent / "tools" /
                 "windows10_popos_native_realwin10_install_guest.sh").read_text(
                     encoding="utf-8")
        marker = "fail 'GASLUX_POP_NATIVE_WRITESET_UNPROVEN"
        self.assertIn(marker, shell)
        self.assertLess(shell.index(marker), shell.index("mkfs.vfat -F 32"))
        self.assertLess(shell.index(marker),
                        shell.index("timeout --kill-after=15s"))
        self.assertLess(shell.index(marker), shell.index("source_list="))

    def test_positive_inert_write_set_has_exact_owned_ranges_and_exclusions(self):
        p = propose_native_write_set(*self.inputs)
        self.assertEqual(p["identitySource"], "existing-windows10-popos-six-gpt-reconcile")
        self.assertEqual([x["partitionIndex"] for x in p["protectedWindowsResources"]],
                         [1, 2, 3, 4])
        self.assertEqual([x["partitionIndex"] for x in p["ownedOperations"]],
                         [5, 6, 6, 5, 6, 5])
        self.assertEqual(p["bootloader"]["partitionIndex"], 5)
        self.assertFalse(p["bootloader"]["efiVariablesWritable"])
        self.assertFalse(p["bootloader"]["windowsEspWritable"])
        self.assertIn("EFI/Microsoft", p["forbiddenEfiPaths"])
        self.assertIn("disk-commit", p["forbiddenOperations"])
        self.assertFalse(p["diskCommitSideEffectsConfined"])
        self.assertFalse(p["signedHandoffAuthorityEstablished"])
        self.assertFalse(p["distinstExecutionAuthorized"])
        self.assertFalse(p["productionInstallationAuthorized"])
        self.assertNotIn("argv", p)
        self.assertNotIn("command", p)
        self.assertNotIn("execute", p)
        for x in p["ownedOperations"]:
            self.assertEqual(x["offsetBytes"] % 512, 0)
            self.assertEqual(x["lengthBytes"] % 512, 0)
            for w in p["protectedWindowsResources"]:
                self.assertTrue(
                    x["offsetBytes"] + x["lengthBytes"] <= w["offsetBytes"]
                    or x["offsetBytes"] >= w["offsetBytes"] + w["lengthBytes"]
                )

    def test_missing_pop_partition_fails(self):
        args = copy.deepcopy(self.inputs)
        args[1]["popEsp"] = None
        self.assert_refused(args)

    def test_foreign_partuuid_fails(self):
        args = copy.deepcopy(self.inputs)
        args[1]["linuxRoot"]["guid"] = str(uuid.uuid4())
        self.assert_refused(args)

    def test_disk_swap_guid_or_serial_fails(self):
        for field, wrong in [("diskGuid", str(uuid.uuid4())),
                             ("diskSerial", "FOREIGN_DISK")]:
            args = copy.deepcopy(self.inputs)
            args[4][field] = wrong
            self.assert_refused(args)

    def test_wrong_offset_length_or_sector_fails(self):
        for field, delta in [("startLba", 1), ("endLba", -1)]:
            args = copy.deepcopy(self.inputs)
            args[1]["linuxRoot"][field] += delta
            self.assert_refused(args)
        args = copy.deepcopy(self.inputs)
        args[7][0]["offsetBytes"] += 512
        self.assert_refused(args)
        args = copy.deepcopy(self.inputs)
        args[7][0]["lengthBytes"] -= 512
        self.assert_refused(args)

    def test_pop_esp_or_root_existing_filesystem_refused(self):
        for role, field, value in [
            ("esp", "popEspFilesystem", "vfat"),
            ("esp", "popEspFilesystem", "ntfs"),
            ("root", "popRootFilesystem", "ext4"),
            ("root", "popRootFilesystem", "crypto_LUKS"),
            ("root", "popRootFilesystem", "vfat"),
        ]:
            args = copy.deepcopy(self.inputs)
            args[4][field] = value
            with self.subTest(role=role, filesystem=value):
                self.assert_refused(args)

    def test_formatting_windows_esp_refused(self):
        args = copy.deepcopy(self.inputs)
        args[7][0]["partitionIndex"] = 1
        self.assert_refused(args)
        args = copy.deepcopy(self.inputs)
        args[7].append({
            **args[7][0], "partitionIndex": 1,
            "partuuid": args[1]["windowsPartitions"][0]["guid"],
        })
        self.assert_refused(args)

    def test_windows_boot_manager_overwrite_refused(self):
        args = copy.deepcopy(self.inputs)
        args[7][-1]["mount"] = "/boot/efi/EFI/Microsoft"
        self.assert_refused(args)
        args = copy.deepcopy(self.inputs)
        args[2]["windowsBootManagerToRemainUntouched"] = False
        self.assert_refused(args)

    def test_backing_qcow2_changed_or_missing_refused(self):
        for name in ("snapshotOfGenuineWindowsParentSha256",
                     "snapshotOfSixGptWindowsStageSha256"):
            args = copy.deepcopy(self.inputs)
            args[6][name] = "a" * 64
            with self.subTest(name=name):
                self.assert_refused(args)
            args = copy.deepcopy(self.inputs)
            del args[6][name]
            self.assert_refused(args)

    def test_missing_or_untrusted_transaction_refused(self):
        for name, value in [
            ("transactionId", ""),
            ("transactionId", str(uuid.uuid4()).upper()),
            ("handoffSha256", "0" * 64),
            ("handoffSignatureVerified", False),
            ("identityGatePassed", False),
            ("recoveryCheckpointPrepared", False),
        ]:
            args = copy.deepcopy(self.inputs)
            args[5][name] = value
            with self.subTest(field=name):
                self.assert_refused(args)
        args = copy.deepcopy(self.inputs)
        args[5] = {}
        self.assert_refused(args)

    def test_incomplete_or_contradictory_write_set_refused(self):
        for mutation in ("missing_root_format", "duplicate", "wrong_fs",
                         "wrong_mount", "wrong_partuuid", "implicit_disk_commit"):
            args = copy.deepcopy(self.inputs)
            events = args[7]
            if mutation == "missing_root_format":
                events.pop(1)
            elif mutation == "duplicate":
                events.append(copy.deepcopy(events[0]))
            elif mutation == "wrong_fs":
                events[1]["filesystem"] = "ntfs"
            elif mutation == "wrong_mount":
                events[3]["mount"] = "/"
            elif mutation == "wrong_partuuid":
                events[0]["partuuid"] = str(uuid.uuid4())
            else:
                events.append({
                    "operation": "disk-commit", "partitionIndex": 0,
                    "partuuid": "", "offsetBytes": 0,
                    "lengthBytes": 512, "filesystem": None, "mount": None,
                })
            with self.subTest(mutation=mutation):
                self.assert_refused(args)

    def test_offline_trace_checker_refuses_writes_outside_exact_resources(self):
        proposal = propose_native_write_set(*self.inputs)
        proof = check_observed_write_events(proposal, self.inputs[7])
        self.assertTrue(proof["observedEventsMatchProposal"])
        self.assertFalse(proof["distinstExecutionAuthorized"])
        for bad in ([], self.inputs[7][:-1],
                    self.inputs[7] + [{"operation": "disk-commit"}]):
            with self.subTest(n=len(bad)), self.assertRaises(DiskAuditError):
                check_observed_write_events(proposal, bad)


if __name__ == "__main__":
    unittest.main()
