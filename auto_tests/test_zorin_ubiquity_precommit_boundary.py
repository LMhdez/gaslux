"""Adversarial tests: there is no proven Ubiquity pre-commit writer fence.

Builds only a private, sparse synthetic GPT regular file. The shared #333
handoff and Safety #307 GPT inspector are exercised, not reimplemented.
"""
from __future__ import annotations

from dataclasses import asdict
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

from test_zorin_ubiquity_handoff_readonly import (
    SECTOR,
    make_proposal,
    make_shared_plan,
    write_synthetic_gpt,
)
from libertix_disk_identity_gate import inspect_gpt_fd
from zorin_ubiquity_handoff_readonly import (
    PINNED_CODE_MAP_SHA,
    UBIQUITY_EXEC_SHA,
    UbiquityHandoffDenied,
)
from zorin_ubiquity_precommit_boundary import (
    PRECOMMIT_UNAVAILABLE,
    classify_zorin_precommit,
    validate_static_code_map,
)


def untrusted_observation(proposal: dict, plan: dict) -> dict:
    return {
        "planId": plan["planId"],
        "transactionId": plan["runtime"]["recoveryRunId"],
        "installerExecutableSha256": UBIQUITY_EXEC_SHA,
        "codeMapSha256": PINNED_CODE_MAP_SHA,
        "selectedDiskUniqueId": proposal["destination"]["diskUniqueId"],
        "commitDiskUniqueId": proposal["destination"]["diskUniqueId"],
        "gptSnapshotSha256": proposal["expectedGptSnapshotSha256"],
        "partmanActions": [],
        "bootloaderActions": [],
        "dryRunClaimed": False,
        "firstWriteBeforeValidation": False,
        "completePrecommitPlanClaimed": False,
        "actionGraphAuthenticated": False,
    }


class ZorinPrecommitBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zorin-precommit-")
        self.addCleanup(self.temp.cleanup)
        self.image = Path(self.temp.name) / "synthetic-gpt.raw"
        write_synthetic_gpt(self.image)
        self.fd = os.open(self.image, os.O_RDONLY)
        self.addCleanup(os.close, self.fd)
        self.gpt = inspect_gpt_fd(self.fd, logical_sector_size=SECTOR)
        self.plan = make_shared_plan(self.gpt)
        self.proposal = make_proposal(self.plan, self.gpt)
        self.candidate = untrusted_observation(self.proposal, self.plan)

    def check(self, **options):
        return classify_zorin_precommit(
            self.proposal, self.plan, self.gpt, self.fd, **options
        )

    def deny(self, reason):
        with self.assertRaises(UbiquityHandoffDenied) as result:
            self.check(candidate=self.candidate)
        self.assertEqual(result.exception.reason, reason)

    def test_h_no_trace_classified_unavailable_even_if_handoff_valid(self):
        before = self.image.stat()
        outcome = self.check()
        after = self.image.stat()
        self.assertEqual(outcome.route, "ROUTE_B")
        self.assertEqual(outcome.status, PRECOMMIT_UNAVAILABLE)
        self.assertEqual(outcome.authorization, "DENY_NO_WRITER")
        self.assertFalse(outcome.staticMapValidated)
        self.assertFalse(outcome.earliestPossibleMutationLocated)
        self.assertFalse(outcome.productionStorageWritesAuthorized)
        self.assertFalse(outcome.precommitActionGraphAuthenticated)
        self.assertFalse(outcome.windowsInPlaceRollbackProven)
        self.assertEqual((before.st_mtime_ns, before.st_size),
                         (after.st_mtime_ns, after.st_size))

    def test_h_structurally_valid_but_untrusted_observation_still_denied(self):
        outcome = self.check(candidate=self.candidate)
        self.assertEqual(outcome.status, PRECOMMIT_UNAVAILABLE)
        self.assertEqual(outcome.authorization, "DENY_NO_WRITER")
        self.assertEqual(outcome.denialReasons[0],
                         "PARTMAN_WRITE_CAN_PRECEDE_UNOBSERVED_COMMIT")
        self.assertFalse(outcome.firstWriteFenced)
        self.assertFalse(outcome.nativeInstallerInvoked)

    def test_partial_precommit_trace_rejected(self):
        self.candidate.pop("gptSnapshotSha256")
        self.deny("E_PARTIAL_PRECOMMIT_OBSERVATION")

    def test_partman_action_is_unobserved_even_on_linux_target(self):
        self.candidate["partmanActions"] = [{"kind": "PARTMAN_COMMIT", "partitionNumber": 5}]
        self.deny("E_UNOBSERVED_PARTMAN_ACTION")

    def test_first_write_before_validation_rejected(self):
        self.candidate["firstWriteBeforeValidation"] = True
        self.deny("E_FIRST_WRITE_PRECEDES_VALIDATION")

    def test_disk_changes_between_selection_and_commit(self):
        self.candidate["commitDiskUniqueId"] = "DIFFERENT-QEMU-DISK"
        self.deny("E_DISK_CHANGED_BEFORE_COMMIT")

    def test_esp_recovery_oem_and_windows_writes_rejected(self):
        for partition in (1, 2, 3, 4):
            with self.subTest(partition=partition):
                self.proposal["proposedOperations"] = [
                    {
                        "kind": "ROOT_FORMAT",
                        "partitionNumber": partition,
                        "origin": "STATIC_CODE_REFERENCE_ONLY",
                    }
                ]
                self.deny("E_WINDOWS_PROTECTED_PARTITION")

    def test_new_bootloader_action_rejected(self):
        for kind in ("GRUB_INSTALL", "ESP_WRITE", "NVRAM_WRITE", "BIOS_BOOT_WRITE"):
            with self.subTest(kind=kind):
                self.candidate["bootloaderActions"] = [
                    {"kind": kind, "partitionNumber": 1}
                ]
                self.deny("E_UNAUTHORIZED_BOOTLOADER_ACTION")
                self.candidate["bootloaderActions"] = []

    def test_installer_source_provenance_mismatch_rejected(self):
        self.candidate["installerExecutableSha256"] = "0" * 64
        self.deny("E_INSTALLER_SOURCE_PROVENANCE")

    def test_target_gpt_identity_drift_rejected(self):
        self.candidate["gptSnapshotSha256"] = "0" * 64
        self.deny("E_DESTINATION_CHANGED")

    def test_false_dry_run_rejected(self):
        for field in ("dryRunClaimed", "completePrecommitPlanClaimed", "actionGraphAuthenticated"):
            with self.subTest(field=field):
                self.candidate[field] = True
                self.deny("E_FALSE_DRY_RUN")
                self.candidate[field] = False

    def test_foreign_transaction_rejected(self):
        self.candidate["transactionId"] = "d" * 32
        self.deny("E_FOREIGN_TRANSACTION")

    def test_wrong_selected_disk_rejected(self):
        self.candidate["selectedDiskUniqueId"] = "OTHER-DISK"
        self.deny("E_WRONG_DISK")

    def test_partial_original_handoff_rejected(self):
        self.proposal.pop("destination")
        with self.assertRaises(UbiquityHandoffDenied) as result:
            self.check()
        self.assertEqual(result.exception.reason, "E_HANDOFF_SCHEMA")

    def test_untrusted_static_map_digest_rejected(self):
        with self.assertRaises(UbiquityHandoffDenied) as result:
            self.check(code_map_bytes=b"not the authenticated #264 map")
        self.assertEqual(result.exception.reason, "E_INSTALLER_SOURCE_PROVENANCE")

    def test_static_map_cannot_be_forged_by_asserting_validation(self):
        self.assertFalse(validate_static_code_map(None))
        with self.assertRaises(UbiquityHandoffDenied) as result:
            validate_static_code_map(b'{"nativeInstallerExecuted": false}')
        self.assertEqual(result.exception.reason, "E_INSTALLER_SOURCE_PROVENANCE")

    def test_only_explicit_false_authorization_fields_returned(self):
        obj = asdict(self.check(candidate=self.candidate))
        for key in (
            "mutationOrderingAuthenticated",
            "precommitActionGraphAuthenticated",
            "firstWriteFenced",
            "nativeInstallerInvoked",
            "productionStorageWritesAuthorized",
            "windowsEspWriteAuthorized",
            "sameDiskDualBootVerified",
            "windowsInPlaceRollbackProven",
            "stable",
        ):
            with self.subTest(key=key):
                self.assertIs(obj[key], False)
        self.assertEqual(obj["authorization"], "DENY_NO_WRITER")


if __name__ == "__main__":
    unittest.main()
