"""POP-DISTINST-PREWRITE-01 — pure, fail-closed, no-disk native boundary tests.

The existing Windows/Pop shaped plan fixture contains synthetic signed claims:
no case proves genuine Windows, a signed handoff, or real source↔ELF mapping.
"""

from __future__ import annotations

import json
import sys
import unittest
import uuid
from pathlib import Path

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

from gaslux_popos_distinst_prewrite_gap import (  # noqa: E402
    ELF_SHA256,
    ISO_BUILD,
    ISO_SHA256,
    SIGNER_FINGERPRINT,
    UPSTREAM_SOURCE_COMMIT,
    assess_prewrite_gap,
)
from test_windows10_popos_native_write_set import lab_fixture  # noqa: E402
from windows10_popos_native_write_set import _digest  # noqa: E402
from windows_x64_installed_gpt_ro_audit import DiskAuditError  # noqa: E402


def fixture() -> tuple[list, dict]:
    values = lab_fixture()
    before, after, plan, media, guest, tx, checkpoint, operations = values
    media["isoSha256"] = ISO_SHA256
    media["distinstSha256"] = ELF_SHA256
    tx["handoffSha256"] = _digest({
        "before": before,
        "after": after,
        "plan": plan,
        "media": media,
        "guest": guest,
        "checkpoint": checkpoint,
        "transactionId": tx["transactionId"],
    })
    request = {
        "operation": "read-only-observation",
        "transactionId": tx["transactionId"],
        "diskGuid": before["diskGuid"],
        "sourceCommitObserved": UPSTREAM_SOURCE_COMMIT,
        "sourceMatchesInstalledElf": False,
        "completePrewriteProposalFromNativeInstaller": False,
        "preflightToCommitIdentityProven": False,
        "nativeBootloaderAuthenticated": False,
        "installerAlreadyInvoked": False,
        "efiVariablesWritable": False,
        "windowsBootManagerModificationAllowed": False,
        "signedManifestFingerprint": SIGNER_FINGERPRINT,
        "isoBuild": ISO_BUILD,
        "isoSha256": ISO_SHA256,
        "distinstElfSha256": ELF_SHA256,
        "backingParentSha256": checkpoint["snapshotOfGenuineWindowsParentSha256"],
        "stageCheckpointSha256": checkpoint["snapshotOfSixGptWindowsStageSha256"],
    }
    return values, request


class PopDistinstPrewriteGapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.values, self.request = fixture()

    def assess(self) -> dict:
        return assess_prewrite_gap(*self.values, self.request)

    def refused(self) -> None:
        with self.assertRaises(DiskAuditError):
            self.assess()

    def test_valid_shaped_candidate_is_still_deny_no_writer(self) -> None:
        result = self.assess()
        self.assertEqual(result["decision"], "DENY_NO_WRITER")
        self.assertEqual(result["transactionId"], self.request["transactionId"])
        self.assertEqual(result["firstPotentialPersistentDiskStep"],
                         "Installer::partition -> disk.commit")
        self.assertFalse(result["nativeTestFlagIsReadOnly"])
        self.assertFalse(result["completeNativeWriteSetAvailableBeforeMutation"])
        self.assertFalse(result["sourceToInstalledElfCorrespondenceVerified"])
        self.assertFalse(result["nativeBootloaderVerifiedForPinnedElf"])
        for key in (
            "observationComplete", "distinstExecutionAuthorized",
            "windowsWriterAuthorized", "productionInstallationAuthorized",
            "sameDiskDualBootVerified", "windowsInPlaceRollbackProven",
            "releaseEligible", "stable",
        ):
            self.assertIs(result[key], False, key)
        self.assertNotIn("argv", result)
        self.assertNotIn("execute", result)
        self.assertEqual(len(result["blockedBy"]), 6)
        json.dumps(result, sort_keys=True)

    def test_changed_destination_and_disk_serial_refuse(self) -> None:
        self.request["diskGuid"] = str(uuid.uuid4())
        self.refused()
        self.values, self.request = fixture()
        self.values[4]["diskSerial"] = "FOREIGN"
        self.refused()

    def test_win_esp_and_microsoft_protection_refuse(self) -> None:
        self.values[7][0]["partitionIndex"] = 1
        self.refused()
        self.values, self.request = fixture()
        self.values[2]["windowsBootManagerToRemainUntouched"] = False
        self.refused()
        self.values, self.request = fixture()
        self.values[7][-1]["mount"] = "/boot/efi/EFI/Microsoft"
        self.refused()

    def test_gpt_changed_after_plan_refuses(self) -> None:
        self.values[4]["partitionEntries"][0]["lastLba"] += 1
        self.refused()
        self.values, self.request = fixture()
        self.values[1]["linuxRoot"]["startLba"] += 1
        self.refused()

    def test_unknown_or_partial_operation_refuses(self) -> None:
        self.values[7].append({"operation": "disk-commit", "partitionIndex": 0})
        self.refused()
        self.values, self.request = fixture()
        self.values[7] = self.values[7][:-1]
        self.refused()

    def test_action_before_authorization_and_test_flag_refuse(self) -> None:
        for action in ("install", "--test", "execute-distinst", "partition-only"):
            with self.subTest(action=action):
                self.values, self.request = fixture()
                self.request["operation"] = action
                self.refused()
        self.values, self.request = fixture()
        self.request["installerAlreadyInvoked"] = True
        self.refused()

    def test_unsigned_bootloader_efi_nvram_claims_refuse(self) -> None:
        for key in (
            "nativeBootloaderAuthenticated",
            "efiVariablesWritable",
            "windowsBootManagerModificationAllowed",
        ):
            with self.subTest(field=key):
                self.values, self.request = fixture()
                self.request[key] = True
                self.refused()
        self.values, self.request = fixture()
        self.values[4]["efiVariablesWritable"] = True
        self.refused()

    def test_installer_provenance_and_source_identity_refuse(self) -> None:
        for key, wrong in (
            ("isoSha256", "c" * 64),
            ("distinstElfSha256", "d" * 64),
            ("signedManifestFingerprint", "0" * 40),
            ("isoBuild", "24.04/intel/21"),
            ("sourceCommitObserved", "0" * 40),
        ):
            with self.subTest(key=key):
                self.values, self.request = fixture()
                self.request[key] = wrong
                self.refused()
        self.values, self.request = fixture()
        self.values[3]["distinstSha256"] = "e" * 64
        self.refused()

    def test_unverified_source_cannot_be_promoted_to_correlated(self) -> None:
        for key in (
            "sourceMatchesInstalledElf",
            "completePrewriteProposalFromNativeInstaller",
            "preflightToCommitIdentityProven",
        ):
            with self.subTest(field=key):
                self.values, self.request = fixture()
                self.request[key] = True
                self.refused()

    def test_foreign_transaction_and_checkpoint_refuse(self) -> None:
        for key, wrong in (
            ("transactionId", str(uuid.uuid4())),
            ("backingParentSha256", "c" * 64),
            ("stageCheckpointSha256", "d" * 64),
        ):
            with self.subTest(field=key):
                self.values, self.request = fixture()
                self.request[key] = wrong
                self.refused()

    def test_missing_extra_or_wrongly_typed_fields_refuse(self) -> None:
        for mutation in ("missing", "extra", "bool-as-string", "partial-plan"):
            with self.subTest(mutation=mutation):
                self.values, self.request = fixture()
                if mutation == "missing":
                    del self.request["signedManifestFingerprint"]
                elif mutation == "extra":
                    self.request["execute"] = True
                elif mutation == "bool-as-string":
                    self.request["installerAlreadyInvoked"] = "false"
                else:
                    self.values[2].pop("partitions")
                self.refused()

    def test_no_process_shell_or_block_device_from_new_classifier(self) -> None:
        source = (TOOLS / "gaslux_popos_distinst_prewrite_gap.py").read_text()
        for forbidden in ("subprocess.run(", "subprocess.Popen(",
                          "os.system(", "os.open(", "distinst --test",
                          "mkfs.fat ", "mkfs.ext4 ", "os.exec"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
