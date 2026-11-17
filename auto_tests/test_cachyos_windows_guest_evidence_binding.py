"""Synthetic Windows 10/11 recovery evidence bound to an Ed25519 CachyOS handoff.

No real Windows boot or Linux/Windows dual boot occurs in these tests.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path

from test_cachyos_windows_transaction_bridge import (
    WindowsBridgeContractTests as _Ed25519BridgeFixture,
)
from test_windows_guest_recovery_proof import baseline as guest_baseline_fixture

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "auto_tests/tools/cachyos_windows_guest_evidence_binding.py"
SPEC = importlib.util.spec_from_file_location("gaslux_guest_binding_test", SOURCE)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(SOURCE.parent))
try:
    SPEC.loader.exec_module(MODULE)
finally:
    sys.path.remove(str(SOURCE.parent))

GIB = 1024 ** 3
WIN = "11111111-2222-3333-4444-555555555555"
ESP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RECOVERY = "12345678-1234-1234-1234-123456789abc"
LINUX = "87654321-abcd-abcd-abcd-abcdef123456"


class WindowsGuestBindingTests(unittest.TestCase):
    def setUp(self):
        # Use the SAME fixture already tested for v4 plan, durable ledger,
        # canonical signed handoff and an independently generated Ed25519 key.
        self.fx = _Ed25519BridgeFixture(
            methodName="test_real_ed25519_bridge_checks_real_legacy_validators"
        )
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

        doc = guest_baseline_fixture()
        doc["runId"] = self.fx.plan["planId"]
        doc["windowsDiskId"] = self.fx.plan["disk"]["uniqueId"]
        doc["disks"][0]["id"] = self.fx.plan["disk"]["uniqueId"]
        doc["windowsPartitionGuid"] = WIN
        doc["espPartitionGuid"] = ESP
        doc["windowsVersion"] = "10.0.19045"
        doc["windowsProductType"] = 1
        doc["espFilesystemUuid"] = "AB12-CD34"
        doc["windowsEfiSha256"] = "a" * 64
        plan_disk = self.fx.plan["disk"]
        doc["disks"][0]["partitions"] = [
            {
                "guid": ESP, "number": 1,
                "offset": plan_disk["boot"]["offsetBytes"],
                "size": plan_disk["boot"]["sizeBytes"],
                "gptType": MODULE.ESP_TYPE, "isBoot": False, "isSystem": True,
            },
            {
                "guid": WIN, "number": 2,
                "offset": plan_disk["windows"]["offsetBytes"],
                "size": plan_disk["windows"]["sizeBytes"],
                "gptType": MODULE.WINDOWS_DATA_TYPE,
                "isBoot": True, "isSystem": False,
            },
            {
                "guid": RECOVERY, "number": 3,
                "offset": plan_disk["recovery"]["offsetBytes"],
                "size": plan_disk["recovery"]["sizeBytes"],
                "gptType": MODULE.WINRE_TYPE, "isBoot": False, "isSystem": False,
            },
        ]
        self.before = doc
        self.after = copy.deepcopy(doc)
        self.after["phase"] = "postinstall"
        self.after["capturedAt"] = "2026-11-17T00:30:00+00:00"
        self.after["windowsBootTime"] = "2026-11-17T00:00:00+00:00"
        self.after["disks"][0]["partitions"][1]["size"] = 180 * GIB
        self.after["disks"][0]["partitions"].append({
            "guid": LINUX, "number": 4, "offset": 181 * GIB,
            "size": 20 * GIB, "gptType": MODULE.LINUX_DATA_TYPE,
            "isBoot": False, "isSystem": False,
        })
        self.fx.baseline["windowsLoaderSha256"] = "a" * 64
        self.fx.baseline["bcdSha256"] = hashlib.sha256(
            doc["bcdAllRaw"].encode("utf-8")
        ).hexdigest()
        self.fx.handoff["windowsLoaderSha256"] = "a" * 64
        self.fx.resign()

    def check(self, mode="postinstall"):
        return MODULE.evaluate_guest_binding(
            self.fx.plan, self.fx.state, self.fx.baseline,
            self.before, self.after, mode,
            self.fx.envelope, self.fx.signature, self.fx.public,
            self.fx.cmdline, "01234567-89ab-cdef-0123-456789abcdef",
        )

    def test_consistent_windows_10_guest_observations_never_authorize_writes(self):
        result = self.check()
        self.assertTrue(result["guestRecoveryDocumentsConsistent"])
        self.assertTrue(result["windowsEspFatSerialCrossChecked"])
        self.assertTrue(result["windowsBcdRawDigestCrossChecked"])
        for property in (
            "storageWritesAuthorized", "releaseEligible", "windowsBootVerified",
            "windowsBcdAndWinreRestorationVerified",
            "firmwareBootOrderRestorationVerified",
            "linuxKernelUpdateCrossbootVerified",
            "transactionIntegratedIntoProductionInstaller",
        ):
            self.assertIs(result[property], False)

    def test_windows_11_client_version_accepted(self):
        self.before["windowsVersion"] = self.after["windowsVersion"] = "10.0.26100"
        self.check()

    def test_windows_server_product_type_rejected(self):
        self.before["windowsProductType"] = 3
        with self.assertRaisesRegex(MODULE.GUEST.EvidenceError, "client"):
            self.check()

    def test_foreign_windows_disk_rejected(self):
        self.before["windowsDiskId"] = "FOREIGN-DISK-000001"
        with self.assertRaises(MODULE.GUEST.EvidenceError):
            self.check()

    def test_mismatched_windows_disk_size_rejected(self):
        self.before["disks"][0]["size"] -= GIB
        with self.assertRaisesRegex(MODULE.BridgeError, "disk geometry"):
            self.check()

    def test_recovery_partition_moved_rejected(self):
        self.before["disks"][0]["partitions"][2]["offset"] -= GIB
        with self.assertRaisesRegex(MODULE.BridgeError, "WinRE"):
            self.check()

    def test_esp_partition_moved_rejected(self):
        self.before["disks"][0]["partitions"][0]["offset"] += 100 * 1024 ** 2
        with self.assertRaisesRegex(MODULE.BridgeError, "ESP"):
            self.check()

    def test_windows_bootloader_tampering_rejected(self):
        self.before["windowsEfiSha256"] = "5" * 64
        with self.assertRaisesRegex(MODULE.BridgeError, "EFI loader"):
            self.check()

    def test_windows_bcd_mismatch_rejected(self):
        self.before["bcdAllRaw"] += "\nnew unowned boot entry"
        with self.assertRaisesRegex(MODULE.BridgeError, "BCD"):
            self.check()

    def test_windows_esp_uuid_mismatch_rejected(self):
        self.before["espFilesystemUuid"] = "DEAD-BEEF"
        with self.assertRaisesRegex(MODULE.BridgeError, "FAT32 UUID"):
            self.check()

    def test_secure_boot_rejected_before_target(self):
        self.before["secureBootEnabled"] = True
        with self.assertRaisesRegex(MODULE.BridgeError, "Secure Boot"):
            self.check()

    def test_bitlocker_rejected_before_target(self):
        self.before["bitlocker"]["protectionStatus"] = "On"
        with self.assertRaisesRegex(MODULE.BridgeError, "encryption"):
            self.check()

    def test_after_windows_boot_timestamp_must_be_later(self):
        self.after["windowsBootTime"] = self.before["windowsBootTime"]
        with self.assertRaisesRegex(MODULE.GUEST.EvidenceError, "subsequent Windows boot"):
            self.check()

    def test_installed_linux_partition_must_match_owned_offset(self):
        self.after["disks"][0]["partitions"][-1]["offset"] += GIB
        self.after["disks"][0]["partitions"][-1]["size"] -= GIB
        with self.assertRaisesRegex(MODULE.BridgeError, "transaction-owned"):
            self.check()

    def test_linux_partition_type_mismatch_rejected(self):
        self.after["disks"][0]["partitions"][-1]["gptType"] = MODULE.WINDOWS_DATA_TYPE
        with self.assertRaisesRegex(MODULE.BridgeError, "transaction-owned"):
            self.check()

    def test_duplicate_linux_partition_rejected(self):
        self.after["disks"][0]["partitions"].append({
            "guid": "b1234567-abcd-abcd-abcd-abcdef123456",
            "number": 5, "offset": 202 * GIB, "size": GIB,
            "gptType": MODULE.LINUX_DATA_TYPE, "isBoot": False,
            "isSystem": False,
        })
        with self.assertRaisesRegex(MODULE.GUEST.EvidenceError, "shrink region"):
            self.check()

    def test_rollback_exact_partition_restoration_consistency(self):
        self.after = copy.deepcopy(self.before)
        self.after["phase"] = "rollback"
        self.after["capturedAt"] = "2026-11-17T00:30:00+00:00"
        self.after["windowsBootTime"] = "2026-11-17T00:00:00+00:00"
        result = self.check(mode="rollback")
        self.assertTrue(result["guestRecoveryDocumentsConsistent"])
        self.assertFalse(result["windowsBcdAndWinreRestorationVerified"])

    def test_rollback_with_foreign_linux_partition_rejected(self):
        self.after["phase"] = "rollback"
        with self.assertRaises(MODULE.GUEST.EvidenceError):
            self.check(mode="rollback")


if __name__ == "__main__":
    unittest.main()
