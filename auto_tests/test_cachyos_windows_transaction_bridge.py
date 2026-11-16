"""Synthetic contract regression for the CachyOS Windows handoff bridge.

No Windows installation, Windows boot, firmware mutation, target formatting,
update or rollback is executed here. A real ephemeral OpenSSL Ed25519 signature
exercises the same authenticated envelope parser as the Archiso lab.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "auto_tests/tools/cachyos_windows_transaction_bridge.py"
SPEC = importlib.util.spec_from_file_location("gaslux_windows_bridge_test", SOURCE)
assert SPEC and SPEC.loader
BRIDGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BRIDGE)
GIB = 1024 ** 3
RUN_ID = "a" * 32
ISO_SHA = "b" * 64
WIN_SHA = "3" * 64
ROOT_UUID = "01234567-89ab-cdef-0123-456789abcdef"
DISK_ID = "WIN-TEST-VIRTIO-000001"
WINDOWS = {"number": 2, "offsetBytes": GIB, "sizeBytes": 200 * GIB}
BOOT = {"number": 1, "offsetBytes": 1024 ** 2, "sizeBytes": 100 * 1024 ** 2}
RECOVERY = {"number": 3, "offsetBytes": 240 * GIB, "sizeBytes": GIB}


def make_plan():
    return {
        "schemaVersion": 4, "planId": RUN_ID,
        "createdAtUtc": "2026-11-16T20:00:00Z", "firmware": "uefi",
        "distribution": {
            "id": "cachyos", "name": "CachyOS", "osReleaseId": "cachyos",
            "grubDisplayName": "CachyOS", "grubIcon": "cachyos",
            "secureBootMicrosoftAuthorities": ["2011"],
            "installerIsoFileName": "cachyos.iso",
            "installerIsoUrl": "https://example.test/cachyos.iso",
            "installerIsoWindowsPath":
                "C:\\ProgramData\\Libertix\\Downloads\\" + RUN_ID + "\\cachyos.iso",
            "installerIsoSha256": ISO_SHA,
            "liveIsoUrl": "https://example.test/libertix.iso",
            "liveIsoSha256": "c" * 64,
        },
        "locale": {
            "languageCode": "fr", "systemLanguage": "fr_FR.UTF-8",
            "keyboardLayout": "fr", "keyboardVariant": "",
            "keyboardModel": "pc105", "timezone": "Europe/Paris",
        },
        "account": {
            "username": "oem",
            "passwordHashWindowsPath": "C:\\ProgramData\\Libertix\\Recovery\\account-secret.env",
            "computerName": "gaslux-test",
        },
        "disk": {
            "number": 0, "uniqueId": DISK_ID,
            "partitionTableId": "gpt:12345678-1234-1234-1234-123456789abc",
            "sizeBytes": 256 * GIB, "logicalSectorSizeBytes": 512,
            "partitionStyle": "GPT", "systemDrive": "C:",
            "windows": copy.deepcopy(WINDOWS), "boot": copy.deepcopy(BOOT),
            "recovery": copy.deepcopy(RECOVERY),
            "installer": {
                "number": 4, "offsetBytes": 181 * GIB,
                "finalOffsetBytes": 181 * GIB,
                "resizeMode": "windows-online",
                "finalSizeBytes": 20 * GIB, "stagingSizeBytes": 8 * GIB,
            },
        },
        "features": {
            "shareWindowsFilesInLinux": True, "shareLinuxFilesInWindows": True,
            "windowsProfilesJsonBase64": "W10=",
            "windowsPreferenceMigration": {
                "enabled": False, "bundleFileName": None, "bundleSha256": None,
                "bundleSizeBytes": 0, "wifiProfileCount": 0,
            },
        },
        "runtime": {
            "windowsBitLockerState": "FullyDecrypted", "lowMemoryMode": False,
            "bootStrategy": "uefi-boot-next", "secureBootEnabled": False,
            "trustedMicrosoftUefiAuthorities": ["2011"],
            "recoveryRootWindows": "C:\\ProgramData\\Libertix\\Recovery",
            "recoveryRunId": "d" * 32,
        },
    }


def make_state():
    return {
        "schemaVersion": 1, "planId": RUN_ID, "revision": 8,
        "status": "running", "phase": "live",
        "activeStep": "live.preflight-verified",
        "completedSteps": list(BRIDGE.WINDOWS_STEPS),
        "compensatedSteps": [], "failure": None,
        "updatedAtUtc": "2026-11-16T20:00:01Z",
    }


def make_baseline():
    return {
        "schemaVersion": 1, "planId": RUN_ID, "diskUniqueId": DISK_ID,
        "partitionTableId": "gpt:12345678-1234-1234-1234-123456789abc",
        "logicalSectorSizeBytes": 512, "firmware": "uefi",
        "partitionStyle": "GPT", "windowsPartition": copy.deepcopy(WINDOWS),
        "bootPartition": copy.deepcopy(BOOT),
        "recoveryPartition": copy.deepcopy(RECOVERY),
        "espUuid": "AB12-CD34", "windowsLoaderSha256": WIN_SHA,
        "bcdSha256": "4" * 64, "winreEnabled": True,
        "bitlockerState": "FullyDecrypted",
    }


def make_handoff():
    return {
        "schemaVersion": 1, "backend": "archiso-cachyos",
        "distribution": "cachyos", "runId": RUN_ID, "bootNonce": "f" * 32,
        "firmware": "uefi", "partitionStyle": "gpt",
        "secureBootEnabled": False, "isoSha256": ISO_SHA,
        "isoSizeBytes": 4_000_000_000,
        "isoStorageUuid": "fedcba98-7654-4321-aaaa-111111111111",
        "isoStorageFilesystem": "ext4", "isoRelativePath": "/cachyos.iso",
        "rootUuid": ROOT_UUID, "targetDiskId": DISK_ID,
        "windowsEspUuid": "AB12-CD34", "windowsLoaderSha256": WIN_SHA,
    }


class WindowsBridgeContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.private = base / "private.pem"
        self.public = base / "public.pem"
        self.envelope = base / "handoff.json"
        self.signature = base / "handoff.sig"
        for args in (
            ["genpkey", "-algorithm", "Ed25519", "-out", str(self.private)],
            ["pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
        ):
            subprocess.run(["openssl", *args], check=True, capture_output=True)
        self.plan = make_plan()
        self.state = make_state()
        self.baseline = make_baseline()
        self.handoff = make_handoff()
        self.resign()

    def resign(self):
        raw = BRIDGE.AUTH.canonical(self.handoff)
        self.envelope.write_bytes(raw)
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.private),
             "-rawin", "-in", str(self.envelope), "-out", str(self.signature)],
            check=True, capture_output=True,
        )
        self.cmdline = " ".join((
            "BOOT_IMAGE=/vmlinuz-linux-cachyos-lts",
            "gaslux.run=" + RUN_ID,
            "gaslux.nonce=" + self.handoff["bootNonce"],
            "gaslux.plan_sha256=" + hashlib.sha256(raw).hexdigest(),
            "gaslux.key_sha256=" +
            hashlib.sha256(self.public.read_bytes()).hexdigest(),
        ))

    def evaluate(self):
        return BRIDGE.evaluate(
            self.plan, self.state, self.baseline,
            self.envelope, self.signature, self.public,
            self.cmdline, ROOT_UUID,
        )

    def test_real_ed25519_bridge_checks_real_legacy_validators(self):
        self.assertIs(self.evaluate()["contractMatched"], True)
        result = self.evaluate()
        for key in (
            "storageWritesAuthorized", "releaseEligible",
            "windowsBootVerified", "windowsBcdAndWinreRestorationVerified",
            "firmwareBootOrderRestorationVerified",
            "linuxKernelUpdateCrossbootVerified", "uninstallVerified",
            "transactionIntegratedIntoProductionInstaller",
        ):
            self.assertIs(result[key], False)

    def test_windows_plan_id_mismatch(self):
        self.state["planId"] = "e" * 32
        with self.assertRaisesRegex(BRIDGE.BridgeError, "IDs differ"):
            self.evaluate()

    def test_incomplete_windows_recovery_ledger(self):
        self.state["completedSteps"] = list(BRIDGE.WINDOWS_STEPS[:2])
        self.state["activeStep"] = "windows.recovery-armed"
        self.state["phase"] = "windows"
        with self.assertRaisesRegex(BRIDGE.BridgeError, "uncompensated live handoff"):
            self.evaluate()

    def test_secure_boot_enabled_rejected(self):
        self.plan["runtime"]["secureBootEnabled"] = True
        with self.assertRaisesRegex(BRIDGE.BridgeError, "Secure Boot"):
            self.evaluate()

    def test_firmware_or_table_mismatch_rejected(self):
        self.plan["firmware"] = "bios"
        with self.assertRaises((BRIDGE.BridgeError, BRIDGE.PLAN.PlanValidationError)):
            self.evaluate()

    def test_foreign_storage_identity_rejected(self):
        self.handoff["targetDiskId"] = "OTHER-QEMU-DISK-999"
        self.resign()
        with self.assertRaisesRegex(BRIDGE.BridgeError, "disk/ISO"):
            self.evaluate()

    def test_sha256_pinned_iso_mismatch_rejected(self):
        self.handoff["isoSha256"] = "e" * 64
        self.resign()
        with self.assertRaisesRegex(BRIDGE.BridgeError, "disk/ISO"):
            self.evaluate()

    def test_windows_partition_geometry_mismatch_rejected(self):
        self.baseline["windowsPartition"]["sizeBytes"] -= GIB
        with self.assertRaisesRegex(BRIDGE.BridgeError, "geometry differs"):
            self.evaluate()

    def test_wrong_efi_loader_hash_rejected(self):
        self.baseline["windowsLoaderSha256"] = "5" * 64
        with self.assertRaisesRegex(BRIDGE.BridgeError, "original Windows EFI"):
            self.evaluate()

    def test_windows_recovery_disabled_rejected(self):
        self.baseline["winreEnabled"] = False
        with self.assertRaisesRegex(BRIDGE.BridgeError, "recovery"):
            self.evaluate()

    def test_incorrect_windows_bcd_hash_rejected(self):
        self.baseline["bcdSha256"] = "0" * 64
        with self.assertRaisesRegex(BRIDGE.BridgeError, "BCD|boot artifact"):
            self.evaluate()

    def test_signature_tampering_rejected(self):
        self.signature.write_bytes(bytes(64))
        with self.assertRaisesRegex(BRIDGE.AUTH.AuthError, "signature"):
            self.evaluate()

    def test_nonce_replay_rejected(self):
        self.cmdline = self.cmdline.replace("gaslux.nonce=" + "f"*32,
                                            "gaslux.nonce=" + "e"*32)
        with self.assertRaisesRegex(BRIDGE.AUTH.AuthError, "nonce"):
            self.evaluate()

    def test_legacy_mint_plan_cannot_request_cachyos(self):
        self.plan["distribution"]["id"] = "mint"
        with self.assertRaisesRegex(BRIDGE.BridgeError, "not explicitly for CachyOS"):
            self.evaluate()

    def test_malformed_baseline_rejected(self):
        self.baseline["arbitraryNewField"] = True
        with self.assertRaisesRegex(BRIDGE.BridgeError, "foreign fields"):
            self.evaluate()

    def test_recovery_session_must_exist(self):
        self.plan["runtime"]["recoveryRootWindows"] = None
        self.plan["runtime"]["recoveryRunId"] = None
        with self.assertRaisesRegex(BRIDGE.BridgeError, "recovery session"):
            self.evaluate()


if __name__ == "__main__":
    unittest.main()
