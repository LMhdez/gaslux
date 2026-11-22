"""Zorin native Ubiquity handoff: real GPT bytes, read-only FD, no writer.

Only a sparse regular file under tempfile is created. GPT fixture generation
is test data only and never replaces the canonical Safety GPT inspector.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from libertix_disk_identity_gate import inspect_gpt_fd
from zorin_native_ubiquity_map import ISO_SHA, UBIQUITY_EXEC_SHA, UBIQUITY_VERSION
from zorin_ubiquity_handoff_readonly import (
    PINNED_CODE_MAP_SHA,
    UbiquityHandoffDenied,
    canonical_sha,
    validate_ubiquity_handoff,
)

SECTOR = 512
DISK_BYTES = 4 * 1024**3
SECTORS = DISK_BYTES // SECTOR
DISK_GUID = "f3a09eb8-7da3-480a-a7ba-25d703c03eab"
TYPE_ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
TYPE_MSR = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
TYPE_DATA = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
TYPE_WINRE = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
TYPE_LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"
SPEC = (
    (TYPE_ESP, "1029731a-5894-4f7e-bbe2-01adc3510f11", 2048, 1050623),
    (TYPE_MSR, "2d10ebaf-970f-4758-9d41-5e925c0da2ba", 1050624, 1083391),
    (TYPE_DATA, "41eecb73-dcfb-47d0-b060-d820046ad3a9", 1083392, 5277695),
    (TYPE_WINRE, "d95f8056-7bc6-47d4-904c-2ba63a07f91d", 5277696, 5801983),
    (TYPE_LINUX, "6a4b6220-5659-4696-8a68-f5b5be59ad77", 5801984, 7899135),
)


def write_synthetic_gpt(path: Path) -> None:
    """Sparse, self-consistent fixture (never a disk writer for host devices)."""
    with path.open("xb") as stream:
        stream.truncate(DISK_BYTES)
        mbr = bytearray(512)
        mbr[446 + 4] = 0xEE
        struct.pack_into("<II", mbr, 446 + 8, 1, SECTORS - 1)
        mbr[510:512] = b"\x55\xaa"
        stream.seek(0)
        stream.write(mbr)

        entries = bytearray(128 * 128)
        for i, (type_guid, part_guid, start, end) in enumerate(SPEC):
            position = 128 * i
            entries[position : position + 16] = uuid.UUID(type_guid).bytes_le
            entries[position + 16 : position + 32] = uuid.UUID(part_guid).bytes_le
            struct.pack_into("<QQQ", entries, position + 32, start, end, 0)
        array_crc = zlib.crc32(entries)
        for location in (2, SECTORS - 33):
            stream.seek(location * SECTOR)
            stream.write(entries)
        for current, alternate, array_lba in (
            (1, SECTORS - 1, 2),
            (SECTORS - 1, 1, SECTORS - 33),
        ):
            header = bytearray(SECTOR)
            header[:8] = b"EFI PART"
            struct.pack_into("<IIII", header, 8, 0x10000, 92, 0, 0)
            struct.pack_into(
                "<QQQQ", header, 24, current, alternate, 34, SECTORS - 34
            )
            header[56:72] = uuid.UUID(DISK_GUID).bytes_le
            struct.pack_into("<QIII", header, 72, array_lba, 128, 128, array_crc)
            struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
            stream.seek(current * SECTOR)
            stream.write(header)
        stream.flush()
        os.fsync(stream.fileno())


def make_shared_plan(snapshot: dict) -> dict:
    parts = {p["number"]: p for p in snapshot["partitions"]}

    def partition(number):
        return {
            "number": number,
            "offsetBytes": parts[number]["offsetBytes"],
            "sizeBytes": parts[number]["sizeBytes"],
        }

    final = partition(5)
    return {
        "schemaVersion": 4,
        "planId": "a" * 32,
        "createdAtUtc": "2026-11-22T14:00:00Z",
        "firmware": "uefi",
        "distribution": {
            "id": "zorin",
            "name": "Zorin OS 18.1 Core",
            "osReleaseId": "zorin",
            "grubDisplayName": "Zorin OS 18.1 Core",
            "grubIcon": "zorin",
            "secureBootMicrosoftAuthorities": ["2011"],
            "installerIsoFileName": "zorin.iso",
            "installerIsoUrl": "https://mirrors.univ-reims.fr/IMAGES/zorinos/18/Zorin-OS-18.1-Core-64-bit.iso",
            "installerIsoWindowsPath": "C:\\zorin.iso",
            "installerIsoSha256": ISO_SHA,
            "liveIsoUrl": "https://test.invalid/synthetic-only",
            "liveIsoSha256": hashlib.sha256(b"synthetic-test-live-fixture").hexdigest(),
        },
        "locale": {
            "languageCode": "en",
            "systemLanguage": "en_US.UTF-8",
            "keyboardLayout": "us",
            "keyboardModel": "pc105",
            "timezone": "Europe/Lisbon",
        },
        "account": {
            "username": "zorintest",
            "passwordHashWindowsPath": "C:\\synthetic-hash",
            "computerName": "zorinlab",
        },
        "disk": {
            "number": 0,
            "uniqueId": "SYNTHETIC-QCOW2-GPT-NOT-A-PHYSICAL-DISK",
            "partitionTableId": snapshot["partitionTableId"],
            "sizeBytes": snapshot["sizeBytes"],
            "logicalSectorSizeBytes": snapshot["logicalSectorSizeBytes"],
            "partitionStyle": "GPT",
            "systemDrive": "C:",
            "windows": partition(3),
            "boot": partition(1),
            "recovery": partition(4),
            "installer": {
                "number": 5,
                "offsetBytes": final["offsetBytes"],
                "finalOffsetBytes": final["offsetBytes"],
                "resizeMode": "windows-online",
                "finalSizeBytes": final["sizeBytes"],
                "stagingSizeBytes": final["sizeBytes"],
            },
        },
        "features": {
            "shareWindowsFilesInLinux": False,
            "shareLinuxFilesInWindows": False,
            "windowsProfilesJsonBase64": "e30=",
            "windowsPreferenceMigration": {
                "enabled": False,
                "bundleFileName": None,
                "bundleSha256": None,
                "bundleSizeBytes": 0,
                "wifiProfileCount": 0,
            },
        },
        "runtime": {
            "windowsBitLockerState": "FullyDecrypted",
            "lowMemoryMode": False,
            "bootStrategy": "uefi-boot-next",
            "secureBootEnabled": False,
            "trustedMicrosoftUefiAuthorities": ["2011"],
            "recoveryRootWindows": "C:\\synthetic-recovery",
            "recoveryRunId": "b" * 32,
        },
    }


def make_proposal(plan: dict, snapshot: dict) -> dict:
    parts = {p["number"]: p for p in snapshot["partitions"]}
    root = parts[5]
    return {
        "schemaVersion": 1,
        "kind": "ZORIN_UBIQUITY_HANDOFF_READONLY",
        "distribution": "zorin",
        "backend": "debian-squashfs",
        "iso": {
            "osReleaseId": "zorin",
            "sizeBytes": 3909091328,
            "sha256": ISO_SHA,
        },
        "installer": {
            "name": "ubiquity",
            "version": UBIQUITY_VERSION,
            "executable": "usr/bin/ubiquity",
            "executableSha256": UBIQUITY_EXEC_SHA,
        },
        "firmware": "uefi",
        "partitionStyle": "GPT",
        "planId": plan["planId"],
        "transactionId": plan["runtime"]["recoveryRunId"],
        "expectedGptSnapshotSha256": canonical_sha(snapshot),
        "destination": {
            "diskUniqueId": plan["disk"]["uniqueId"],
            "partitionTableId": snapshot["partitionTableId"],
            "sizeBytes": snapshot["sizeBytes"],
            "logicalSectorSizeBytes": snapshot["logicalSectorSizeBytes"],
            "partitionNumber": 5,
            "partGuid": root["partGuid"],
            "offsetBytes": root["offsetBytes"],
            "partitionBytes": root["sizeBytes"],
        },
        "protectedPartitions": [
            {
                "number": n,
                "partGuid": parts[n]["partGuid"],
                "role": role,
            }
            for n, role in ((1, "ESP"), (2, "MSR"), (3, "WINDOWS"), (4, "RECOVERY"))
        ],
        "proposedOperations": [
            {
                "kind": "ROOT_CONFIGURE",
                "partitionNumber": 5,
                "origin": "STATIC_CODE_REFERENCE_ONLY",
            }
        ],
        "bootloader": {
            "strategy": "GRUB_EFI_UNVERIFIED",
            "writeAuthorized": False,
        },
        "sourceEvidence": {
            "codeMapSha256": PINNED_CODE_MAP_SHA,
            "sourceInspectionRevalidated": False,
            "runtimeActionGraphObserved": False,
        },
        "provenance": {
            "sharedPlanSignatureAuthenticated": False,
            "guestDiskSourceAuthenticated": False,
            "partmanActionGraphAuthenticated": False,
            "efiWriteSetAuthenticated": False,
        },
        "recovery": {
            "independentCheckpointRestored": False,
            "windowsBcdWinreAuthenticated": False,
            "windowsBootAfterRecoveryVerified": False,
        },
        "authorization": "DENY_NO_WRITER",
        "nativeInstallerInvoked": False,
        "productionStorageWritesAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "sameDiskDualBootVerified": False,
        "windowsInPlaceRollbackProven": False,
        "stable": False,
    }


class ZorinUbiquityHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zorin-ubiquity-deny-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic-gpt.raw"
        write_synthetic_gpt(self.path)
        self.fd = os.open(self.path, os.O_RDONLY)
        self.addCleanup(os.close, self.fd)
        self.snapshot = inspect_gpt_fd(self.fd, logical_sector_size=SECTOR)
        self.plan = make_shared_plan(self.snapshot)
        self.proposal = make_proposal(self.plan, self.snapshot)

    def validate(self):
        return validate_ubiquity_handoff(
            self.proposal, self.plan, self.snapshot, self.fd
        )

    def rejected(self, reason):
        with self.assertRaises(UbiquityHandoffDenied) as caught:
            self.validate()
        self.assertEqual(caught.exception.reason, reason)

    def test_h_valid_readonly_proposal_never_grants_writes(self):
        before = self.path.stat()
        result = self.validate()
        after = self.path.stat()
        self.assertTrue(result["structurallyValidReadOnlyProposal"])
        self.assertEqual(result["authorization"], "DENY_NO_WRITER")
        self.assertEqual(result["writeOperationsAuthorized"], [])
        self.assertFalse(result["productionStorageWritesAuthorized"])
        self.assertFalse(result["windowsInPlaceRollbackProven"])
        self.assertEqual((before.st_size, before.st_mtime_ns),
                         (after.st_size, after.st_mtime_ns))

    def test_a_iso_hash_mismatch(self):
        self.proposal["iso"]["sha256"] = "0" * 64
        self.rejected("E_ISO_IDENTITY_MISMATCH")

    def test_a_iso_size_mismatch(self):
        self.proposal["iso"]["sizeBytes"] += 1
        self.rejected("E_ISO_IDENTITY_MISMATCH")

    def test_a_wrong_ubiquity_version(self):
        self.proposal["installer"]["version"] = "0.0-untrusted"
        self.rejected("E_INSTALLER_IDENTITY_MISMATCH")

    def test_a_wrong_ubiquity_executable_digest(self):
        self.proposal["installer"]["executableSha256"] = "f" * 64
        self.rejected("E_INSTALLER_IDENTITY_MISMATCH")

    def test_a_tampered_code_map_claim(self):
        self.proposal["sourceEvidence"]["codeMapSha256"] = "f" * 64
        self.rejected("E_INSTALLER_IDENTITY_MISMATCH")

    def test_b_wrong_disk_unique_id(self):
        self.proposal["destination"]["diskUniqueId"] = "UNRELATED-DISK"
        self.rejected("E_WRONG_DISK")

    def test_c_disk_sector_size_mismatch(self):
        self.proposal["destination"]["logicalSectorSizeBytes"] = 4096
        self.rejected("E_GPT_GEOMETRY_MISMATCH")

    def test_c_target_offset_mismatch(self):
        self.proposal["destination"]["offsetBytes"] += 512
        self.rejected("E_GPT_GEOMETRY_MISMATCH")

    def test_c_partuuid_mismatch(self):
        self.proposal["destination"]["partGuid"] = str(uuid.uuid4())
        self.rejected("E_GPT_GEOMETRY_MISMATCH")

    def test_c_expected_gpt_snapshot_mismatch(self):
        self.proposal["expectedGptSnapshotSha256"] = "f" * 64
        self.rejected("E_GPT_GEOMETRY_MISMATCH")

    def test_c_gpt_on_fd_mutated_after_baseline(self):
        os.close(self.fd)
        with self.path.open("r+b") as stream:
            stream.seek(SECTOR)
            stream.write(b"CORRUPTED")
        self.fd = os.open(self.path, os.O_RDONLY)
        self.rejected("E_GPT_GEOMETRY_MISMATCH")

    def test_d_windows_esp_recovery_msr_protected(self):
        for number in (1, 2, 3, 4):
            with self.subTest(partition=number):
                self.proposal["proposedOperations"] = [
                    {
                        "kind": "ROOT_FORMAT",
                        "partitionNumber": number,
                        "origin": "STATIC_CODE_REFERENCE_ONLY",
                    }
                ]
                self.rejected("E_WINDOWS_PROTECTED_PARTITION")

    def test_d_missing_protected_partition(self):
        self.proposal["protectedPartitions"].pop()
        self.rejected("E_WINDOWS_PROTECTED_PARTITION")

    def test_d_wrong_esp_guid(self):
        self.proposal["protectedPartitions"][0]["partGuid"] = str(uuid.uuid4())
        self.rejected("E_WINDOWS_PROTECTED_PARTITION")

    def test_e_foreign_transaction(self):
        self.proposal["transactionId"] = "c" * 32
        self.rejected("E_FOREIGN_TRANSACTION")

    def test_e_foreign_plan(self):
        self.proposal["planId"] = "c" * 32
        self.rejected("E_FOREIGN_TRANSACTION")

    def test_f_unauthenticated_partman_commit(self):
        self.proposal["proposedOperations"] = [
            {
                "kind": "PARTMAN_COMMIT",
                "partitionNumber": 5,
                "origin": "STATIC_CODE_REFERENCE_ONLY",
            }
        ]
        self.rejected("E_UNAUTHENTICATED_PARTMAN_ACTION")

    def test_g_unauthorized_bootloader_actions(self):
        for kind in ("GRUB_INSTALL", "ESP_WRITE", "NVRAM_WRITE", "BIOS_BOOT_WRITE"):
            with self.subTest(action=kind):
                self.proposal["proposedOperations"] = [
                    {
                        "kind": kind,
                        "partitionNumber": 1,
                        "origin": "STATIC_CODE_REFERENCE_ONLY",
                    }
                ]
                self.rejected("E_UNAUTHORIZED_BOOTLOADER_ACTION")

    def test_no_secure_boot_permission_in_this_scenario(self):
        self.plan["runtime"]["secureBootEnabled"] = True
        self.rejected("E_SECURE_BOOT_UNPROVEN")

    def test_no_bios_mbr_claim_via_shared_plan(self):
        self.plan["firmware"] = "bios"
        self.rejected("E_SHARED_PLAN_SCHEMA")

    def test_rejects_missing_authentication_fields(self):
        self.proposal["provenance"]["sharedPlanSignatureAuthenticated"] = True
        self.rejected("E_HANDOFF_SCHEMA")

    def test_rejects_attempted_grant(self):
        self.proposal["authorization"] = "ALLOW"
        self.rejected("E_HANDOFF_SCHEMA")

    def test_rejects_native_installer_claim(self):
        self.proposal["nativeInstallerInvoked"] = True
        self.rejected("E_HANDOFF_SCHEMA")

    def test_rejects_rw_disk_descriptor(self):
        rw = os.open(self.path, os.O_RDWR)
        try:
            with self.assertRaises(UbiquityHandoffDenied) as caught:
                validate_ubiquity_handoff(
                    self.proposal, self.plan, self.snapshot, rw
                )
            self.assertEqual(caught.exception.reason, "E_GPT_GEOMETRY_MISMATCH")
        finally:
            os.close(rw)


if __name__ == "__main__":
    unittest.main()
