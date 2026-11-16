"""Synthetic fixtures only: never proof of a real dual boot."""
from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parent / "tools/verify_windows_guest_recovery.py"
SPEC = importlib.util.spec_from_file_location("gaslux_windows_proof", FILE)
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)

MIB = 1024 * 1024
GIB = 1024 * MIB
WIN = "11111111-2222-3333-4444-555555555555"
ESP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RECOVERY = "12345678-1234-1234-1234-123456789abc"
EXTRA = "f1234567-1111-2222-3333-444444444444"
LINUX = "87654321-abcd-abcd-abcd-abcdef123456"


def part(guid, number, offset, size, kind, *, boot=False, system=False):
    return {
        "guid": guid, "number": number, "offset": offset, "size": size,
        "gptType": kind, "isBoot": boot, "isSystem": system,
    }


def baseline():
    esp_type = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    data_type = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
    system = {
        "id": "windows-gpt-disk-id", "size": 256 * GIB,
        "logicalSectorSize": 512, "partitionStyle": "GPT",
        "partitions": [
            part(ESP, 1, MIB, 100 * MIB, esp_type, system=True),
            part(WIN, 2, 117 * MIB, 200 * GIB, data_type, boot=True),
            part(RECOVERY, 3, 220 * GIB, GIB,
                 "de94bba4-06d1-4d40-a16a-bfd50179d6ac"),
        ],
    }
    foreign = {
        "id": "second-disk-with-ntfs-data", "size": 128 * GIB,
        "logicalSectorSize": 4096, "partitionStyle": "GPT",
        "partitions": [part(EXTRA, 1, MIB, 50 * GIB, data_type)],
    }
    return {
        "schemaVersion": 1,
        "source": "gaslux-windows-guest-readonly-v1",
        "phase": "baseline",
        "runId": "vm-run-12345",
        "capturedAt": "2026-11-16T15:00:00+00:00",
        "computerName": "DISPOSABLE-WIN11",
        "windowsVersion": "10.0.22631",
        "windowsBootTime": "2026-11-16T14:00:00+00:00",
        "windowsDiskId": system["id"], "windowsPartitionGuid": WIN,
        "espPartitionGuid": ESP, "windowsEfiSha256": "a" * 64,
        "secureBootEnabled": False, "winreEnabled": True,
        "winreRaw": "Windows RE status: Enabled",
        "bcdCurrentRaw": "Windows Boot Loader \\Windows\\system32\\winload.efi",
        "bcdAllRaw": "Windows Boot Manager and \\Windows\\system32\\winload.efi",
        "firmwareRaw": "Windows Boot Manager \\EFI\\Microsoft\\Boot\\bootmgfw.efi",
        "bitlocker": {
            "protectionStatus": "Off", "volumeStatus": "FullyDecrypted",
            "encryptionPercentage": 0,
        },
        "disks": [system, foreign],
    }


def observed(mode):
    doc = copy.deepcopy(baseline())
    doc["phase"] = mode
    doc["capturedAt"] = "2026-11-16T17:00:00+00:00"
    doc["windowsBootTime"] = "2026-11-16T16:00:00+00:00"
    if mode == "postinstall":
        windows = doc["disks"][0]["partitions"][1]
        windows["size"] = 150 * GIB
        doc["disks"][0]["partitions"].append(
            part(
                LINUX, 4, windows["offset"] + windows["size"], 50 * GIB,
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
            )
        )
        doc["firmwareRaw"] += "\nGaslux Linux"
    return doc


class WindowsRecoveryFixtureTests(unittest.TestCase):
    def rejected(self, mutate, mode="postinstall", message=None):
        old, new = baseline(), observed(mode)
        mutate(old, new)
        with self.assertRaises(verify.EvidenceError) as raised:
            verify.compare(old, new, mode)
        if message:
            self.assertIn(message, str(raised.exception))

    def test_postinstall_fixture_is_never_full_dualboot_proof(self):
        result = verify.compare(baseline(), observed("postinstall"), "postinstall")
        self.assertTrue(result["checked"])
        self.assertEqual(result["newPartitionCount"], 1)
        self.assertFalse(result["linuxBootVerified"])
        self.assertFalse(result["stable"])
        self.assertFalse(result["proxmoxSnapshotVerified"])
        self.assertFalse(result["reviewerSigned"])

    def test_exact_rollback_fixture(self):
        result = verify.compare(baseline(), observed("rollback"), "rollback")
        self.assertTrue(result["diskGeometryChecked"])

    def test_windows_efi_loader_hash_changed(self):
        self.rejected(lambda a, b: b.update(windowsEfiSha256="b" * 64),
                      message="windowsEfiSha256")

    def test_winre_disabled(self):
        self.rejected(lambda a, b: b.update(winreEnabled=False), message="WinRE")

    def test_bcd_current_tampered(self):
        self.rejected(lambda a, b: b.update(bcdCurrentRaw="modified winload.efi"),
                      message="bcdCurrentRaw")

    def test_bitlocker_status_changed(self):
        self.rejected(lambda a, b: b["bitlocker"].update(protectionStatus="On"),
                      message="bitlocker")

    def test_secure_boot_enabled_is_rejected(self):
        self.rejected(lambda a, b: b.update(secureBootEnabled=True),
                      message="Secure Boot")

    def test_no_independently_observed_reboot(self):
        self.rejected(lambda a, b: b.update(windowsBootTime=a["windowsBootTime"]),
                      message="reboot")

    def test_recovery_partition_deleted(self):
        self.rejected(lambda a, b: b["disks"][0]["partitions"].pop(2),
                      message="removed")

    def test_recovery_partition_moved(self):
        self.rejected(lambda a, b: b["disks"][0]["partitions"][2].update(offset=222 * GIB))

    def test_esp_guid_modified(self):
        self.rejected(lambda a, b: b.update(espPartitionGuid=LINUX))

    def test_wrong_target_disk(self):
        self.rejected(lambda a, b: b.update(windowsDiskId="wrong-disk"))

    def test_foreign_data_disk_modified(self):
        self.rejected(lambda a, b: b["disks"][1]["partitions"][0].update(size=49 * GIB),
                      message="foreign")

    def test_foreign_disk_removed(self):
        self.rejected(lambda a, b: b["disks"].pop(), message="disk inventory")

    def test_linux_partition_outside_shrink_region(self):
        self.rejected(
            lambda a, b: b["disks"][0]["partitions"][-1].update(
                offset=221 * GIB, size=1 * GIB
            ),
            message="authorized",
        )

    def test_missing_linux_partition(self):
        self.rejected(lambda a, b: b["disks"][0]["partitions"].pop(),
                      message="no Linux")

    def test_windows_root_moved(self):
        self.rejected(
            lambda a, b: b["disks"][0]["partitions"][1].update(offset=118 * MIB),
            message="Windows",
        )

    def test_invalid_logical_sector_size(self):
        self.rejected(lambda a, b: b["disks"][0].update(logicalSectorSize=520),
                      message="sector")

    def test_partial_rollback_partition_left_behind(self):
        self.rejected(
            lambda a, b: b["disks"][0]["partitions"].append(
                part(LINUX, 4, 204 * GIB, GIB,
                     "0fc63daf-8483-4772-8e79-3d69d8477de4")
            ),
            mode="rollback", message="rollback",
        )

    def test_rollback_firmware_entry_not_restored(self):
        self.rejected(
            lambda a, b: b.update(firmwareRaw=b["firmwareRaw"] + "\nrogue"),
            mode="rollback", message="firmwareRaw",
        )

    def test_unexpected_evidence_field_is_not_accepted(self):
        self.rejected(lambda a, b: b.update(fakeSuccess=True), message="fields")

    def test_forged_fixture_source_is_not_accepted(self):
        self.rejected(lambda a, b: b.update(source="fixture"), message="guest collector")


if __name__ == "__main__":
    unittest.main()
