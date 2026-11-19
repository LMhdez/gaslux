"""Synthetic-only fail-closed System76 6-GPT handoff candidate contracts.

No media, VM, disk read, formatting, distinst invocation, boot or rollback.
"""
from __future__ import annotations

import copy
import pathlib
import sys
import unittest
import uuid

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE / "tools"))

from test_windows10_popos_independent_esp_root_stage import staged_fixture
from windows_x64_installed_gpt_ro_audit import DiskAuditError
from windows10_popos_native_readonly_handoff_candidate import (
    LAB_VIRTIO_SERIAL, preview_native_handoff,
)


def fixtures():
    _, _, _, _, before, after, plan = staged_fixture()
    media = {
        "upstreamId": "pop",
        "version": "24.04",
        "variant": "intel",
        "isoSha256": "a" * 64,
        "distinstSha256": "b" * 64,
        # Only a mock claim used to exercise the pure validator. A real ISO
        # signature MUST be verified independently before any guest handoff.
        "officialIsoSignedMetadataVerified": True,
    }
    guest = {
        "hostedDisposableVm": True,
        "qcow2ChildOnly": True,
        "windowsBackingWritable": False,
        "firmware": "uefi",
        "partitionStyle": "gpt",
        "secureBootEnabled": False,
        "diskSerial": LAB_VIRTIO_SERIAL,
        "diskGuid": before["diskGuid"],
        "partitionEntries": [
            {
                "index": item["number"],
                "guid": item["guid"],
                "typeGuid": item["type"],
                "firstLba": item["startLba"],
                "lastLba": item["endLba"],
            }
            for item in after["windowsPartitions"] + [after["popEsp"], after["linuxRoot"]]
        ],
        "popEspFilesystem": None,
        "popRootFilesystem": None,
        "windowsEspMounted": False,
        "windowsNtfsMounted": False,
        "networkAttached": False,
        "efiVariablesWritable": False,
    }
    return before, after, plan, media, guest


class NativePopSharedDiskHandoffCandidate(unittest.TestCase):
    def test_exact_six_gpt_claim_has_only_inert_owned_partition_selectors(self):
        before, after, plan, media, guest = fixtures()
        candidate = preview_native_handoff(before, after, plan, media, guest)
        self.assertEqual(candidate["protectedWindowsPartitionIndexes"], [1, 2, 3, 4])
        self.assertEqual(candidate["ownedEsp"]["partitionIndex"], 5)
        self.assertEqual(candidate["ownedEsp"]["mount"], "/boot/efi")
        self.assertEqual(candidate["ownedEsp"]["mode"], "reuse")
        self.assertEqual(candidate["ownedRoot"]["partitionIndex"], 6)
        self.assertEqual(candidate["ownedRoot"]["intendedFilesystem"], "ext4")
        self.assertEqual(candidate["upstreamBootloaderUefi"], "systemd-boot")
        self.assertEqual(candidate["nativeBackend"], "system76")
        for key in ("authenticatedWindowsToLiveHandoffVerified",
                    "durableRecoveryCheckpointVerified",
                    "efiNvrAMWriteAuthorized",
                    "distinstExecutionAuthorized",
                    "productionInstallationAuthorized",
                    "popInstalled", "sameDiskDualBootVerified", "stable"):
            self.assertIs(candidate[key], False, key)
        self.assertNotIn("argv", candidate)
        self.assertNotIn("command", candidate)
        self.assertNotIn("formatDisk", candidate)

    def test_refuse_any_foreign_gpt_or_partition_identity(self):
        before, after, plan, media, guest = fixtures()
        for mutation in ("disk_guid", "windows_entry", "pop_esp_guid",
                         "pop_root_geometry", "unexpected_seventh", "observed_esp_guid"):
            with self.subTest(mutation=mutation):
                b, a, p, m, g = copy.deepcopy((before, after, plan, media, guest))
                if mutation == "disk_guid":
                    a["diskGuid"] = str(uuid.uuid4())
                elif mutation == "windows_entry":
                    a["windowsEntryHex"][0] = "ff" * 128
                elif mutation == "pop_esp_guid":
                    p["partitions"][0]["uniqueGuid"] = str(uuid.uuid4())
                elif mutation == "pop_root_geometry":
                    a["linuxRoot"]["endLba"] -= 1
                elif mutation == "unexpected_seventh":
                    g["partitionEntries"].append(copy.deepcopy(g["partitionEntries"][-1]))
                elif mutation == "observed_esp_guid":
                    g["partitionEntries"][4]["guid"] = str(uuid.uuid4())
                with self.assertRaises(DiskAuditError):
                    preview_native_handoff(b, a, p, m, g)

    def test_refuse_media_without_signed_identity_or_agent_digest(self):
        before, after, plan, media, guest = fixtures()
        mutations = {
            "upstreamId": "ubuntu",
            "version": "25.04",
            "variant": "nvidia",
            "officialIsoSignedMetadataVerified": False,
            "isoSha256": "bad-digest",
            "distinstSha256": "0" * 64,
        }
        for field, wrong in mutations.items():
            with self.subTest(field=field):
                m = dict(media)
                m[field] = wrong
                with self.assertRaises(DiskAuditError):
                    preview_native_handoff(before, after, plan, m, guest)

    def test_refuse_wrong_guest_secure_boot_or_foreign_mounts(self):
        before, after, plan, media, guest = fixtures()
        mutations = {
            "hostedDisposableVm": False,
            "qcow2ChildOnly": False,
            "windowsBackingWritable": True,
            "firmware": "bios",
            "partitionStyle": "mbr",
            "secureBootEnabled": True,
            "diskSerial": "SDA-ORDER-NOT-IDENTITY",
            "diskGuid": str(uuid.uuid4()),
            "popEspFilesystem": "vfat",
            "popRootFilesystem": "ext4",
            "windowsEspMounted": True,
            "windowsNtfsMounted": True,
            "networkAttached": True,
            "efiVariablesWritable": True,
        }
        for field, wrong in mutations.items():
            with self.subTest(field=field):
                g = copy.deepcopy(guest)
                g[field] = wrong
                with self.assertRaises(DiskAuditError):
                    preview_native_handoff(before, after, plan, media, g)

    def test_refuse_production_authorization_or_windows_esp_reuse(self):
        before, after, plan, media, guest = fixtures()
        for field, wrong in (
            ("productionInstallationAuthorized", True),
            ("windowsEspToRemainUntouched", False),
            ("windowsBootManagerToRemainUntouched", False),
            ("firmware", "bios"),
            ("partitionStyle", "mbr"),
        ):
            with self.subTest(field=field):
                p = copy.deepcopy(plan)
                p[field] = wrong
                with self.assertRaises(DiskAuditError):
                    preview_native_handoff(before, after, p, media, guest)


if __name__ == "__main__":
    unittest.main()
