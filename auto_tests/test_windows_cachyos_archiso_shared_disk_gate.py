"""No-guest Windows+CachyOS shared-GPT preflight contracts; zero disk access."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location(
    "cachyos_shared_gate", ROOT / "windows_cachyos_archiso_shared_disk_gate.py")
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SECTOR = 512
GIB = 1024**3
ISO = "a" * 64
PARTUUID = "01234567-89ab-4def-8012-123456789abc"
FSUUID = "59dd7982-58ab-4ade-8aab-445577889911"


def fixtures():
    starts = (2048, 534528, 567296, 30000000)
    ends = (534527, 567295, 29999999, 60000000)
    windows = [
        dict(index=i+1, type=gate.TYPES[i], firstLba=start,
             lastLba=end, lengthBytes=(end-start+1)*SECTOR)
        for i, (start, end) in enumerate(zip(starts, ends))
    ]
    root = {
        "index": 5, "typeGuid": gate.LINUX_TYPE, "uniqueGuid": PARTUUID,
        "firstLba": 60002304,
        "lastLba": 60002304 + 24*GIB//SECTOR-1,
        "lengthBytes": 24*GIB,
        "remainingUnallocatedAfterLinuxBytes": 25*GIB,
    }
    geometry = {
        "candidateWindowsGptPrimaryAndBackupConsistent": True,
        "virtualDiskBytes": 128*GIB, "sectorBytes": SECTOR,
        "windowsPartitions": windows, "diskGuidSha256": "b"*64,
        "storageWritesAuthorized": False, "releaseEligible": False,
    }
    cow = {
        "candidateWindowsCowCheckpointPrepared": True,
        "trialOverlayInitiallyMatchesWindows": True,
        "windowsBaselineUnchangedDuringCheckpoint": True,
        "snapshotIndependentlyRestorable": False,
        "storageWritesAuthorized": False, "releaseEligible": False,
    }
    stage = {
        "overlayGptLinuxRootEntryPrepared": True,
        "onlyDisposableOverlayModified": True,
        "windowsPartitionEntriesUnchanged": True,
        "bothGptMirrorsAfterStageVerified": True,
        "windowsBackingQcow2Unchanged": True,
        "windowsUefiVariablesUnchanged": True,
        "linuxRootFilesystemFormatted": False, "cachyosInstalled": False,
        "storageWritesAuthorized": False, "releaseEligible": False,
        "linuxRoot": root,
    }
    third = {
        "windowsBootAfterOverlayMutationVerified": True,
        "guestBcdWinreEspAfterOverlayVerified": True,
        "windowsGuestShutdownAfterOverlayVerified": True,
        "fifthGptUnchangedAfterGuestBoot": True,
        "windowsBackingUnchangedAfterGuestBoot": True,
        "originalUefiVarsUnchangedAfterGuestBoot": True,
        "sameDiskDualBootVerified": False, "releaseEligible": False,
    }
    ext4 = {
        "linuxRoot": deepcopy(root),
        "onlyOwnedOverlayFifthPartitionFormatted": True,
        "linuxRootFilesystemFormatted": True,
        "windowsBackingQcow2UnchangedAfterExt4": True,
        "windowsOriginalUefiUnchangedAfterExt4": True,
        "cachyosInstalled": False, "windowsRecoveryAfterLinuxVerified": False,
        "storageWritesAuthorized": False, "releaseEligible": False,
        "rootFilesystem": {
            "filesystemType": "ext4",
            "filesystemUuid": FSUUID,
            "allFourWindowsPartitionSha256Unchanged": True,
            "gptMirrorsByteIdenticalAfterExt4": True,
            "windowsFourPartitionSha256": ["c"*64, "d"*64, "e"*64, "f"*64],
        },
    }
    fourth = {
        "windowsBootAfterExt4Verified": True,
        "windowsBcdWinreEspAfterExt4Verified": True,
        "fourthGuestCleanShutdownVerified": True,
        "fifthExt4UuidSurvivedWindowsBoot": True,
        "windowsGptUnchangedAfterExt4Boot": True,
        "windowsBackingUnchangedAfterExt4Boot": True,
        "originalWindowsUefiUnchangedAfterExt4Boot": True,
        "cachyosInstalled": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "storageWritesAuthorized": False, "releaseEligible": False,
    }
    return geometry, cow, stage, third, ext4, fourth


class SharedDiskGateTests(unittest.TestCase):
    def call(self, items):
        return gate.candidate(*items, transaction="gaslux-vm-0123456789abcdef",
                              iso_sha256=ISO)

    def test_documentary_candidate_is_never_write_authority(self):
        result = self.call(fixtures())
        self.assertEqual(result["rootPartitionIndex"], 5)
        self.assertEqual(result["rootLengthBytes"], 24*GIB)
        self.assertEqual(result["rootPartitionGuid"], PARTUUID)
        self.assertEqual(result["rootFilesystemUuid"], FSUUID)
        for field in (
            "archisoGuestDiskIdentityVerified", "handoffAuthenticated",
            "archisoWriteAuthorized", "pacstrapExecuted", "cachyosInstalled",
            "linuxFirstBootVerified", "windowsRecoveryAfterLinuxVerified",
            "rollbackProven", "sameDiskDualBootVerified",
            "storageWritesAuthorized", "releaseEligible",
        ):
            self.assertIs(result[field], False, field)

    def test_rejects_modified_windows_partitions(self):
        for key, value in (
            ("type", "0fc63daf-8483-4772-8e79-3d69d8477de4"),
            ("index", 5), ("index", True),
            ("firstLba", 500), ("lastLba", 0),
            ("lengthBytes", 1),
        ):
            with self.subTest(key=key):
                x = fixtures()
                x[0]["windowsPartitions"][3][key] = value
                with self.assertRaises(gate.SharedDiskGateError):
                    self.call(x)

    def test_rejects_missing_windows_layout_or_release_falsehood(self):
        for pos, prop, bad in (
            (0, "candidateWindowsGptPrimaryAndBackupConsistent", False),
            (0, "diskGuidSha256", "invalid"),
            (0, "virtualDiskBytes", 64*GIB),
            (0, "sectorBytes", 4096),
            (0, "storageWritesAuthorized", True),
            (1, "trialOverlayInitiallyMatchesWindows", False),
            (1, "snapshotIndependentlyRestorable", True),
            (2, "bothGptMirrorsAfterStageVerified", False),
            (2, "cachyosInstalled", True),
            (3, "guestBcdWinreEspAfterOverlayVerified", False),
            (4, "windowsBackingQcow2UnchangedAfterExt4", False),
            (4, "storageWritesAuthorized", True),
            (5, "windowsBcdWinreEspAfterExt4Verified", False),
            (5, "originalWindowsUefiUnchangedAfterExt4Boot", False),
            (5, "releaseEligible", True),
        ):
            with self.subTest(pos=pos, prop=prop):
                x = fixtures()
                x[pos][prop] = bad
                with self.assertRaises(gate.SharedDiskGateError):
                    self.call(x)

    def test_rejects_root_extent_and_foreign_identity(self):
        for key, value in (
            ("index", 4), ("firstLba", 60000001), ("lastLba", 99999999),
            ("lengthBytes", 1), ("remainingUnallocatedAfterLinuxBytes", 0),
            ("remainingUnallocatedAfterLinuxBytes", "999999999999999999999"),
            ("typeGuid", gate.TYPES[0]), ("uniqueGuid", "00000000-0000-0000-0000-000000000000"),
        ):
            with self.subTest(key=key):
                x = fixtures()
                x[2]["linuxRoot"][key] = value
                x[4]["linuxRoot"] = deepcopy(x[2]["linuxRoot"])
                with self.assertRaises(gate.SharedDiskGateError):
                    self.call(x)

    def test_missing_ext4_uuid_and_sha_rejected(self):
        for prop, bad in (
            ("filesystemUuid", "not-an-uuid"),
            ("windowsFourPartitionSha256", ["bad"] * 4),
            ("allFourWindowsPartitionSha256Unchanged", False),
            ("gptMirrorsByteIdenticalAfterExt4", False),
        ):
            x = fixtures()
            x[4]["rootFilesystem"][prop] = bad
            with self.subTest(prop=prop), self.assertRaises(gate.SharedDiskGateError):
                self.call(x)

    def test_invalid_iso_pin_and_transaction_rejected(self):
        for iso, transaction in (
            ("deadbeef", "gaslux-vm-0123456789abcdef"),
            ("A"*64, "gaslux-vm-0123456789abcdef"),
            (ISO, "../../../"),
            (ISO, "test"),
        ):
            with self.subTest(iso=iso, transaction=transaction):
                with self.assertRaises(gate.SharedDiskGateError):
                    gate.candidate(*fixtures(), transaction=transaction, iso_sha256=iso)

    def test_pure_function_does_not_open_or_modify_disks(self):
        original = fixtures()
        snapshot = deepcopy(original)
        with patch("builtins.open", side_effect=AssertionError("Unexpected disk IO")):
            self.call(original)
        self.assertEqual(original, snapshot)
        src = (ROOT / "windows_cachyos_archiso_shared_disk_gate.py").read_text()
        for forbidden in (
            "pacstrap(", "sgdisk --clear", "mkfs(", "efibootmgr(",
            "subprocess", "os.open", "guestfs.GuestFS(", "shutil",
        ):
            self.assertNotIn(forbidden, src)


if __name__ == "__main__":
    unittest.main()
