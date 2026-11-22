"""Offline adversarial preparation: never execute QEMU, GRUB or delete EFI."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import cachyos_grub_uefi_effects_offline as effects

REPO = Path(__file__).resolve().parents[1]
TX = "gaslux-synthetic-20261122"
SHA_A = hashlib.sha256(b"a").hexdigest()
SHA_B = hashlib.sha256(b"b").hexdigest()
SHA_C = hashlib.sha256(b"c").hexdigest()
WINDOWS = "/boot/efi/EFI/Microsoft/Boot/bootmgfw.efi"
FALLBACK = "/boot/efi/EFI/BOOT/BOOTX64.EFI"
OWNED = "/boot/efi/EFI/Gaslux-CachyOS/grubx64.efi"
ROOT = "/boot/grub/grub.cfg"

BASE = {
    "sampleId": "test-grub-effects-lab01",
    "transactionId": TX,
    "diskGuid": "d84daec5-2209-5df5-a10f-0327c8cbc278",
    "espPartuuid": "cbb3d10a-6881-5dc8-b976-20d2098756fa",
    "diskBytes": 64 * 1024 * 1024,
    "sectorBytes": 512,
    "espOffsetBytes": 2048 * 512,
    "espLengthBytes": 32768 * 512,
    "gptPrimarySha256": SHA_A,
    "gptBackupSha256": SHA_B,
    "pmbrSha256": SHA_C,
    "ovmfVarsSha256": SHA_A,
    "bootOrder": ["0001", "0002"],
    "bootNext": None,
    "files": {
        WINDOWS: {"sizeBytes": 100, "sha256": SHA_A},
        FALLBACK: {"sizeBytes": 100, "sha256": SHA_B},
        ROOT: {"sizeBytes": 100, "sha256": SHA_A},
    },
    "sectorSamples": {"2048": SHA_A, "2049": SHA_A, "30000": SHA_A, "0": SHA_A},
}


class GrubUefiEffectsOfflineTests(unittest.TestCase):
    def snapshots(self):
        return deepcopy(BASE), deepcopy(BASE)

    def diff(self, changes=None):
        before, after = self.snapshots()
        if changes is not None:
            changes(before, after)
        return effects.compare_synthetic_snapshots(before, after)

    def assert_violation(self, result, expected):
        self.assertIn(expected, " ".join(result["violations"]))
        self.assertFalse(result["syntheticSampledNoViolation"])
        self.assertFalse(result["authorization"])

    def owned_dir(self, root: Path, extra=False):
        efi = root / "EFI" / "Gaslux-CachyOS"
        efi.mkdir(parents=True)
        payloads = {".gaslux-owner": (TX + "\n").encode(),
                    "grubx64.efi": b"MZ-SYNTHETIC-GRUB-NOT-EXECUTABLE"}
        for name, data in payloads.items():
            (efi / name).write_bytes(data)
        expected = {
            k: {"sizeBytes": len(v), "sha256": hashlib.sha256(v).hexdigest()}
            for k, v in payloads.items()
        }
        if extra:
            (efi / "foreign-owned.efi").write_bytes(b"foreign")
        return efi, expected

    def test_grub_source_unpinned_no_execution_permission(self):
        result = effects.grub_source_readiness(REPO)
        self.assertEqual(result["status"],
                         "GRUB_VERSION_AND_SIGNED_BINARIES_UNPINNED")
        self.assertEqual(result["packageDependency"],
                         "grub (unversioned pacstrap package)")
        self.assertEqual(len(result["sourceGitBlobs"]), 4)
        for field in ("grubPackageVersion", "grubPackageSha256",
                      "grubExecutableSha256", "grubModulesSha256"):
            self.assertIsNone(result[field])
        for field in ("archPackageSignatureVerified",
                      "ovmfCodeIdentityVerified", "ovmfVarsCheckpointVerified",
                      "qcow2SnapshotRestorableVerified",
                      "physicalEspFdAuthenticated", "safetyApprovedToExecute",
                      "canRunGrubInstall", "authorization"):
            self.assertIs(result[field], False, field)

    def test_unchanged_synthetic_sample_never_proves_write_set(self):
        report = self.diff()
        self.assertEqual(report["status"], "SYNTHETIC_SAMPLED_EFFECTS_DENY_ONLY")
        self.assertEqual(report["changedFiles"], [])
        self.assertEqual(report["sampledChangedLbas"], [])
        self.assertEqual(report["violations"], [])
        self.assertTrue(report["syntheticSampledNoViolation"])
        for field in ("sectorCoverageComplete", "actualGrubInstallExecuted",
                      "grubVersionVerified", "grubEffectiveWriteSetProven",
                      "nvramPreservationIndependentlyProven",
                      "windowsProtectedFilesPreservedIndependently",
                      "authorization", "productionStorageWritesAuthorized",
                      "qemuBlkNodeToDiskAuthenticated"):
            self.assertFalse(report[field], field)

    def test_declared_owned_efi_file_and_linux_config_remain_deny_only(self):
        def change(_, b):
            b["files"][OWNED] = {"sizeBytes": 200, "sha256": SHA_C}
            b["files"][ROOT] = {"sizeBytes": 110, "sha256": SHA_B}
            b["sectorSamples"]["2049"] = SHA_B
        report = self.diff(change)
        self.assertTrue(report["syntheticSampledNoViolation"])
        self.assertEqual(report["sampledChangedLbas"], [2049])
        self.assertEqual({x["path"] for x in report["changedFiles"]},
                         {OWNED, ROOT})
        self.assertTrue(all(x["authorization"] is False
                            for x in report["changedFiles"]))
        self.assertFalse(report["grubEffectiveWriteSetProven"])

    def test_microsoft_efi_and_bcd_changes_denied(self):
        def change(_, b):
            b["files"][WINDOWS]["sha256"] = SHA_C
            b["files"]["/boot/efi/EFI/Microsoft/Boot/BCD"] = {
                "sizeBytes": 20, "sha256": SHA_A
            }
        report = self.diff(change)
        self.assert_violation(report, "PROTECTED_EFI_WRITE")
        self.assert_violation(report, "FOREIGN_OR_PROTECTED_ESP_WRITE")

    def test_fallback_oem_recovery_and_other_linux_esp_denied(self):
        for path in (FALLBACK, "/boot/efi/EFI/OEM/loader.efi",
                     "/boot/efi/EFI/Recovery/recovery.efi",
                     "/boot/efi/EFI/CachyOS/grubx64.efi"):
            with self.subTest(path=path):
                def change(_, b):
                    b["files"][path] = {"sizeBytes": 123, "sha256": SHA_C}
                report = self.diff(change)
                self.assert_violation(report, "FOREIGN_OR_PROTECTED_ESP_WRITE")

    def test_casefold_collision_in_fat_directory_denied(self):
        def change(_, b):
            b["files"]["/boot/efi/efi/gaslux-cachyos/GRUBX64.EFI"] = {
                "sizeBytes": 9, "sha256": SHA_C
            }
        self.assert_violation(self.diff(change), "EFI_CASEFOLD_COLLISION")

    def test_unexpected_root_update_denied(self):
        def change(_, b):
            b["files"]["/etc/secureboot/private.key"] = {
                "sizeBytes": 10, "sha256": SHA_C
            }
        self.assert_violation(self.diff(change), "UNEXPECTED_ROOT_WRITE")

    def test_bootorder_bootnext_and_ovmf_mutations_separately_denied(self):
        for key, value, issue in (
            ("bootOrder", ["0002", "0001"], "BOOTORDER_CHANGED"),
            ("bootNext", "0003", "BOOTNEXT_CHANGED"),
            ("ovmfVarsSha256", SHA_B, "OVMF_VARS_CHANGED"),
        ):
            with self.subTest(key=key):
                def change(_, b):
                    b[key] = value
                self.assert_violation(self.diff(change), issue)

    def test_gpt_primary_backup_and_pmbr_changes_denied(self):
        for key in ("gptPrimarySha256", "gptBackupSha256", "pmbrSha256"):
            with self.subTest(key=key):
                def change(_, b):
                    b[key] = SHA_C
                self.assert_violation(self.diff(change), "GPT_OR_PMBR_CHANGED")

    def test_changed_sector_beyond_esp_rejected_as_effect(self):
        def change(_, b):
            b["sectorSamples"]["0"] = SHA_C
        self.assert_violation(self.diff(change), "WRITE_OUTSIDE_DECLARED_ESP")

    def test_sector_coverage_different_is_not_proof(self):
        before, after = self.snapshots()
        del after["sectorSamples"]["2048"]
        with self.assertRaisesRegex(effects.EffectsRefused,
                                    "SECTOR_SAMPLE_COVERAGE_CHANGED"):
            effects.compare_synthetic_snapshots(before, after)

    def test_foreign_transaction_guid_partuuid_and_volume_rejected(self):
        for key, value in (
            ("transactionId", "different-source-20261122"),
            ("diskGuid", "d84daec5-2209-5df5-a10f-0327c8cbc279"),
            ("espPartuuid", "cbb3d10a-6881-5dc8-b976-20d2098756fb"),
            ("espOffsetBytes", 4096 * 512),
        ):
            with self.subTest(key=key):
                before, after = self.snapshots()
                after[key] = value
                with self.assertRaisesRegex(effects.EffectsRefused,
                                             "FOREIGN_CHECKPOINT"):
                    effects.compare_synthetic_snapshots(before, after)

    def test_metadata_and_path_traversal_rejected(self):
        for path in ("/boot/efi/EFI/../Microsoft/Boot/BCD",
                     "/boot/efi/EFI/BOOT/..",
                     "/boot/efi//EFI/BOOT/BOOTX64.EFI"):
            with self.subTest(path=path):
                before, after = self.snapshots()
                after["files"][path] = {"sizeBytes": 9, "sha256": SHA_A}
                with self.assertRaisesRegex(effects.EffectsRefused,
                                             "INVALID_FILE_INVENTORY"):
                    effects.compare_synthetic_snapshots(before, after)

    def test_no_forged_complete_coverage_field_accepted(self):
        before, after = self.snapshots()
        after["sectorCoverageComplete"] = True
        with self.assertRaisesRegex(effects.EffectsRefused,
                                     "SNAPSHOT_SCHEMA_INVALID"):
            effects.compare_synthetic_snapshots(before, after)

    def test_sha_and_lba_out_of_bounds_refused(self):
        for sector, digest in (("0x800", SHA_A), ("131072", SHA_A),
                               ("3000", "not-a-hash")):
            before, after = self.snapshots()
            before["sectorSamples"] = {sector: digest}
            after["sectorSamples"] = {sector: digest}
            with self.subTest(sector=sector):
                with self.assertRaisesRegex(effects.EffectsRefused,
                                             "INVALID_SECTOR_SAMPLES"):
                    effects.compare_synthetic_snapshots(before, after)

    def test_cleanup_exact_owned_inventory_is_still_no_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, expected = self.owned_dir(Path(tmp))
            before = {p.name: p.read_bytes() for p in directory.iterdir()}
            result = effects.preview_efi_cleanup_owned_files(directory, TX, expected)
            self.assertEqual(result["status"],
                             "OWNED_FILE_INVENTORY_MATCHES_DENY_ONLY")
            self.assertEqual(set(result["entries"]), set(expected))
            self.assertTrue(result["allExpectedChildrenEnumerated"])
            self.assertFalse(result["canDelete"])
            self.assertFalse(result["authorization"])
            self.assertFalse(result["deleteActionPresent"])
            self.assertEqual(before, {p.name: p.read_bytes()
                                      for p in directory.iterdir()})

    def test_cleanup_foreign_file_blocks_entire_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, expected = self.owned_dir(Path(tmp), extra=True)
            with self.assertRaisesRegex(effects.EffectsRefused,
                                         "FOREIGN_CHILD"):
                effects.preview_efi_cleanup_owned_files(directory, TX, expected)
            self.assertTrue((directory / "foreign-owned.efi").is_file())

    def test_cleanup_foreign_transaction_and_digest_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, expected = self.owned_dir(Path(tmp))
            with self.assertRaisesRegex(effects.EffectsRefused,
                                         "FOREIGN_TRANSACTION_MARKER"):
                effects.preview_efi_cleanup_owned_files(
                    directory, "different-source-20261122", expected)
            expected["grubx64.efi"]["sha256"] = SHA_A
            with self.assertRaisesRegex(effects.EffectsRefused,
                                         "OWNED_FILE_CONTENT_DIVERGED"):
                effects.preview_efi_cleanup_owned_files(directory, TX, expected)

    def test_cleanup_symlink_and_hardlink_foreign_children_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, expected = self.owned_dir(Path(tmp))
            original = directory / "grubx64.efi"
            original.unlink()
            original.symlink_to("/etc/hosts")
            with self.assertRaises(effects.EffectsRefused):
                effects.preview_efi_cleanup_owned_files(directory, TX, expected)
            self.assertTrue(original.is_symlink())
        with tempfile.TemporaryDirectory() as tmp:
            directory, expected = self.owned_dir(Path(tmp))
            duplicate = Path(tmp) / "other-hardlink.efi"
            os.link(directory / "grubx64.efi", duplicate)
            with self.assertRaisesRegex(effects.EffectsRefused,
                                         "FOREIGN_CHILD_TYPE_OWNER_OR_LENGTH"):
                effects.preview_efi_cleanup_owned_files(directory, TX, expected)

    def test_cleanup_subdirectory_or_root_not_declared_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, expected = self.owned_dir(Path(tmp))
            alien = directory / "otherdir"
            alien.mkdir()
            with self.assertRaisesRegex(effects.EffectsRefused,
                                         "FOREIGN_CHILD"):
                effects.preview_efi_cleanup_owned_files(directory, TX, expected)
            with self.assertRaisesRegex(effects.EffectsRefused,
                                         "NOT_THE_DECLARED"):
                effects.preview_efi_cleanup_owned_files(
                    Path(tmp).resolve(), TX, expected)

    def test_cleanup_missing_owner_marker_foreign_or_preexisting_directory_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, expected = self.owned_dir(Path(tmp))
            (directory / ".gaslux-owner").unlink()
            with self.assertRaisesRegex(effects.EffectsRefused,
                                         "FOREIGN_CHILD"):
                effects.preview_efi_cleanup_owned_files(directory, TX, expected)
            self.assertTrue((directory / "grubx64.efi").exists())


if __name__ == "__main__":
    unittest.main()
