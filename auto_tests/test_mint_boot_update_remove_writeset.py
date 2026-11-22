"""Mint/Zorin read-only boot maintenance and uninstall write-set negatives.

Tests import the actual diagnostic module; they do not invoke grub-install,
update-grub, apt, efibootmgr, bcdedit or any disk/image writer.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import mint_boot_update_remove_writeset as audit

REPOSITORY = Path(__file__).resolve().parents[1]
RUN_ID = "0123456789abcdef0123456789abcdef"


class ReadonlyMintBootWriteSet(unittest.TestCase):
    def test_exact_real_dev_sources_pinned_without_claiming_publisher_trust(self):
        proof = audit.audit_source_pins(REPOSITORY)
        self.assertTrue(proof["sourcePinned"], proof["issues"])
        self.assertFalse(proof["sourcePinsAreCryptographicPublisherSignatures"])
        self.assertEqual(set(proof["observedBlobIds"]), set(audit.PINNED_SOURCE_BLOBS))
        self.assertFalse(proof["productionWriteAuthorized"])
        self.assertFalse(proof["bootUpdateVerified"])

    def test_changed_writer_source_is_refused_even_when_required_tokens_remain(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            for name in audit.PINNED_SOURCE_BLOBS:
                copy = target / name
                copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPOSITORY / name, copy)
            original = audit.audit_source_pins(target)
            self.assertTrue(original["sourcePinned"], original["issues"])
            script = target / "assets/live/libertix-sync-efi.sh"
            script.write_bytes(script.read_bytes() + b"\n# synthetic unreviewed change\n")
            mutated = audit.audit_source_pins(target)
            self.assertFalse(mutated["sourcePinned"])
            self.assertTrue(any(
                issue["file"] == "assets/live/libertix-sync-efi.sh"
                and issue["reason"] == "source_git_blob_changed"
                for issue in mutated["issues"]
            ))
            script.unlink()
            script.symlink_to(REPOSITORY / "assets/live/libertix-sync-efi.sh")
            linked = audit.audit_source_pins(target)
            self.assertFalse(linked["sourcePinned"])
            self.assertTrue(any(
                issue["file"] == "assets/live/libertix-sync-efi.sh"
                for issue in linked["issues"]
            ))

    def test_all_known_scenarios_never_grant_boot_or_rollback_authority(self):
        for distro in ("mint", "zorin"):
            for fw in ("bios", "uefi"):
                for operation in ("install", "update", "uninstall"):
                    for preferred in (False, True):
                        if fw == "bios" and preferred:
                            continue
                        with self.subTest(distro=distro, fw=fw, op=operation, pref=preferred):
                            data = audit.classify_write_set(
                                firmware=fw, operation=operation,
                                preferred_active=preferred,
                            )
                            self.assertFalse(data["executeWrites"])
                            self.assertFalse(data["productionWriteAuthorized"])
                            self.assertFalse(data["bootUpdateVerified"])
                            self.assertFalse(data["windowsInPlaceRollbackProven"])
                            self.assertFalse(data["installedPackagesHooksExhaustivelyAudited"])
                            self.assertTrue(data["writeSet"])
                            self.assertTrue(all(not item["writeAuthorized"]
                                                for item in data["writeSet"]))

    def test_uefi_preferred_path_explicitly_includes_windows_boot_manager_files(self):
        ordinary = audit.classify_write_set(
            firmware="uefi", operation="update", preferred_active=False)
        exceptional = audit.classify_write_set(
            firmware="uefi", operation="update", preferred_active=True)
        windows = [entry for entry in exceptional["writeSet"]
                   if entry["impact"] == "WINDOWS_BOOT_CRITICAL"]
        self.assertEqual(len(windows), 5)
        self.assertTrue(any("bootmgfw.efi" in item["target"] for item in windows))
        self.assertFalse(any(e["impact"] == "WINDOWS_BOOT_CRITICAL"
                             for e in ordinary["writeSet"]))
        self.assertTrue(any(
            e["impact"] == "UNKNOWN_EXTERNAL_WRITER" for e in ordinary["writeSet"]))
        self.assertTrue(any("EFI/BOOT" in e["target"] for e in ordinary["writeSet"]))

    def test_uninstall_reports_bios_mbr_and_uefi_esp_firmware_and_windows_fallback(self):
        bios = audit.classify_write_set(
            firmware="bios", operation="uninstall", preferred_active=False)
        uefi = audit.classify_write_set(
            firmware="uefi", operation="uninstall", preferred_active=True)
        self.assertTrue(any("MBR/PBR" in e["target"] for e in bios["writeSet"]))
        self.assertTrue(any("BootNext" in e["target"] for e in uefi["writeSet"]))
        self.assertTrue(any(e["target"] == "ESP/EFI/Microsoft/Boot/*"
                            for e in uefi["writeSet"]))
        self.assertFalse(uefi["windowsBootAndRecoveryValidatedAfterAction"])

    def test_invalid_or_untrusted_classification_rejected(self):
        for kwargs in (
            {"firmware": "uefi", "operation": "upgrade", "preferred_active": False},
            {"firmware": "mbr", "operation": "update", "preferred_active": False},
            {"firmware": "bios", "operation": "update", "preferred_active": True},
            {"firmware": "uefi", "operation": "update", "preferred_active": "false"},
        ):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaises(audit.BootWriteSetError),
            ):
                audit.classify_write_set(**kwargs)


class ReadonlyEspTargets(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mint-writeset-no-disk-")
        self.addCleanup(self.temp.cleanup)
        self.esp = Path(self.temp.name) / "esp"
        (self.esp / "EFI/Libertix").mkdir(parents=True)
        (self.esp / "EFI/Microsoft/Boot").mkdir(parents=True)
        (self.esp / "EFI/BOOT").mkdir(parents=True)
        (self.esp / "EFI/Libertix/.libertix-owner").write_text(
            RUN_ID + "\nBoot0007\n", encoding="ascii")
        (self.esp / "EFI/Microsoft/Boot/bootmgfw.efi").write_bytes(b"MZ-windows-fixture")
        (self.esp / "EFI/Libertix/shimx64.efi").write_bytes(b"MZ-owned-fixture")

    def test_readonly_file_digests_do_not_mutate_esp(self):
        original = self.esp / "EFI/Microsoft/Boot/bootmgfw.efi"
        before = hashlib.sha256(original.read_bytes()).hexdigest()
        found = audit.inspect_esp_file(self.esp, "EFI/Microsoft/Boot/bootmgfw.efi")
        self.assertEqual(found["sha256"], before)
        self.assertEqual(found["status"], "OBSERVED_READONLY")
        self.assertFalse(found["sourceIdentityAndMountAuthenticated"])
        self.assertFalse(found["writeAuthorized"])
        snapshot = audit.audit_esp_snapshot(self.esp, RUN_ID)
        self.assertEqual(snapshot["status"], "READONLY_INVENTORY_ONLY")
        self.assertTrue(snapshot["markerMatchesRunId"])
        self.assertFalse(snapshot["markerAuthenticatesOwnership"])
        self.assertFalse(snapshot["actualEspMountVerified"])
        self.assertFalse(snapshot["productionWriteAuthorized"])
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), before)

    def test_foreign_or_missing_marker_never_claims_owned_esp(self):
        owner = self.esp / "EFI/Libertix/.libertix-owner"
        for data in (b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n", b"", b"not-an-owner\n"):
            with self.subTest(marker=data):
                owner.write_bytes(data)
                status = audit.audit_esp_snapshot(self.esp, RUN_ID)
                self.assertEqual(status["status"], "BLOCKED_EVIDENCE")
                self.assertFalse(status["markerMatchesRunId"])
                self.assertFalse(status["productionWriteAuthorized"])

    def test_ancestor_symlink_into_foreign_windows_directory_is_rejected(self):
        boot = self.esp / "EFI/Microsoft/Boot"
        foreign = Path(self.temp.name) / "foreign"
        foreign.mkdir()
        (foreign / "bootmgfw.efi").write_bytes(b"MZ-foreign")
        (boot / "bootmgfw.efi").unlink()
        boot.rmdir()
        boot.symlink_to(foreign, target_is_directory=True)
        with self.assertRaisesRegex(audit.BootWriteSetError, "symlink"):
            audit.inspect_esp_file(self.esp, "EFI/Microsoft/Boot/bootmgfw.efi")
        status = audit.audit_esp_snapshot(self.esp, RUN_ID)
        self.assertEqual(status["status"], "BLOCKED_EVIDENCE")
        self.assertFalse(status["productionWriteAuthorized"])

    def test_leaf_symlink_and_hardlink_denied_without_modifying_foreign_file(self):
        loader = self.esp / "EFI/Microsoft/Boot/bootmgfw.efi"
        foreign = Path(self.temp.name) / "foreign-loader"
        foreign.write_bytes(b"MZ-external")
        loader.unlink()
        loader.symlink_to(foreign)
        with self.assertRaises(audit.BootWriteSetError):
            audit.inspect_esp_file(self.esp, "EFI/Microsoft/Boot/bootmgfw.efi")
        loader.unlink()
        os.link(foreign, loader)
        with self.assertRaises(audit.BootWriteSetError):
            audit.inspect_esp_file(self.esp, "EFI/Microsoft/Boot/bootmgfw.efi")
        self.assertEqual(foreign.read_bytes(), b"MZ-external")

    def test_unsafe_relative_paths_and_unlisted_efi_files_are_rejected(self):
        for name in (
            "../EFI/Microsoft/Boot/bootmgfw.efi",
            "EFI/Microsoft/Boot/../../bootmgfw.efi",
            "EFI/Microsoft/Boot/BCD",
            "EFI/Libertix/../../bootmgfw.efi",
            "/etc/hosts",
            "EFI/BOOT/BOOTX64.EFI/../../Windows",
        ):
            with (
                self.subTest(path=name),
                self.assertRaisesRegex(audit.BootWriteSetError, "unrecognized"),
            ):
                audit.inspect_esp_file(self.esp, name)

    def test_missing_loader_or_untrusted_transaction_is_fail_closed(self):
        (self.esp / "EFI/Microsoft/Boot/bootmgfw.efi").unlink()
        status = audit.audit_esp_snapshot(self.esp, RUN_ID)
        self.assertEqual(status["status"], "BLOCKED_EVIDENCE")
        self.assertIn("windows_loader_absent_or_unsafe", status["issues"])
        with self.assertRaises(audit.BootWriteSetError):
            audit.audit_esp_snapshot(self.esp, "not-a-transaction")

    def test_esp_read_failure_remains_unverified(self):
        loader = self.esp / "EFI/Microsoft/Boot/bootmgfw.efi"
        original_read = audit.os.read

        def interrupted(fd, size):
            if os.fstat(fd).st_ino == loader.stat().st_ino:
                raise OSError(5, "synthetic input/output error")
            return original_read(fd, size)

        with patch.object(audit.os, "read", side_effect=interrupted):
            status = audit.audit_esp_snapshot(self.esp, RUN_ID)
        self.assertEqual(status["status"], "BLOCKED_EVIDENCE")
        self.assertFalse(status["productionWriteAuthorized"])


if __name__ == "__main__":
    unittest.main()
