"""Fail-closed tests for independent Mint COW firstboot evidence validation."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import validate_mint_cow_boot_evidence as validator


ROOT_UUID = "12345678-1234-4234-8234-123456789abc"
PROFILE = "win10_22h2_en_us_x64"
FOURTH_SERIAL = (
    b'BdsDxe: starting Boot0001 "Windows Boot Manager"\n'
    + b"GASLUX_COW_WIN10_REBOOT_LIVE=1\n"
    + b"GASLUX_COW_WIN10_REBOOT_BUILD=19045\n"
    + b"GASLUX_COW_WIN10_REBOOT_ESP=1\n"
    + b"GASLUX_COW_WIN10_REBOOT_BCD=1\n"
    + b"GASLUX_COW_WIN10_REBOOT_WINRE=1\n"
    + b"GASLUX_COW_WIN10_REBOOT_FIFTH_GPT=1\n"
)
SERIAL = (
    b"Linux version 6.14.0-generic (builder)\n"
    + f"Kernel command line: root=UUID={ROOT_UUID} rw rootwait console=ttyS0,115200n8\n".encode()
    + b"systemd[1]: Reached target Multi-User System.\n"
    + b"GASLUXMINT login:\n"
    + b"systemd-shutdown[1]: Powering off.\n"
)


class MintCowBootEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.proof = {
            "mintIsoSha256": validator.MINT_SHA256,
            "mintIsoBytes": validator.MINT_BYTES,
            "mintRootUuid": ROOT_UUID,
            "mintKernel": "vmlinuz-6.14.0-24-generic",
            "mintSquashfsRootCopiedToWindowsCOWPartition5": True,
            "mintFirstBootFromSameWindowsCOWVerified": True,
            "windowsFourPartitionSha256Unchanged": True,
            "windowsPartitionSha256": ["a" * 64, "b" * 64, "c" * 64, "d" * 64],
            "windowsBackingQcow2Unchanged": True,
            "windowsBackingQcow2Sha256": "e" * 64,
            "windowsOriginalNvramUnchanged": True,
            "windowsOriginalNvramSha256": "f" * 64,
            "windowsOvmfTrialVarsSha256": "1" * 64,
            "mintSerialSha256": hashlib.sha256(SERIAL).hexdigest(),
            "nativeGrubDualBootVerified": False,
            "sameDiskDualBootVerified": False,
            "updatesVerified": False,
            "rollbackVerified": False,
            "releaseEligible": False,
        }
        self._write_evidence()

    def tearDown(self):
        self.temp.cleanup()

    def _write_evidence(self):
        serial_hash = hashlib.sha256(SERIAL).hexdigest()
        proof_bytes = (json.dumps(self.proof, sort_keys=True, indent=2) + "\n").encode()
        (self.directory / "mint-same-windows-cow.json").write_bytes(proof_bytes)
        (self.directory / "mint-same-windows-cow-serial.log").write_bytes(SERIAL)
        (self.directory / "mint-same-windows-cow-serial.sha256").write_text(
            f"{serial_hash}  mint-same-windows-cow-serial.log\n", encoding="ascii")
        fourth_digest = hashlib.sha256(FOURTH_SERIAL).hexdigest()
        fourth = {
            "windowsBootAfterExt4Verified": True,
            "windowsBcdWinreEspAfterExt4Verified": True,
            "fourthGuestCleanShutdownVerified": True,
            "fourthGuestSerialSha256": fourth_digest,
            "fifthExt4UuidSurvivedWindowsBoot": True,
            "windowsGptUnchangedAfterExt4Boot": True,
            "windowsBackingUnchangedAfterExt4Boot": True,
            "originalWindowsUefiUnchangedAfterExt4Boot": True,
            "sameDiskDualBootVerified": False,
            "rollbackProven": False,
            "releaseEligible": False,
            "storageWritesAuthorized": False,
            "windowsRecoveryAfterLinuxVerified": False,
        }
        fourth_bytes = (json.dumps(fourth, sort_keys=True, indent=2) + "\n").encode()
        (self.directory / f"{PROFILE}-fourth-post-ext4.json").write_bytes(fourth_bytes)
        (self.directory / f"{PROFILE}-fourth-boot-serial.log").write_bytes(FOURTH_SERIAL)
        (self.directory / f"{PROFILE}-fourth-boot-serial.sha256").write_text(
            f"{fourth_digest}  {PROFILE}-fourth-boot-serial.log\n", encoding="ascii")
        report = {
            "windowsBootAfterExt4Verified": True,
            "thirdBootBcdWinreEspVerified": True,
            "fourthPostExt4EvidenceSha256": hashlib.sha256(fourth_bytes).hexdigest(),
            "mintSquashfsRootCopiedIntoWindowsCow": True,
            "mintFirstBootFromSameWindowsCowVerified": True,
            "windowsBootAfterMintRootVerified": True,
            "sameDiskBothOperatingSystemsBootVerified": True,
            "mintCowEvidenceSha256": hashlib.sha256(proof_bytes).hexdigest(),
            "nativeGrubDualBootVerified": False,
            "sameDiskDualBootVerified": False,
            "updatesVerified": False,
            "rollbackVerified": False,
        }
        (self.directory / f"{PROFILE}-result.json").write_text(
            json.dumps(report), encoding="utf-8")

    def test_accepts_bound_direct_kernel_boot_and_shutdown_evidence(self):
        result = validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)
        self.assertEqual(result["rootUuid"], ROOT_UUID)
        self.assertFalse(result["nativeGrubDualBootVerified"])
        self.assertFalse(result["updatesVerified"])
        self.assertFalse(result["rollbackVerified"])

    def test_rejects_missing_fourth_windows_efi_bcd_winre_proof(self):
        (self.directory / f"{PROFILE}-fourth-post-ext4.json").unlink()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "missing evidence file"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_changed_fourth_windows_proof_digest(self):
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["fourthPostExt4EvidenceSha256"] = "0" * 64
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "not bound to"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_efi_bcd_winre_failure_even_if_fourth_proof_is_rehashed(self):
        fourth_path = self.directory / f"{PROFILE}-fourth-post-ext4.json"
        fourth = json.loads(fourth_path.read_text())
        fourth["windowsBcdWinreEspAfterExt4Verified"] = False
        fourth_bytes = (json.dumps(fourth, sort_keys=True, indent=2) + "\n").encode()
        fourth_path.write_bytes(fourth_bytes)
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["fourthPostExt4EvidenceSha256"] = hashlib.sha256(fourth_bytes).hexdigest()
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "guest/ESP/BCD/WinRE"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_missing_guest_winre_marker(self):
        self._replace_fourth_serial(FOURTH_SERIAL.replace(
            b"GASLUX_COW_WIN10_REBOOT_WINRE=1\\n", b""))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "unique ESP/BCD/WinRE"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_duplicate_guest_esp_marker(self):
        self._replace_fourth_serial(
            FOURTH_SERIAL + b"GASLUX_COW_WIN10_REBOOT_ESP=1\\n")
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "unique ESP/BCD/WinRE"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_guest_audit_failure_even_with_all_markers(self):
        self._replace_fourth_serial(
            FOURTH_SERIAL + b"GASLUX_COW_WIN10_REBOOT_FAIL=1\\n")
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "audit failure"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_unbound_fourth_serial_hash(self):
        path = self.directory / f"{PROFILE}-fourth-boot-serial.log"
        path.write_bytes(FOURTH_SERIAL + b"tampering\\n")
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "digest disagrees"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def _replace_fourth_serial(self, serial: bytes) -> None:
        digest = hashlib.sha256(serial).hexdigest()
        (self.directory / f"{PROFILE}-fourth-boot-serial.log").write_bytes(serial)
        (self.directory / f"{PROFILE}-fourth-boot-serial.sha256").write_text(
            f"{digest}  {PROFILE}-fourth-boot-serial.log\\n", encoding="ascii")
        fourth_path = self.directory / f"{PROFILE}-fourth-post-ext4.json"
        fourth = json.loads(fourth_path.read_text())
        fourth["fourthGuestSerialSha256"] = digest
        fourth_bytes = (json.dumps(fourth, sort_keys=True, indent=2) + "\\n").encode()
        fourth_path.write_bytes(fourth_bytes)
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["fourthPostExt4EvidenceSha256"] = hashlib.sha256(fourth_bytes).hexdigest()
        report_path.write_text(json.dumps(report))

    def test_rejects_missing_serial_login(self):
        self._replace_serial(SERIAL.replace(b"GASLUXMINT login:", b""))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "serial login prompt"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_serial_root_uuid_mismatch_even_with_updated_hashes(self):
        serial = SERIAL.replace(ROOT_UUID.encode(), b"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        self._replace_serial(serial)
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "authenticated root UUID"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_false_native_grub_claim(self):
        self.proof["nativeGrubDualBootVerified"] = True
        self._write_evidence()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "overstates"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_missing_windows_partition_hashes(self):
        self.proof["windowsPartitionSha256"] = ["a" * 64, "b" * 64]
        self._write_evidence()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "four Windows partition"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_report_without_windows_reboot_after_mint(self):
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["windowsBootAfterMintRootVerified"] = False
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "independent Windows reboot"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_wrong_pinned_iso(self):
        self.proof["mintIsoSha256"] = "0" * 64
        self._write_evidence()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "pinned ISO"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_legacy_misleading_installation_field(self):
        self.proof["mintInstalledIntoWindowsCOWPartition5"] = True
        self._write_evidence()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "legacy installation claim"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_report_not_bound_to_proof(self):
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["mintCowEvidenceSha256"] = "0" * 64
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "does not bind"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_symlinked_proof(self):
        proof_path = self.directory / "mint-same-windows-cow.json"
        content = proof_path.read_bytes()
        proof_path.unlink()
        target = self.directory / "proof-target.json"
        target.write_bytes(content)
        proof_path.symlink_to(target)
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "regular file"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def test_rejects_missing_orderly_shutdown(self):
        serial = SERIAL.replace(b"systemd-shutdown[1]: Powering off.\n", b"")
        self._replace_serial(serial)
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "orderly shutdown"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE)

    def _replace_serial(self, serial):
        serial_path = self.directory / "mint-same-windows-cow-serial.log"
        serial_path.write_bytes(serial)
        digest = hashlib.sha256(serial).hexdigest()
        self.proof["mintSerialSha256"] = digest
        proof_bytes = (json.dumps(self.proof, sort_keys=True, indent=2) + "\n").encode()
        (self.directory / "mint-same-windows-cow.json").write_bytes(proof_bytes)
        (self.directory / "mint-same-windows-cow-serial.sha256").write_text(
            f"{digest}  mint-same-windows-cow-serial.log\n", encoding="ascii")
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["mintCowEvidenceSha256"] = hashlib.sha256(proof_bytes).hexdigest()
        report_path.write_text(json.dumps(report), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
