"""Fail-closed tests for genuine Zorin root on verified Windows 10 COW."""
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
SERIAL = (
    b"Linux version 6.14.0-generic (builder)\n"
    + f"Kernel command line: root=UUID={ROOT_UUID} rw rootwait console=ttyS0,115200n8\n".encode()
    + b"systemd[1]: Reached target Multi-User System.\n"
    + b"GASLUXZORIN login:\n"
    + b"systemd-shutdown[1]: Powering off.\n"
)


class ZorinCowBootEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.proof = {
            "zorinIsoSha256": validator.ZORIN_SHA256,
            "zorinIsoBytes": validator.ZORIN_BYTES,
            "zorinRootUuid": ROOT_UUID,
            "zorinKernel": "vmlinuz-6.14.0-24-generic",
            "zorinSquashfsRootCopiedToWindowsCOWPartition5": True,
            "zorinFirstBootFromSameWindowsCOWVerified": True,
            "windowsFourPartitionSha256Unchanged": True,
            "windowsPartitionSha256": ["a" * 64, "b" * 64, "c" * 64, "d" * 64],
            "windowsBackingQcow2Unchanged": True,
            "windowsBackingQcow2Sha256": "e" * 64,
            "windowsOriginalNvramUnchanged": True,
            "windowsOriginalNvramSha256": "f" * 64,
            "windowsOvmfTrialVarsSha256": "1" * 64,
            "zorinSerialSha256": hashlib.sha256(SERIAL).hexdigest(),
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
        (self.directory / "zorin-same-windows-cow.json").write_bytes(proof_bytes)
        (self.directory / "zorin-same-windows-cow-serial.log").write_bytes(SERIAL)
        (self.directory / "zorin-same-windows-cow-serial.sha256").write_text(
            f"{serial_hash}  zorin-same-windows-cow-serial.log\n", encoding="ascii")
        report = {
            "zorinSquashfsRootCopiedIntoWindowsCow": True,
            "zorinFirstBootFromSameWindowsCowVerified": True,
            "windowsBootAfterZorinRootVerified": True,
            "sameDiskBothOperatingSystemsBootVerified": True,
            "zorinCowEvidenceSha256": hashlib.sha256(proof_bytes).hexdigest(),
            "nativeGrubDualBootVerified": False,
            "sameDiskDualBootVerified": False,
            "updatesVerified": False,
            "rollbackVerified": False,
        }
        (self.directory / f"{PROFILE}-result.json").write_text(
            json.dumps(report), encoding="utf-8")

    def test_accepts_bound_direct_kernel_boot_and_shutdown_evidence(self):
        result = validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")
        self.assertEqual(result["rootUuid"], ROOT_UUID)
        self.assertFalse(result["nativeGrubDualBootVerified"])
        self.assertFalse(result["updatesVerified"])
        self.assertFalse(result["rollbackVerified"])

    def test_rejects_missing_serial_login(self):
        self._replace_serial(SERIAL.replace(b"GASLUXZORIN login:", b""))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "serial login prompt"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_serial_root_uuid_mismatch_even_with_updated_hashes(self):
        serial = SERIAL.replace(ROOT_UUID.encode(), b"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        self._replace_serial(serial)
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "authenticated root UUID"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_false_native_grub_claim(self):
        self.proof["nativeGrubDualBootVerified"] = True
        self._write_evidence()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "overstates"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_missing_windows_partition_hashes(self):
        self.proof["windowsPartitionSha256"] = ["a" * 64, "b" * 64]
        self._write_evidence()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "four Windows partition"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_report_without_windows_reboot_after_zorin(self):
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["windowsBootAfterZorinRootVerified"] = False
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "independent Windows reboot"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_wrong_pinned_iso(self):
        self.proof["zorinIsoSha256"] = "0" * 64
        self._write_evidence()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "pinned ISO"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_legacy_misleading_installation_field(self):
        self.proof["zorinInstalledIntoWindowsCOWPartition5"] = True
        self._write_evidence()
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "legacy installation claim"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_report_not_bound_to_proof(self):
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["zorinCowEvidenceSha256"] = "0" * 64
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "does not bind"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_symlinked_proof(self):
        proof_path = self.directory / "zorin-same-windows-cow.json"
        content = proof_path.read_bytes()
        proof_path.unlink()
        target = self.directory / "proof-target.json"
        target.write_bytes(content)
        proof_path.symlink_to(target)
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "regular file"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def test_rejects_missing_orderly_shutdown(self):
        serial = SERIAL.replace(b"systemd-shutdown[1]: Powering off.\n", b"")
        self._replace_serial(serial)
        with self.assertRaisesRegex(validator.MintBootEvidenceError, "orderly shutdown"):
            validator.validate_mint_cow_boot_evidence(self.directory, PROFILE, distribution="zorin")

    def _replace_serial(self, serial):
        serial_path = self.directory / "zorin-same-windows-cow-serial.log"
        serial_path.write_bytes(serial)
        digest = hashlib.sha256(serial).hexdigest()
        self.proof["zorinSerialSha256"] = digest
        proof_bytes = (json.dumps(self.proof, sort_keys=True, indent=2) + "\n").encode()
        (self.directory / "zorin-same-windows-cow.json").write_bytes(proof_bytes)
        (self.directory / "zorin-same-windows-cow-serial.sha256").write_text(
            f"{digest}  zorin-same-windows-cow-serial.log\n", encoding="ascii")
        report_path = self.directory / f"{PROFILE}-result.json"
        report = json.loads(report_path.read_text())
        report["zorinCowEvidenceSha256"] = hashlib.sha256(proof_bytes).hexdigest()
        report_path.write_text(json.dumps(report), encoding="utf-8")




class ZorinOwnedRootContracts(unittest.TestCase):
    def test_extracted_relative_os_release_symlink_stays_inside_root(self):
        import windows_mint_overlay_root as ubuntu
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "usr/lib").mkdir(parents=True)
            (root / "usr/lib/os-release").write_text("ID=zorin\\n", encoding="utf-8")
            (root / "etc/os-release").symlink_to("../usr/lib/os-release")
            self.assertEqual(ubuntu.read_target_os_release(root), "ID=zorin\\n")

    def test_extracted_absolute_os_release_symlink_never_reads_host(self):
        import windows_mint_overlay_root as ubuntu
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "usr/lib").mkdir(parents=True)
            (root / "usr/lib/os-release").write_text("ID=zorin\\n", encoding="utf-8")
            (root / "etc/os-release").symlink_to("/usr/lib/os-release")
            self.assertEqual(ubuntu.read_target_os_release(root), "ID=zorin\\n")

    def test_extracted_os_release_symlink_must_not_escape_root(self):
        import windows_mint_overlay_root as ubuntu
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "etc/os-release").symlink_to("../../../../etc/os-release")
            with self.assertRaisesRegex(ubuntu.MintOverlayError, "escapes extracted root"):
                ubuntu.read_target_os_release(root)

    def test_extracted_os_release_broken_link_rejected(self):
        import windows_mint_overlay_root as ubuntu
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "etc/os-release").symlink_to("../usr/lib/missing")
            with self.assertRaisesRegex(ubuntu.MintOverlayError, "missing"):
                ubuntu.read_target_os_release(root)

    def test_unknown_distro_refused_before_touching_any_disk(self):
        import windows_mint_overlay_root as ubuntu
        with self.assertRaisesRegex(ubuntu.MintOverlayError, "unsupported Ubuntu-family"):
            ubuntu.install_mint_root_and_boot(
                overlay=Path("/does/not/exist"), base=Path("/does/not/exist"),
                nvram=Path("/does/not/exist"), workspace=Path("/does/not/exist"),
                ext4_proof={}, iso=Path("/does/not/exist"),
                evidence=Path("/does/not/exist"), distribution="cachyos",
            )

    def test_orphan_zorin_iso_cli_refused_before_windows_download(self):
        import windows_x64_tcg_firstboot as windows
        with self.assertRaisesRegex(SystemExit, "--zorin-iso requires"):
            windows.main(["--profile", PROFILE, "--fixture-only",
                          "--zorin-iso", "/missing/zorin.iso"])

    def test_zorin_root_cli_requires_all_windows_proof_gates(self):
        import windows_x64_tcg_firstboot as windows
        with self.assertRaisesRegex(SystemExit, "Zorin Windows COW root needs"):
            windows.main(["--profile", PROFILE, "--install-zorin-cow-root",
                          "--zorin-iso", "/missing/zorin.iso"])

    def test_zorin_root_cli_rejects_missing_separate_consent(self):
        import os
        import windows_x64_tcg_firstboot as windows
        from unittest.mock import patch
        consent = {
            "GASLUX_WINDOWS_COW_CHECKPOINT_CONSENT":
                "I_ACCEPT_GITHUB_HOSTED_POSTBOOT_OVERLAY_ONLY",
            "GASLUX_CACHYOS_OVERLAY_GPT_CONSENT":
                "I_ACCEPT_DISPOSABLE_QCOW2_OVERLAY_GPT_ONLY",
            "GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT":
                "I_ACCEPT_WINDOWS_GUEST_REBOOT_ON_PRIVATE_GPT_OVERLAY_ONLY",
            "GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT":
                "I_ACCEPT_EXT4_ONLY_FIFTH_PARTITION_ON_HOSTED_WIN10_COW",
            "GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT":
                "I_ACCEPT_WINDOWS_FOURTH_GUEST_ON_EXT4_ONLY_QCOW2_COW",
            "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
                "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
        }
        flags = ["--profile", PROFILE, "--accel", "kvm",
                 "--derived-no-prompt", "--two-stage-install-only",
                 "--prepare-owned-cow-checkpoint",
                 "--stage-cachyos-overlay-root-gpt-only",
                 "--verify-windows-reboot-with-fifth-gpt",
                 "--format-owned-fifth-ext4-only",
                 "--verify-windows-reboot-after-ext4",
                 "--install-zorin-cow-root", "--zorin-iso", "/missing/zorin.iso"]
        with patch.dict(os.environ, consent, clear=True):
            with self.assertRaisesRegex(SystemExit, "Zorin Windows COW root needs"):
                windows.main(flags)

    def test_zorin_cannot_claim_native_grub_or_rollback(self):
        from inspect import getsource
        import windows_mint_overlay_root as ubuntu
        body = getsource(ubuntu.install_mint_root_and_boot)
        self.assertIn('"nativeGrubDualBootVerified": False', body)
        self.assertIn('"sameDiskDualBootVerified": False', body)
        self.assertIn('"rollbackVerified": False', body)

if __name__ == "__main__":
    unittest.main()
