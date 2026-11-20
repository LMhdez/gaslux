"""No guest/disk writes: CachyOS + Windows same-COW re-entry contracts."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import windows_cachyos_postpacstrap_windows as lab


def valid_pacstrap() -> dict:
    fields = (
        "rootWriteGrantIssued", "pacstrapExecuted", "labOnlyPacstrapCompleted",
        "cachyosRootPacstrapped", "nativeCachyOSOsReleaseVerified",
        "nativeKernelAndInitramfsPresent", "strictInstalledPacmanPolicyVerified",
        "minimalInstalledReadOnlyBootVerified",
        "installedWritableChildKernelAndSystemdBootVerified",
        "installedWritableChildSecondBootVerified",
        "installedWritableChildSecondBootPersistentMarkerVerified",
        "installedWritableChildOverlayDiscarded",
        "windowsGptUnchangedAfterPacstrap",
        "windowsProtectedHashesUnchangedAfterPacstrap",
        "windowsBaseSha256UnchangedAfterPacstrap",
        "originalWindowsUefiUnchangedAfterPacstrap",
    )
    status = {field: True for field in fields}
    status.update(
        installedWritableChildRunId="gaslux-test-txn",
        sameDiskDualBootVerified=False,
        windowsEspWritesAllowed=False,
        efiBootloaderInstalled=False,
        releaseEligible=False,
        productionStorageWritesAuthorized=False,
    )
    return status


def lab_env() -> dict:
    return {
        "GITHUB_ACTIONS": "true",
        "RUNNER_OS": "Linux",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": "LMhdez/gaslux",
        "GASLUX_CACHYOS_POST_PACSTRAP_WINDOWS_CONSENT": lab.CONSENT,
    }


FOURTH = {"windowsBootAfterExt4Verified": True,
          "windowsGptUnchangedAfterExt4Boot": True}
EXT4 = {"onlyOwnedOverlayFifthPartitionFormatted": True,
        "rootFilesystem": {"filesystemUuid": "01234567-89ab-4def-8123-123456789abc"}}


class PostPacstrapWindowsContracts(unittest.TestCase):
    def test_no_consent_rejects_before_any_disk_or_guest(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(lab, "validate_workspace",
                                   side_effect=AssertionError("disk touched")):
                with self.assertRaisesRegex(lab.PostPacstrapWindowsError,
                                            "separate disposable"):
                    lab.verify_windows_with_installed_root(
                        [], Path("/no-disk"), Path("/no-nvram"),
                        {}, {}, {}, {}, EXT4, FOURTH, valid_pacstrap())

    def test_incomplete_or_forged_proof_rejected_before_any_disk(self):
        with mock.patch.dict(os.environ, lab_env(), clear=True):
            for bad_key, value in (
                ("pacstrapExecuted", False),
                ("minimalInstalledReadOnlyBootVerified", False),
                ("installedWritableChildSecondBootVerified", False),
                ("windowsProtectedHashesUnchangedAfterPacstrap", False),
                ("windowsEspWritesAllowed", True),
                ("efiBootloaderInstalled", True),
                ("sameDiskDualBootVerified", True),
                ("releaseEligible", True),
                ("installedWritableChildRunId", None),
            ):
                pac = valid_pacstrap()
                pac[bad_key] = value
                with self.subTest(field=bad_key), \
                     mock.patch.object(lab, "validate_workspace",
                                       side_effect=AssertionError("disk touched")), \
                     self.assertRaises(lab.PostPacstrapWindowsError):
                    lab.verify_windows_with_installed_root(
                        [], Path("/no-disk"), Path("/no-nvram"),
                        {}, {}, {}, {}, EXT4, FOURTH, pac)

    def test_invalid_timeout_rejected_before_disk(self):
        with mock.patch.dict(os.environ, lab_env(), clear=True):
            with mock.patch.object(lab, "validate_workspace",
                                   side_effect=AssertionError("disk touched")):
                for timeout in (-1, 0, 120.0, 1801):
                    with self.subTest(timeout=timeout), \
                         self.assertRaises(lab.PostPacstrapWindowsError):
                        lab.verify_windows_with_installed_root(
                            [], Path("/no-disk"), Path("/no-nvram"),
                            {}, {}, {}, {}, EXT4, FOURTH,
                            valid_pacstrap(), timeout=timeout)

    def test_valid_prerequisites_do_not_claim_dual_boot(self):
        with mock.patch.dict(os.environ, lab_env(), clear=True):
            self.assertEqual(lab.preflight(valid_pacstrap(), FOURTH, EXT4),
                             EXT4["rootFilesystem"]["filesystemUuid"])
            with mock.patch.object(lab, "validate_workspace",
                                   side_effect=RuntimeError("disk access intentionally stopped")):
                with self.assertRaisesRegex(RuntimeError, "intentionally stopped"):
                    lab.verify_windows_with_installed_root(
                        [], Path("/no-disk"), Path("/no-nvram"),
                        {}, {}, {}, {}, EXT4, FOURTH, valid_pacstrap())

    def test_signed_plan_symlink_denied_without_invoking_openssl(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            (workspace / "cachyos-root-write-handoff").symlink_to(workspace)
            with mock.patch.object(lab.subprocess, "run") as command, \
                 self.assertRaises(lab.PostPacstrapWindowsError):
                lab.signed_lab_plan(workspace, "0" * 36, "gaslux-test-txn")
            command.assert_not_called()

    def test_distinct_serial_and_discard_order_are_enforced_in_source(self):
        post = (TOOLS / "windows_cachyos_postext4_windows.py").read_text()
        orchestrator = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        helper = (TOOLS / "windows_cachyos_postpacstrap_windows.py").read_text()
        self.assertIn('"sixth-post-pacstrap"', post)
        self.assertIn('evidence_stem="sixth-post-pacstrap"', helper)
        self.assertLess(orchestrator.index("verify_windows_with_installed_root("),
                        orchestrator.index("verify_discard_postext4_cow("))
        self.assertIn('side_by_side["failureType"]', orchestrator)
        self.assertIn('"sameDiskDualBootVerified": False', helper)
        self.assertIn('"cachyosBootloaderInstalledToWindowsEsp": False', helper)
        self.assertNotIn("sgdisk --clear", helper)
        self.assertNotIn("mkfs", helper)
        self.assertNotIn("grub-install", helper)


    def test_postboot_gpt_or_protected_windows_hash_change_still_fails_closed(self):
        # No block devices, guestfs, KVM or Windows installation: all mocked.
        with tempfile.TemporaryDirectory(prefix="gaslux-win10-reentry-contract-") as td:
            root = Path(td)
            base = root / "only-disposable-windows-target.qcow2"
            nvram = root / "ovmf-variables.fd"
            checkpoint = root / lab.CHECKPOINT_DIR
            checkpoint.mkdir()
            overlay = checkpoint / lab.OVERLAY_NAME
            for path in (base, nvram, overlay):
                path.write_bytes(b"private-synthetic-lab-file")
            base.chmod(0o400)
            overlay.chmod(0o600)
            (root / "sixth-post-pacstrap-windows-serial.log").write_bytes(
                b"synthetic serial (NOT a Windows boot proof)")
            front, back = b"synthetic-gpt-primary", b"synthetic-gpt-backup"
            original_hashes = {
                "espBootManagerSha256": "a" * 64,
                "espBcdSha256": "b" * 64,
                "windowsLoaderSha256": "c" * 64,
                "winreImageSha256": "d" * 64,
            }
            plan = {
                "runId": "gaslux-test-txn",
                "gptWindowsSha256": hashlib.sha256(front + back).hexdigest(),
                "windowsHashes": original_hashes,
            }
            for tamper, error in (
                ("gpt", "primary or backup GPT bytes changed"),
                ("windows_files", "espBcdSha256"),
                ("none", None),
            ):
                gpt_reads = [
                    (front, back),
                    (front + b"-tampered", back) if tamper == "gpt" else (front, back),
                ]
                file_reads = [
                    original_hashes,
                    {**original_hashes, "espBcdSha256": "e" * 64}
                    if tamper == "windows_files" else original_hashes,
                ]
                with self.subTest(tamper=tamper), mock.patch.dict(
                    os.environ, lab_env(), clear=True
                ), mock.patch.object(lab, "validate_workspace"), mock.patch.object(
                    lab, "owned_regular"
                ), mock.patch.object(
                    lab, "signed_lab_plan", return_value=plan
                ), mock.patch.object(
                    lab, "qcow2_file_identity", return_value={"synthetic": True}
                ), mock.patch.object(
                    lab, "_verify_installed_root", return_value={"nativeRoot": True}
                ), mock.patch.object(
                    lab, "verify_windows_post_ext4",
                    return_value={
                        "windowsBootAfterExt4Verified": True,
                        "fifthExt4UuidSurvivedWindowsBoot": True,
                    },
                ), mock.patch.object(
                    lab, "gpt_windows", side_effect=gpt_reads
                ), mock.patch.object(
                    lab, "read_windows_file_hashes", side_effect=file_reads
                ):
                    args = (
                        [], base, nvram, {}, {}, {}, {}, EXT4, FOURTH,
                        valid_pacstrap(),
                    )
                    if error:
                        with self.assertRaisesRegex(
                            lab.PostPacstrapWindowsError, error
                        ):
                            lab.verify_windows_with_installed_root(*args)
                    else:
                        status = lab.verify_windows_with_installed_root(*args)
                        self.assertTrue(
                            status["windowsBootWithPacstrappedCachyosOnSameDiskVerified"])
                        self.assertFalse(status["sameDiskDualBootVerified"])
                        self.assertFalse(status["cachyosBootloaderInstalledToWindowsEsp"])
                        self.assertFalse(status["rollbackProven"])
                        self.assertFalse(status["releaseEligible"])


if __name__ == "__main__":
    unittest.main()
