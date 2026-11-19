"""Host-side Ed25519 grant issuance is bound to a disposable Windows COW proof."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
import unittest
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "tools"))
from cachyos_windows_shared_archiso_handoff import canonical, VIRTUAL_BYTES
import cachyos_windows_shared_cow_grant as issuer
from test_cachyos_windows_shared_archiso_handoff import fixture as signed_fixture

ROOT_UUID = "01234567-89ab-cdef-0123-456789abcdef"
SERIAL_SHA = "d" * 64


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class HostRootGrantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runner_temp = Path(self.temp.name).resolve()
        self.win = self.runner_temp / "gaslux-win-x64-grant-test"
        self.win.mkdir(mode=0o700)
        os.chmod(self.win, 0o700)
        self.base = self.win / "only-disposable-windows-target.qcow2"
        self.base.write_bytes(b"immutable-windows-qcow2-fixture")
        os.chmod(self.base, 0o400)
        self.checkpoint_dir = self.win / issuer.CHECKPOINT_DIR
        self.checkpoint_dir.mkdir(mode=0o700)
        os.chmod(self.checkpoint_dir, 0o700)
        self.overlay = self.checkpoint_dir / issuer.OVERLAY_NAME
        self.overlay.write_bytes(b"external-cow-overlay-fixture")
        os.chmod(self.overlay, 0o600)
        self.nvram = self.win / "ovmf-variables.fd"
        self.nvram.write_bytes(b"windows-ovmf-baseline-fixture")
        os.chmod(self.nvram, 0o600)
        self.baseline_vars = self.checkpoint_dir / "windows-ovmf-baseline.fd"
        self.baseline_vars.write_bytes(self.nvram.read_bytes())
        os.chmod(self.baseline_vars, 0o400)
        self.workspace = self.win / "handoff"
        self.workspace.mkdir(mode=0o700)
        os.chmod(self.workspace, 0o700)
        self.plan = signed_fixture()
        self.front = b"F" * (1024 * 1024)
        self.back = b"B" * (1024 * 1024)
        self.plan["gptWindowsSha256"] = digest(self.front + self.back)
        self.plan_path = self.workspace / "plan.json"
        self.plan_path.write_bytes(canonical(self.plan))
        self.private_key = self.workspace / "private.pem"
        self.public_key = self.workspace / "public.pem"
        self.signature = self.workspace / "plan.sig"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private_key)],
            check=True, capture_output=True,
        )
        os.chmod(self.private_key, 0o600)
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.private_key), "-pubout",
             "-out", str(self.public_key)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.private_key),
             "-rawin", "-in", str(self.plan_path), "-out", str(self.signature)],
            check=True, capture_output=True,
        )
        self.serial = self.win / "fourth-post-ext4-windows-serial.log"
        self.serial.write_bytes(b"synthetic-fourth-windows-com1")
        self.geometry = {
            "candidateWindowsGptPrimaryAndBackupConsistent": True,
            "windowsPartitions": [{}, {}, {}, {}],
            "storageWritesAuthorized": False,
        }
        self.checkpoint = {
            "candidateWindowsCowCheckpointPrepared": True,
            "trialOverlayInitiallyMatchesWindows": True,
            "windowsBaselineUnchangedDuringCheckpoint": True,
            "snapshotIndependentlyRestorable": False,
            "uefiVarsCopySha256": digest(self.nvram.read_bytes()),
        }
        self.staged = {
            "overlayGptLinuxRootEntryPrepared": True,
            "onlyDisposableOverlayModified": True,
            "windowsPartitionEntriesUnchanged": True,
            "windowsPartitionBoundarySamplesUnchanged": True,
            "protectiveMbrAndGptOutsideWhitelistUnchanged": True,
            "bothGptMirrorsAfterStageVerified": True,
            "windowsBackingQcow2Unchanged": True,
            "windowsUefiVariablesUnchanged": True,
            "linuxRoot": {
                "index": 5,
                "uniqueGuid": self.plan["partitions"][4]["uniqueGuid"],
            },
        }
        self.third = {
            "windowsBootAfterOverlayMutationVerified": True,
            "guestBcdWinreEspAfterOverlayVerified": True,
            "windowsGuestShutdownAfterOverlayVerified": True,
            "cachyosInstalled": False,
            "sameDiskDualBootVerified": False,
            "storageWritesAuthorized": False,
            "releaseEligible": False,
        }
        self.ext4 = {
            "onlyOwnedOverlayFifthPartitionFormatted": True,
            "linuxRootFilesystemFormatted": True,
            "rootFilesystem": {
                "filesystemType": "ext4",
                "filesystemUuid": self.plan["rootFsUuid"],
                "allFourWindowsPartitionSha256Unchanged": True,
            },
            "windowsBackingQcow2UnchangedAfterExt4": True,
            "windowsOriginalUefiUnchangedAfterExt4": True,
            "cachyosInstalled": False,
            "sameDiskDualBootVerified": False,
            "storageWritesAuthorized": False,
            "releaseEligible": False,
        }
        self.fourth = {
            "windowsBootAfterExt4Verified": True,
            "windowsBcdWinreEspAfterExt4Verified": True,
            "fourthGuestCleanShutdownVerified": True,
            "fifthExt4UuidSurvivedWindowsBoot": True,
            "windowsGptUnchangedAfterExt4Boot": True,
            "windowsBackingUnchangedAfterExt4Boot": True,
            "originalWindowsUefiUnchangedAfterExt4Boot": True,
            "fourthGuestSerialSha256": SERIAL_SHA,
            "windowsRecoveryAfterLinuxVerified": False,
            "rollbackProven": False,
            "cachyosInstalled": False,
            "sameDiskDualBootVerified": False,
            "storageWritesAuthorized": False,
            "releaseEligible": False,
        }
        self.programs = {
            "cachyos_windows_shared_root_pacstrap.py":
                HERE / "tools/cachyos_windows_shared_root_pacstrap.py",
            "cachyos_configure_installed.py":
                HERE / "tools/cachyos_configure_installed.py",
            "cachyos_windows_shared_archiso_handoff.py":
                HERE / "tools/cachyos_windows_shared_archiso_handoff.py",
            "cachyos_windows_shared_archiso_guest_probe.py":
                HERE / "tools/cachyos_windows_shared_archiso_guest_probe.py",
            "windows_cachyos_qcow2_gpt_readonly.py":
                HERE / "tools/windows_cachyos_qcow2_gpt_readonly.py",
            "strict-pacman.py":
                HERE.parent / "assets/live/cachyos-strict-pacman.py",
            "pacman-trust.py":
                HERE.parent / "assets/live/cachyos-pacman-trust.py",
            "gaslux-install.sh":
                HERE / "tools/gaslux-cachyos-shared-root-install.sh",
            "gaslux-launch.sh":
                HERE / "tools/gaslux-cachyos-shared-root-launch.sh",
        }

    def tearDown(self):
        self.temp.cleanup()

    def _issue(self, *, fourth=None, backing=None):
        base_info = {
            "format": "qcow2", "virtual-size": VIRTUAL_BYTES,
        }
        overlay_info = {
            "format": "qcow2", "virtual-size": VIRTUAL_BYTES,
            "backing-filename": str(backing or self.base),
            "backing-filename-format": "qcow2",
        }
        def info(path):
            return base_info if Path(path) == self.base else overlay_info
        env = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "GITHUB_REPOSITORY": "LMhdez/gaslux",
            "RUNNER_TEMP": str(self.runner_temp),
            "GASLUX_CACHYOS_SHARED_ROOT_PACSTRAP_CONSENT": issuer.CONSENT,
        }
        with patch.dict(os.environ, env, clear=False), \
             patch.object(issuer, "_qemu_info", side_effect=info), \
             patch.object(issuer, "_qemu_check", return_value="No errors were found on the image."), \
             patch.object(issuer, "gpt_windows", return_value=(self.front, self.back)), \
             patch.object(issuer, "read_windows_file_hashes",
                          return_value=self.plan["windowsHashes"]), \
             patch.object(issuer, "audit_complete_third_serial", return_value=SERIAL_SHA):
            return issuer.issue_root_write_grant(
                plan_path=self.plan_path,
                plan_signature=self.signature,
                public_key=self.public_key,
                private_key=self.private_key,
                base=self.base,
                overlay=self.overlay,
                nvram=self.nvram,
                workspace=self.workspace,
                geometry=self.geometry,
                checkpoint=self.checkpoint,
                staged=self.staged,
                third=self.third,
                ext4=self.ext4,
                fourth=fourth or self.fourth,
                fourth_serial=self.serial,
                programs=self.programs,
            )

    def test_issues_grant_only_for_signed_fifth_ext4_and_exact_cow(self):
        result = self._issue()
        self.assertTrue(result["rootWriteGrantIssued"])
        self.assertTrue(result["sourceImageReadOnly"])
        self.assertTrue(result["discardableOverlay"])
        self.assertFalse(result["pacstrapExecuted"])
        self.assertFalse(result["productionStorageWritesAuthorized"])
        self.assertFalse(result["sameDiskDualBootVerified"])
        self.assertEqual((self.workspace / "root-write-grant.sig").stat().st_size, 64)
        self.assertTrue((self.workspace / "host-checkpoint.json").is_file())
        self.assertTrue((self.workspace / "host-overlay-backing-proof.json").is_file())

    def test_refuses_missing_fourth_windows_boot_witness(self):
        fourth = dict(self.fourth)
        fourth["windowsBootAfterExt4Verified"] = False
        with self.assertRaisesRegex(issuer.GrantIssueError, "fourth Windows boot"):
            self._issue(fourth=fourth)

    def test_refuses_foreign_qcow2_backing(self):
        foreign = self.win / "foreign-windows.qcow2"
        foreign.write_bytes(b"foreign")
        os.chmod(foreign, 0o400)
        with self.assertRaisesRegex(issuer.GrantIssueError, "exact protected Windows backing"):
            self._issue(backing=foreign)


if __name__ == "__main__":
    unittest.main()
