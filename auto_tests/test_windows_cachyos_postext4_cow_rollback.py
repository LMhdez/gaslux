"""Pure-Python fail-closed contracts for VM-only ext4 COW discard recovery."""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location(
    "windows_cachyos_postext4_cow_rollback_test",
    TOOLS / "windows_cachyos_postext4_cow_rollback.py",
)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)
from windows_cachyos_overlay_reboot import (
    PROOF, BASELINE_PROOF, audit_complete_four_partition_serial,
    guest_reboot_script,
)


class PostExt4CowRollbackContracts(unittest.TestCase):
    def empty_inputs(self):
        return ([], Path("/invalid"), Path("/invalid"), {}, {}, {}, {}, {}, {})

    def full_environment(self):
        return {
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "LMhdez/gaslux",
            "RUNNER_TEMP": "/home/runner/work/_temp",
            "GASLUX_WINDOWS_POST_EXT4_COW_DISCARD_CONSENT": LAB.CONSENT,
            "GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT": LAB.FOURTH_BOOT_CONSENT,
            "GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT": LAB.THIRD_BOOT_CONSENT,
            "GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT": LAB.EXT4_CONSENT,
        }

    def test_explicit_separate_consent_required_before_touching_files(self):
        env = self.full_environment()
        for missing in env:
            with self.subTest(missing=missing):
                case = dict(env)
                del case[missing]
                with patch.dict(os.environ, case, clear=True):
                    with patch.object(LAB, "validate_workspace",
                                      side_effect=AssertionError("attempted IO")):
                        with self.assertRaisesRegex(
                            LAB.CowRollbackError, "separate GitHub-hosted"
                        ):
                            LAB.verify_discard_postext4_cow(*self.empty_inputs())

    def test_missing_real_fourth_boot_rejected_before_file_io(self):
        with patch.dict(os.environ, self.full_environment(), clear=True):
            with patch.object(LAB, "validate_workspace",
                              side_effect=AssertionError("attempted IO")):
                with self.assertRaisesRegex(
                    LAB.CowRollbackError, "actual fourth Windows boot"
                ):
                    LAB.verify_discard_postext4_cow(*self.empty_inputs())

    def test_invalid_timeouts_fail_preflight(self):
        with patch.dict(os.environ, self.full_environment(), clear=True):
            for timeout in (0, -1, 119, 1801, 120.0, None):
                with self.subTest(timeout=timeout):
                    with self.assertRaises(LAB.CowRollbackError):
                        LAB.verify_discard_postext4_cow(
                            *self.empty_inputs(), timeout=timeout
                        )

    def test_four_partition_guest_has_distinct_marker(self):
        source = guest_reboot_script()
        self.assertIn("$parts.Count -notin @(4,5)", source)
        self.assertIn("$linux.Count -ne 0", source)
        self.assertIn("GASLUX_COW_WIN10_REBOOT_FIFTH_GPT=1", source)
        self.assertIn("GASLUX_COW_WIN10_ROLLBACK_FOUR_GPT=1", source)
        self.assertIn("reagentc.exe /info", source)
        self.assertIn("bcdedit.exe /enum '{bootmgr}'", source)
        self.assertEqual(BASELINE_PROOF[:5], PROOF[:5])

    def test_real_serial_auditor_requires_exact_four_partition_witness(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "owned-fifth-serial.log"
            common = b'BdsDxe: starting Boot0001 "Windows Boot Manager"\r\n'
            lines = b"\r\n".join(x.encode("ascii") for x in BASELINE_PROOF)
            serial = common + lines + b"\r\n"
            log.write_bytes(serial)
            self.assertEqual(len(audit_complete_four_partition_serial(log)), 64)
            for bad in (
                serial + BASELINE_PROOF[-1].encode("ascii") + b"\r\n",
                serial + PROOF[-1].encode("ascii") + b"\r\n",
                serial + b"GASLUX_COW_WIN10_REBOOT_FAIL=1\r\n",
                serial + common,
                serial.replace(BASELINE_PROOF[-1].encode("ascii"), b""),
            ):
                with self.subTest(tail=bad[-80:]):
                    log.write_bytes(bad)
                    with self.assertRaises(Exception):
                        audit_complete_four_partition_serial(log)
            log.write_bytes(serial)
            self.assertEqual(len(audit_complete_four_partition_serial(log)), 64)

    def test_no_linux_install_or_inplace_recovery_claim(self):
        source = (TOOLS / "windows_cachyos_postext4_cow_rollback.py").read_text()
        for flag in (
            '"cachyosInstalled": False', '"windowsRecoveryAfterLinuxVerified": False',
            '"windowsInPlaceRecoveryVerified": False', '"rollbackProven": False',
            '"sameDiskDualBootVerified": False', '"storageWritesAuthorized": False',
            '"releaseEligible": False',
        ):
            self.assertIn(flag, source)
        for token in ("pacstrap", "sgdisk --clear", "mkfs(", "efibootmgr",
                      "guestfs.add_drive_opts"):
            self.assertNotIn(token, source)
        self.assertIn("owned_regular(overlay, directory, OVERLAY_NAME)", source)
        self.assertIn("require_unchanged_qcow2(base, baseline_id)", source)
        self.assertIn("audit_complete_four_partition_serial(serial)", source)
        self.assertIn("qemu-img", source)
        self.assertIn("sha256_file(base)", source)


if __name__ == "__main__":
    unittest.main()
