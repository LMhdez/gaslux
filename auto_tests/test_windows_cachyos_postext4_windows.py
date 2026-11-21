"""Negative fourth-boot safety gates: no host I/O or guests."""
from __future__ import annotations
import hashlib, importlib.util, json, os, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent/"tools"
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location("post_ext4",ROOT/"windows_cachyos_postext4_windows.py")
assert spec and spec.loader
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
class FourthBootContracts(unittest.TestCase):
    def args(self):return ([],Path("/invalid"),Path("/invalid"),{},{},{},{},{})
    def test_no_separate_consent_denied_before_file_or_guest(self):
        with patch.dict(os.environ,{},clear=True):
            with patch.object(lab,"validate_workspace",side_effect=AssertionError("disk")):
                with self.assertRaisesRegex(lab.FourthBootError,"dedicated"):
                    lab.verify_windows_post_ext4(*self.args())
    def test_missing_genuine_ext4_and_thirdboot_denied_without_file_io(self):
        env={"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted",
             "GITHUB_REPOSITORY":"LMhdez/gaslux",
             "GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT":lab.CONSENT,
             "GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT":lab.THIRD_BOOT_CONSENT,
             "GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT":lab.EXT4_CONSENT}
        with patch.dict(os.environ,env):
            with patch.object(lab,"validate_workspace",side_effect=AssertionError("disk")):
                with self.assertRaisesRegex(lab.FourthBootError,"genuine Windows"):
                    lab.verify_windows_post_ext4(*self.args())
    def test_invalid_timeout_denied_without_file_io(self):
        env={"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted",
             "GITHUB_REPOSITORY":"LMhdez/gaslux",
             "GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT":lab.CONSENT,
             "GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT":lab.THIRD_BOOT_CONSENT,
             "GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT":lab.EXT4_CONSENT}
        with patch.dict(os.environ,env):
            for bad in (0,-1,1801,120.0):
                with self.subTest(bad=bad),self.assertRaisesRegex(
                    lab.FourthBootError,"dedicated"
                ):lab.verify_windows_post_ext4(*self.args(),timeout=bad)
    def test_contextual_error_codes_do_not_expand_acceptance(self):
        self.assertEqual(
            lab.boot_failure_code("fourth-post-ext4", "TIMEOUT"),
            "WINDOWS_FOURTH_POST_EXT4_TIMEOUT")
        self.assertEqual(
            lab.boot_failure_code("bcd-control-windows-only", "TIMEOUT"),
            "BCD_AB_CONTROL_WINDOWS_ONLY_TIMEOUT")
        self.assertEqual(
            lab.boot_failure_code("sixth-post-pacstrap", "TIMEOUT"),
            "POST_PACSTRAP_WINDOWS_TIMEOUT")
        self.assertEqual(
            lab.boot_failure_code("bcd-control-windows-only",
                                  "QEMU_EXIT_NONZERO"),
            "BCD_AB_CONTROL_WINDOWS_ONLY_QEMU_EXIT_NONZERO")
        self.assertEqual(
            lab.boot_failure_code("bcd-control-windows-only",
                                  "COM1_INCOMPLETE"),
            "BCD_AB_CONTROL_WINDOWS_ONLY_COM1_INCOMPLETE")
        with self.assertRaises(lab.FourthBootError):
            lab.boot_failure_code("untrusted-stem", "TIMEOUT")

    def test_com1_missing_partial_complete_and_untrusted_sources(self):
        with tempfile.TemporaryDirectory() as td:
            serial = Path(td) / "serial.log"
            self.assertEqual(
                lab.read_bounded_com1_witness(serial)["exists"], False)
            serial.write_bytes(lab.COM1_WITNESSES[0] + b"\n")
            partial = lab.read_bounded_com1_witness(serial)
            self.assertTrue(partial["exists"])
            self.assertFalse(partial["completeBootWitness"])
            self.assertEqual(partial["markerNames"],
                             [lab.COM1_WITNESSES[0].decode()])
            serial.write_bytes(b"\n".join(lab.COM1_WITNESSES) + b"\n")
            complete = lab.read_bounded_com1_witness(serial)
            self.assertTrue(complete["completeBootWitness"])
            self.assertEqual(complete["sizeBytes"], serial.stat().st_size)
            serial.unlink()
            serial.symlink_to(Path(td) / "missing")
            with self.assertRaises(lab.FourthBootError):
                lab.read_bounded_com1_witness(serial)

    def test_bounded_host_timeout_diagnostic_never_claims_boot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "only-disposable-windows-target.qcow2"
            base.write_bytes(b"synthetic base")
            folder = root / lab.CHECKPOINT_DIR
            folder.mkdir()
            overlay = folder / lab.OVERLAY_NAME
            overlay.write_bytes(b"synthetic fifth GPT private overlay")
            var = folder / "bcd-ab-control-ovmf-variables.fd"
            var.write_bytes(b"synthetic OVMF")
            serial = root / "bcd-control-windows-only-windows-serial.log"
            serial.write_bytes(lab.COM1_WITNESSES[0] + b"\n")
            with patch.object(lab, "qcow2_file_identity", return_value={"digest":"lab"}):
                path = lab.record_windows_boot_failure(
                    base=base, evidence_stem="bcd-control-windows-only",
                    serial=serial, overlay=overlay, trial_vars=var,
                    original_vars_sha256=lab.sha256_file(var),
                    original_overlay_sha256=lab.sha256_file(overlay),
                    base_identity={"digest":"lab"},
                    qemu_args=["qemu-system-x86_64", "-boot", "order=c"],
                    elapsed_seconds=1200, timeout_seconds=1200,
                    observed_exit_code=None, forced_termination=True,
                    trace_file=None, reason="TIMEOUT")
            diagnostic = json.loads(path.read_text())
            self.assertEqual(diagnostic["failureCode"],
                             "BCD_AB_CONTROL_WINDOWS_ONLY_TIMEOUT")
            self.assertEqual(diagnostic["source"], "HOST_OBSERVATION_ONLY")
            self.assertFalse(diagnostic["guestWindowsBootVerified"])
            self.assertTrue(diagnostic["forcedTermination"])
            self.assertIsNone(diagnostic["observedProcessExitCodeBeforeTermination"])
            self.assertEqual(diagnostic["configuredTimeoutSeconds"], 1200)
            self.assertTrue(diagnostic["com1"]["exists"])
            self.assertFalse(diagnostic["com1"]["completeBootWitness"])
            self.assertFalse(diagnostic["controlCloneChanged"])
            self.assertFalse(diagnostic["ovmfVarsChanged"])
            self.assertTrue(diagnostic["immutableBackingIdentityUnchanged"])
            for field in ("rollbackProven", "sameDiskDualBootVerified",
                          "releaseEligible", "productionStorageWritesAuthorized"):
                self.assertFalse(diagnostic[field])
            self.assertNotIn("synthetic OVMF", path.read_text())
            self.assertNotIn("synthetic base", path.read_text())
            with self.assertRaises(lab.FourthBootError):
                lab.record_windows_boot_failure(
                    base=base, evidence_stem="bcd-control-windows-only",
                    serial=serial, overlay=overlay, trial_vars=var,
                    original_vars_sha256=lab.sha256_file(var),
                    original_overlay_sha256=lab.sha256_file(overlay),
                    base_identity={}, qemu_args=[], elapsed_seconds=1,
                    timeout_seconds=1200, observed_exit_code=-1,
                    forced_termination=False, trace_file=None,
                    reason="QEMU_EXIT_NONZERO")

    def test_qemu_active_until_deadline_is_timeout_not_boot(self):
        with tempfile.TemporaryDirectory() as td:
            serial = Path(td) / "missing-com1.log"
            process = type("Alive", (), {"poll": lambda self: None})()
            with patch.object(lab.time, "monotonic", side_effect=[0, 0, 1201]):
                with patch.object(lab.time, "sleep"):
                    with self.assertRaisesRegex(
                        lab.FourthBootError,
                        "BCD_AB_CONTROL_WINDOWS_ONLY_TIMEOUT"):
                        lab.observe_windows_qemu(
                            process, serial, "bcd-control-windows-only", 1200)

    def test_qemu_complete_marker_does_not_pass_without_process_shutdown(self):
        with tempfile.TemporaryDirectory() as td:
            serial = Path(td) / "partial-com1.log"
            serial.write_bytes(b"\n".join(lab.COM1_WITNESSES) + b"\n")
            process = type("Alive", (), {"poll": lambda self: None})()
            with patch.object(lab.time, "monotonic", side_effect=[0, 0, 1201]):
                with patch.object(lab.time, "sleep"):
                    with self.assertRaisesRegex(
                        lab.FourthBootError,
                        "BCD_AB_CONTROL_WINDOWS_ONLY_TIMEOUT"):
                        lab.observe_windows_qemu(
                            process, serial, "bcd-control-windows-only", 1200)

    def test_qemu_exit_error_and_missing_com1_are_distinct(self):
        with tempfile.TemporaryDirectory() as td:
            serial = Path(td) / "missing.log"
            for status, expected in (
                (1, "BCD_AB_CONTROL_WINDOWS_ONLY_QEMU_EXIT_NONZERO"),
                (0, "BCD_AB_CONTROL_WINDOWS_ONLY_COM1_INCOMPLETE"),
            ):
                with self.subTest(status=status):
                    proc = type("Done", (), {"poll": lambda self: status})()
                    with patch.object(lab.time, "monotonic",
                                      side_effect=[0, 0]):
                        with self.assertRaisesRegex(lab.FourthBootError, expected):
                            lab.observe_windows_qemu(
                                proc, serial, "bcd-control-windows-only", 1200)

    def test_qemu_partial_com1_after_clean_shutdown_is_not_boot(self):
        with tempfile.TemporaryDirectory() as td:
            serial = Path(td) / "partial.log"
            serial.write_bytes(lab.COM1_WITNESSES[0] + b"\n")
            proc = type("Done", (), {"poll": lambda self: 0})()
            with patch.object(lab.time, "monotonic", side_effect=[0, 0]):
                with self.assertRaisesRegex(
                    lab.FourthBootError, "BCD_AB_CONTROL_WINDOWS_ONLY_COM1_INCOMPLETE"):
                    lab.observe_windows_qemu(
                        proc, serial, "bcd-control-windows-only", 1200)

    def test_qemu_complete_guest_audit_requires_shutdown_and_own_com1(self):
        with tempfile.TemporaryDirectory() as td:
            serial = Path(td) / "complete.log"
            serial.write_bytes(b"guest COM1 fixture")
            proc = type("Done", (), {"poll": lambda self: 0})()
            with patch.object(lab.time, "monotonic", side_effect=[0, 0]):
                with patch.object(lab, "audit_complete_third_serial",
                                  return_value="a" * 64) as audit:
                    self.assertEqual(lab.observe_windows_qemu(
                        proc, serial, "bcd-control-windows-only", 1200),
                        "a" * 64)
            audit.assert_called_once_with(serial)

    def test_qemu_guest_failure_marker_blocks_early(self):
        with tempfile.TemporaryDirectory() as td:
            serial = Path(td) / "error.log"
            serial.write_bytes(b"GASLUX_COW_WIN10_REBOOT_FAIL=1\\n")
            proc = type("Alive", (), {"poll": lambda self: None})()
            with patch.object(lab.time, "monotonic", side_effect=[0, 0]):
                with self.assertRaisesRegex(
                    lab.FourthBootError, "BCD_AB_CONTROL_WINDOWS_ONLY_COM1_REJECTED"):
                    lab.observe_windows_qemu(
                        proc, serial, "bcd-control-windows-only", 1200)

    def test_host_diagnostic_detects_modified_ovmf_and_unexpected_disk(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "only-disposable-windows-target.qcow2"
            base.write_bytes(b"base")
            folder = root / lab.CHECKPOINT_DIR
            folder.mkdir()
            overlay = folder / lab.OVERLAY_NAME
            overlay.write_bytes(b"disk")
            var = folder / "bcd-ab-control-ovmf-variables.fd"
            var.write_bytes(b"OVMF after modification")
            serial = root / "bcd-control-windows-only-windows-serial.log"
            with patch.object(lab, "qcow2_file_identity", return_value={}):
                path = lab.record_windows_boot_failure(
                    base=base, evidence_stem="bcd-control-windows-only",
                    serial=serial, overlay=overlay, trial_vars=var,
                    original_vars_sha256=hashlib.sha256(b"prior OVMF").hexdigest(),
                    original_overlay_sha256=hashlib.sha256(b"prior disk").hexdigest(),
                    base_identity={"base": "prior"}, qemu_args=[],
                    elapsed_seconds=1, timeout_seconds=1200,
                    observed_exit_code=1, forced_termination=False,
                    trace_file=None, reason="QEMU_EXIT_NONZERO")
            diagnostic = json.loads(path.read_text())
            self.assertTrue(diagnostic["ovmfVarsChanged"])
            self.assertTrue(diagnostic["controlCloneChanged"])
            self.assertFalse(diagnostic["immutableBackingIdentityUnchanged"])
            self.assertFalse(diagnostic["com1"]["exists"])
            self.assertEqual(diagnostic["failureCode"],
                             "BCD_AB_CONTROL_WINDOWS_ONLY_QEMU_EXIT_NONZERO")

    def test_no_linux_or_rollback_claims(self):
        s=(ROOT/"windows_cachyos_postext4_windows.py").read_text()
        for flag in ("cachyosInstalled","cachyosFirstBootVerified",
                     "windowsRecoveryAfterLinuxVerified","rollbackProven",
                     "sameDiskDualBootVerified","storageWritesAuthorized",
                     "releaseEligible"):
            self.assertIn('"'+flag+'":False',s)
        self.assertNotIn("sgdisk --clear",s)
        self.assertNotIn("pacstrap -K",s)
if __name__=="__main__":unittest.main()
