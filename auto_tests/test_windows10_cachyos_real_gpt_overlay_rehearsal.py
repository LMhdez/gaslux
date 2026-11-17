"""No-VM negative guards for Windows/CachyOS shared GPT COW rehearsal."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "rehearsal", TOOLS / "windows10_cachyos_real_gpt_overlay_rehearsal.py")
assert spec and spec.loader
rehearsal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rehearsal)


def base_args():
    return [
        "qemu-system-x86_64",
        "-drive", "if=pflash,format=raw,readonly=on,file=/boot/OVMF_CODE.fd",
        "-drive", "if=pflash,format=raw,file=/tmp/owned-windows-vars.fd",
        "-drive", "if=none,id=only_windows,format=qcow2,file=/tmp/windows-base.qcow2",
        "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
        "-serial", "file:/tmp/fresh-third-windows-guest-serial",
        "-boot", "order=c",
    ]


class WindowsCachyosRealOverlaySafetyTests(unittest.TestCase):
    def test_exact_disk_and_uefi_trial_target_substitution(self):
        with tempfile.TemporaryDirectory() as dirname:
            parent = Path(dirname) / "windows-uefi-cow-checkpoint"
            trial = parent / "windows-reboot-after-linux-gpt-discard.qcow2"
            vars = parent / "trial-ovmf-variables.fd"
            result = rehearsal.build_post_discard_boot_args(base_args(), trial, vars)
            self.assertIn("if=none,id=only_windows,format=qcow2,file=" +
                          str(trial), result)
            self.assertIn("if=pflash,format=raw,file=" + str(vars), result)
            self.assertIn("if=pflash,format=raw,readonly=on,file=/boot/OVMF_CODE.fd",
                          result)
            self.assertNotIn("if=none,id=only_windows,format=qcow2,file=/tmp/windows-base.qcow2",
                             result)
            self.assertNotIn("if=pflash,format=raw,file=/tmp/owned-windows-vars.fd",
                             result)
            self.assertIn("order=c", result)

    def test_duplicate_or_missing_windows_disk_refused(self):
        with tempfile.TemporaryDirectory() as dirname:
            parent = Path(dirname)
            trial = parent / "windows-reboot-after-linux-gpt-discard.qcow2"
            vars = parent / "trial-ovmf-variables.fd"
            for candidate in (base_args()[:3], base_args() + [
                "-drive", base_args()[6],
            ]):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(rehearsal.GptOverlayTrialRejected):
                        rehearsal.build_post_discard_boot_args(candidate, trial, vars)

    def test_disallowed_private_overlay_names_refused(self):
        with tempfile.TemporaryDirectory() as dirname:
            parent = Path(dirname)
            for overlay, vars in (
                (parent / "foreign.qcow2", parent / "trial-ovmf-variables.fd"),
                (parent / "windows-reboot-after-linux-gpt-discard.qcow2",
                 parent / "foreign-vars.fd"),
                (parent / "a" / "windows-reboot-after-linux-gpt-discard.qcow2",
                 parent / "b" / "trial-ovmf-variables.fd"),
            ):
                with self.subTest(overlay=overlay), self.assertRaises(
                        rehearsal.GptOverlayTrialRejected):
                    rehearsal.build_post_discard_boot_args(base_args(),
                                                           overlay, vars)

    def test_opted_out_mode_does_not_disable_guard_contracts(self):
        source = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        self.assertIn('"GASLUX_CACHYOS_OVERLAY_GPT_CONSENT"', source)
        self.assertIn("prepare_linux_gpt_rehearsal", source)
        self.assertIn("verify_after_independent_windows_boot", source)

    def test_recovery_proof_does_not_authorize_any_host_write(self):
        source = (TOOLS / "windows10_cachyos_real_gpt_overlay_rehearsal.py").read_text()
        self.assertIn('"storageWritesAuthorized": False', source)
        self.assertIn('"cachyosInstalled": False', source)
        self.assertIn('"windowsBcdWinreRestorationVerified": False', source)
        self.assertNotIn("sgdisk --clear", source)
        self.assertNotIn("mkfs", source)


if __name__ == "__main__":
    unittest.main()
