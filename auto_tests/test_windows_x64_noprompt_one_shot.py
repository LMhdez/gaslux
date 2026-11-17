"""One-shot derived Microsoft ISO KVM install: virtual-only negative contracts.

No Windows media download, guest installation or host disk writes are executed.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
SRC = TOOLS / "windows_x64_tcg_firstboot.py"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("gaslux_win_one_shot", SRC)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class FakeGuest:
    def __init__(self):
        self.rc = None
        self.killed = False

    def poll(self):
        return self.rc

    def kill(self):
        self.rc = -9
        self.killed = True

    def wait(self, timeout):
        return self.rc


class OneShotHostedWindowsLabTests(unittest.TestCase):
    def rejected(self, args, environment=None):
        with patch.dict(os.environ, environment or {}, clear=True):
            result = subprocess.run(
                [sys.executable, str(SRC), "--profile",
                 "win10_22h2_en_us_x64", *args],
                capture_output=True, text=True, timeout=15,
                env=dict(os.environ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("one-shot Windows lab installation requires explicit",
                      result.stderr)

    def test_missing_opt_in_rejected_before_windows_media_download(self):
        self.rejected(["--one-shot-install-only",
                       "--derived-no-prompt", "--accel", "kvm"])

    def test_tcg_fails_closed_even_with_lab_opt_in(self):
        self.rejected(
            ["--one-shot-install-only", "--derived-no-prompt", "--accel", "tcg"],
            {"GASLUX_WINDOWS_ONE_SHOT_INSTALL_CONSENT":
             "I_ACCEPT_DISPOSABLE_GITHUB_KVM_INITIAL_DVD_ONLY"},
        )

    def test_unpinned_original_iso_mode_fails_closed(self):
        self.rejected(
            ["--one-shot-install-only", "--accel", "kvm"],
            {"GASLUX_WINDOWS_ONE_SHOT_INSTALL_CONSENT":
             "I_ACCEPT_DISPOSABLE_GITHUB_KVM_INITIAL_DVD_ONLY"},
        )

    def test_probe_only_cannot_write_disk_even_with_install_consent(self):
        self.rejected(
            ["--one-shot-install-only", "--derived-no-prompt", "--boot-probe-only",
             "--accel", "kvm"],
            {"GASLUX_WINDOWS_ONE_SHOT_INSTALL_CONSENT":
             "I_ACCEPT_DISPOSABLE_GITHUB_KVM_INITIAL_DVD_ONLY"},
        )

    def test_repeated_dvd_boot_detected_and_vm_stopped(self):
        with tempfile.TemporaryDirectory() as temp:
            serial = pathlib.Path(temp) / "win-serial.log"
            serial.write_bytes(
                b'BdsDxe: starting Boot0001 "UEFI QEMU DVD-ROM ...\n'
                b'BdsDxe: starting Boot0001 "UEFI QEMU DVD-ROM ...\n'
            )
            vm_guest = FakeGuest()
            with patch.object(vm.subprocess, "Popen", return_value=vm_guest), (
                patch.object(vm.time, "monotonic", side_effect=iter(range(0, 1000, 5)))
            ), patch.object(vm.time, "sleep", return_value=None):
                ok, reason = vm.boot_vm(
                    ["qemu-system-x86_64"], serial, 400,
                    "win10_22h2_en_us_x64", reject_repeated_dvd_boot=True,
                )
            self.assertFalse(ok)
            self.assertIn("retried one-shot", reason)
            self.assertTrue(vm_guest.killed)

    def test_only_once_dvd_boot_and_hosted_vm_storage_source(self):
        source = SRC.read_text()
        self.assertIn('"-boot", ("order=c,once=d" if args.one_shot_install_only',
                      source)
        self.assertIn('reject_repeated_dvd_boot=args.one_shot_install_only', source)
        self.assertIn('id=only_windows,format=qcow2,file={disk}', source)
        self.assertIn('require(not disk.exists(), "refuse to reuse an existing Windows disk")',
                      source)
        self.assertIn('workspace.parent == host_temp', source)
        self.assertIn('os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"',
                      source)
        self.assertNotIn("file=/dev/sda", source)
        self.assertNotIn("file=/dev/nvme", source)


if __name__ == "__main__":
    unittest.main()
