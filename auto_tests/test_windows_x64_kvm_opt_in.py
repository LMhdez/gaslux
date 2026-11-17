"""KVM is opt-in, hosted GitHub runner only, with virtual disk device isolation."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SRC = TOOLS / "windows_x64_tcg_firstboot.py"
spec = importlib.util.spec_from_file_location("win_kvm_gate", SRC)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class HostedKvmGate(unittest.TestCase):
    def test_explicit_kvm_opt_in_does_not_accept_tcg_consent(self):
        with tempfile.TemporaryDirectory() as root:
            env = {
                "GITHUB_ACTIONS": "true",
                "RUNNER_OS": "Linux",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_REPOSITORY": "LMhdez/gaslux",
                "GASLUX_WINDOWS_TCG_CONSENT": mod.CONSENT,
            }
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(mod.LabError, "expressly authorized"):
                    mod.validate_environment(Path(root), "kvm")

    def test_kvm_refuses_self_hosted_even_with_explicit_consent(self):
        with tempfile.TemporaryDirectory() as root:
            env = {
                "GITHUB_ACTIONS": "true",
                "RUNNER_OS": "Linux",
                "RUNNER_ENVIRONMENT": "self-hosted",
                "GITHUB_REPOSITORY": "LMhdez/gaslux",
                "GASLUX_WINDOWS_KVM_CONSENT": "I_ACCEPT_DISPOSABLE_GITHUB_KVM_ONLY",
            }
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(mod.LabError, "self-hosted"):
                    mod.validate_environment(Path(root), "kvm")

    def test_invalid_accelerator_rejected_before_any_disk_access(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(mod.LabError, "unknown guest accelerator"):
                mod.validate_environment(Path(root), "host-disk")

    def test_virtual_disk_only_and_uefi_vm_paths_preserved(self):
        source = SRC.read_text()
        for required in (
            '"q35,accel=kvm,smm=on"',
            '"q35,accel=tcg,smm=on"',
            '"host" if args.accel == "kvm"',
            "0xAE00", "0xAE01",
            'os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"',
            '"only-disposable-windows-target.qcow2"',
            '"if=none,id=only_windows,format=qcow2,file={disk}"',
            'args.accel',
            "kvm.open",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        for prohibited in (
            "file=/dev/sda", "file=/dev/nvme", "file=/dev/vda",
            "bcdedit /delete", "--skippgpcheck", "SigLevel = Never",
        ):
            self.assertNotIn(prohibited, source)


if __name__ == "__main__":
    unittest.main()
