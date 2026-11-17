"""Win11-only opt-in GPT COW staging must reject before catalog or VM."""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).parent / "tools"
sys.path.insert(0, str(TOOLS))
P = TOOLS / "windows_x64_tcg_firstboot.py"
spec = importlib.util.spec_from_file_location("win11_only_cow_contract", P)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)

BASE = [
    "--profile", "win11_26h2_en_us_x64",
    "--accel", "kvm",
    "--two-stage-install-only", "--derived-no-prompt",
    "--audit-installed-gpt-readonly", "--audit-primary-backup-gpt-readonly",
    "--stage-cachyos-win11-root-gpt-overlay-only",
]
ENV = {
    "GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_REPOSITORY": "LMhdez/gaslux",
    "RUNNER_TEMP": "/home/runner/work/_temp",
    "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
        "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
    "GASLUX_WINDOWS_ACPI_LAB_CONSENT":
        "I_ACCEPT_DISPOSABLE_WIN11_POSTAUDIT_ACPI_POWERDOWN",
    "GASLUX_WINDOWS_COW_CHECKPOINT_CONSENT":
        "I_ACCEPT_GITHUB_HOSTED_POSTBOOT_OVERLAY_ONLY",
    "GASLUX_CACHYOS_OVERLAY_GPT_CONSENT":
        "I_ACCEPT_DISPOSABLE_QCOW2_OVERLAY_GPT_ONLY",
    "GASLUX_WINDOWS11_CACHYOS_STAGE_CONSENT":
        "I_ACCEPT_WIN11_POSTBOOT_GPT_COW_ONLY_NO_FILESYSTEM",
}

class Win11CowPreflightTests(unittest.TestCase):
    def reject(self, args, env):
        with patch.dict(os.environ, env, clear=True), patch.object(
            vm, "load_catalog",
            side_effect=AssertionError("no catalog, network, guest or disk access"),
        ):
            with self.assertRaisesRegex(SystemExit, "Windows 11 fifth GPT overlay"):
                vm.main(args)

    def test_missing_each_consent_fails_before_any_filesystem(self):
        for key in (
            "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT",
            "GASLUX_WINDOWS_ACPI_LAB_CONSENT",
            "GASLUX_WINDOWS_COW_CHECKPOINT_CONSENT",
            "GASLUX_CACHYOS_OVERLAY_GPT_CONSENT",
            "GASLUX_WINDOWS11_CACHYOS_STAGE_CONSENT",
            "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "RUNNER_TEMP",
            "RUNNER_ENVIRONMENT",
        ):
            with self.subTest(missing=key):
                self.reject(BASE, {k: v for k, v in ENV.items() if k != key})

    def test_wrong_firmware_profile_or_missing_independent_audits_fail(self):
        variants = (
            ["--profile", "win10_22h2_en_us_x64", *BASE[2:]],
            [a for a in BASE if a != "--audit-installed-gpt-readonly"],
            [a for a in BASE if a != "--audit-primary-backup-gpt-readonly"],
            [a for a in BASE if a != "--derived-no-prompt"],
            [a for a in BASE if a != "--two-stage-install-only"],
            [*BASE, "--fixture-only"],
        )
        for args in variants:
            with self.subTest(args=args):
                self.reject(args, ENV)

    def test_complete_preflight_reaches_catalog_but_starts_no_guest(self):
        with patch.dict(os.environ, ENV, clear=True), patch.object(
            vm, "load_catalog", side_effect=RuntimeError("passed fail-closed preflight"),
        ):
            with self.assertRaisesRegex(RuntimeError, "passed fail-closed preflight"):
                vm.main(BASE)

    def test_only_no_filesystem_gpt_stage_is_exposed(self):
        source = P.read_text()
        self.assertIn("prepare_postboot_cow(disk, nvram, candidate)", source)
        self.assertIn("stage_overlay_gpt(", source)
        self.assertIn("overlay.unlink()", source)
        self.assertNotIn("mkfs.ext4", source)
        self.assertIn('report["win11CachyosOverlayDiscarded"] = True', source)

if __name__ == "__main__":
    unittest.main()
