"""Fail-closed signed CachyOS repository policy regression tests.

Uses mocked pacman-conf output, never uses pacman or writes a real disk.
"""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets/live/cachyos-pacman-trust.py"
SPEC = importlib.util.spec_from_file_location("cachyos_pacman_trust", SOURCE)
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class PacmanTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "pacman.conf"
        self.config.write_text(
            "[options]\nSigLevel = Required DatabaseOptional\n[core]\n",
            encoding="utf-8",
        )
        self.outputs = {
            ("SigLevel",): "Required DatabaseOptional",
            ("--repo-list",): "cachyos\ncore\nextra\n",
            ("--repo", "cachyos", "SigLevel"): "Required DatabaseOptional",
            ("--repo", "core", "SigLevel"): "Required DatabaseOptional",
            ("--repo", "extra", "SigLevel"): "Required DatabaseOptional",
        }

    def runner(self, args, *, capture_output, text, timeout, check):
        self.assertEqual(args[0], "pacman-conf")
        self.assertEqual(args[1:3], ["--config", str(self.config)])
        self.assertTrue(capture_output)
        self.assertTrue(text)
        return subprocess.CompletedProcess(
            args,
            0 if tuple(args[3:]) in self.outputs else 1,
            self.outputs.get(tuple(args[3:]), ""),
            "",
        )

    def check(self):
        return POLICY.assess(self.config, run=self.runner)

    def test_strict_signed_official_repositories_accepted(self):
        observed = self.check()
        self.assertTrue(observed["ok"])
        self.assertTrue(observed["packageSignaturesMandatory"])
        self.assertFalse(observed["windowsInstallerStable"])
        self.assertEqual(observed["configuredRepositories"], ["cachyos", "core", "extra"])
        self.assertEqual(len(observed["pacmanConfigSha256"]), 64)

    def test_arch_standard_database_optional_does_not_disable_package_sig(self):
        self.assertEqual(
            POLICY.verify_tokens("Required DatabaseOptional", label="global"),
            ["Required", "DatabaseOptional"],
        )

    def test_cachyos_lax_live_signature_policy_rejected(self):
        self.outputs[("--repo", "cachyos", "SigLevel")] = "Optional TrustAll"
        with self.assertRaisesRegex(POLICY.PolicyError, "weak or unknown"):
            self.check()

    def test_optional_global_signature_rejected(self):
        self.outputs[("SigLevel",)] = "Optional TrustAll"
        with self.assertRaisesRegex(POLICY.PolicyError, "weak or unknown"):
            self.check()

    def test_per_repository_package_optional_rejected(self):
        self.outputs[("--repo", "extra", "SigLevel")] = "PackageOptional DatabaseRequired"
        with self.assertRaisesRegex(POLICY.PolicyError, "weak or unknown"):
            self.check()

    def test_packages_never_rejected(self):
        with self.assertRaises(POLICY.PolicyError):
            POLICY.verify_tokens("PackageNever", label="unsafe")

    def test_package_trustall_rejected(self):
        with self.assertRaises(POLICY.PolicyError):
            POLICY.verify_tokens("Required PackageTrustAll", label="unsafe")

    def test_database_never_rejected(self):
        with self.assertRaises(POLICY.PolicyError):
            POLICY.verify_tokens("PackageRequired DatabaseNever", label="unsafe")

    def test_missing_explicit_required_package_sig_rejected(self):
        with self.assertRaisesRegex(POLICY.PolicyError, "not mandatory"):
            POLICY.verify_tokens("DatabaseRequired TrustedOnly", label="unsafe")

    def test_missing_cachyos_repo_rejected(self):
        self.outputs[("--repo-list",)] = "core\nextra\nmultilib\n"
        self.outputs[("--repo", "multilib", "SigLevel")] = "Required"
        with self.assertRaisesRegex(POLICY.PolicyError, "repositories are required"):
            self.check()

    def test_duplicated_repo_rejected(self):
        self.outputs[("--repo-list",)] = "core\ncachyos\nextra\nextra\n"
        with self.assertRaisesRegex(POLICY.PolicyError, "duplicated"):
            self.check()

    def test_repo_injection_rejected(self):
        self.outputs[("--repo-list",)] = "core\ncachyos\nextra\nfoo; touch /tmp/evil\n"
        with self.assertRaisesRegex(POLICY.PolicyError, "invalid or duplicated"):
            self.check()

    def test_pacman_conf_failure_rejected(self):
        self.outputs.pop(("--repo", "cachyos", "SigLevel"))
        with self.assertRaisesRegex(POLICY.PolicyError, "pacman-conf rejected"):
            self.check()

    def test_symlink_config_rejected(self):
        link = self.config.parent / "pacman-linked.conf"
        link.symlink_to(self.config)
        with self.assertRaisesRegex(POLICY.PolicyError, "regular explicit"):
            POLICY.assess(link, run=self.runner)

    def test_relative_config_rejected(self):
        with self.assertRaisesRegex(POLICY.PolicyError, "regular explicit"):
            POLICY.assess(Path("etc/pacman.conf"), run=self.runner)

    def test_vm_guest_must_refuse_weak_config_before_pacstrap(self):
        # The PR #171 root-only backend reuses PR #34's strict policy
        # renderer and trust guard, not PR #34's empty-disk guest launcher.
        guest = (ROOT / "auto_tests/tools/cachyos_windows_shared_root_pacstrap.py").read_text()
        install = guest.split("def pacstrap_only(args:", 1)[1]
        self.assertLess(
            install.index("verify_lab_root_write_grant(args, plan)"),
            install.index("strict_folder = prepare_signed_only_pacman(plan)"))
        self.assertLess(
            install.index("strict_folder = prepare_signed_only_pacman(plan)"),
            install.index('execute(["mount", "-t", "ext4"'))
        self.assertLess(
            install.index('execute(["mount", "-t", "ext4"'),
            install.index('execute(["pacstrap", "-K", "-C", str(strict_config)'))
        self.assertIn('"python3", str(verifier), "--config", str(config)', guest)
        self.assertIn('"--prepare-vm"', guest)
        self.assertIn('shutil.copyfile(strict_folder / "pacman-target.conf"', guest)
        self.assertNotIn('execute(["pacstrap", "-K", str(ROOT)', guest)
        self.assertNotIn('SigLevel = Never', guest)

    def test_no_trust_bypass_in_guard(self):
        raw = SOURCE.read_text()
        for word in (
            "--skippgpcheck",
            "--assume-installed",
            "--noconfirm",
            "SigLevel = Never",
            "SigLevel = Optional TrustAll",
        ):
            self.assertNotIn(word, raw)


if __name__ == "__main__":
    unittest.main()
