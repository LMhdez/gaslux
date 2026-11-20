"""No media: reject unauthorized real System76 ELF/CLI inspection."""
from __future__ import annotations
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import hashlib
sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows10_popos_distinst_readonly_observer as obs
from windows_x64_installed_gpt_ro_audit import DiskAuditError


class ReadonlyDistinstObserver(unittest.TestCase):
    def test_reject_without_consent_before_file_or_subprocess(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(obs.subprocess, "run", side_effect=AssertionError("executed")):
            with self.assertRaises(DiskAuditError):
                obs.require_readonly_distinst_environment()

    def test_no_install_argument_can_be_supplied(self):
        self.assertEqual(obs.SAFE_ARGS, ("--help",))
        self.assertNotIn("--use", obs.SAFE_ARGS)
        self.assertNotIn("--block", obs.SAFE_ARGS)
        self.assertNotIn("--test", obs.SAFE_ARGS)
        self.assertNotIn("--new-table", obs.SAFE_ARGS)
        self.assertNotIn("--modify-boot", obs.SAFE_ARGS)

    def test_pinned_agent_digest_exactly_matches_genuine_win10_live_log(self):
        self.assertEqual(obs.PINNED_DISTINST_SHA256,
                         "8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5")

    def test_help_result_pins_exact_argv_and_bounded_real_option_shape(self):
        cli = ("Usage: distinst [OPTIONS]\\n\\nOptions:\\n"
               "  -b, --block <disk>       Select disk\\n"
               "  -u, --use <part>         Reuse partition\\n"
               "      --no-efi-vars        Do not mount efivars\\n"
               "      --modify-boot        Change boot variables\\n")
        with patch.object(obs, "require_readonly_distinst_environment"), \
             patch.object(obs.subprocess, "run",
                          return_value=SimpleNamespace(
                              returncode=0, stdout=cli, stderr="")) as runner:
            proof = obs.inspect_distinst_help()
        runner.assert_called_once()
        self.assertEqual(runner.call_args.args[0], [str(obs.AGENT), "--help"])
        self.assertTrue(proof["cliElfExecutedForHelp"])
        self.assertEqual(proof["cliHelpExitCode"], 0)
        self.assertEqual(proof["cliHelpOutputSha256"],
                         hashlib.sha256(cli.encode()).hexdigest())
        self.assertEqual(len(proof["cliOptionLines"]), 4)
        self.assertFalse(proof["observerExecutedInstaller"])
        self.assertFalse(proof["nativeInstallObserved"])
        self.assertFalse(proof["distinstExecutionAuthorized"])

    def test_no_untrusted_elf_can_reach_help_subprocess(self):
        with patch.object(obs, "require_readonly_distinst_environment",
                          side_effect=DiskAuditError("invalid ELF")), \
             patch.object(obs.subprocess, "run",
                          side_effect=AssertionError("must not execute")):
            with self.assertRaises(DiskAuditError):
                obs.inspect_distinst_help()


if __name__ == "__main__":
    unittest.main()
