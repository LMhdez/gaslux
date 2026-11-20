"""No media: reject unauthorized real System76 ELF/CLI inspection."""
from __future__ import annotations
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
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

    def test_no_untrusted_elf_can_reach_help_subprocess(self):
        with patch.object(obs, "require_readonly_distinst_environment",
                          side_effect=DiskAuditError("invalid ELF")), \
             patch.object(obs.subprocess, "run",
                          side_effect=AssertionError("must not execute")):
            with self.assertRaises(DiskAuditError):
                obs.inspect_distinst_help()


if __name__ == "__main__":
    unittest.main()
