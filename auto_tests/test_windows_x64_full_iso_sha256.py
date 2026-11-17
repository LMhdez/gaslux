"""Offline gates for Microsoft ISO byte-level integrity workflow.

No network or disk writes are executed by this test module.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SRC = TOOLS / "windows_x64_full_iso_sha256.py"
spec = importlib.util.spec_from_file_location("win_iso_digest", SRC)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FullMicrosoftISOContract(unittest.TestCase):
    def test_exact_sha256_and_independent_reported_size_for_both_clients(self):
        profiles = mod.load_catalog()["profiles"]
        self.assertEqual(set(profiles), set(mod.EXPECTED_BYTES))
        self.assertEqual(mod.EXPECTED_BYTES["win10_22h2_en_us_x64"], 5550497792)
        self.assertEqual(mod.EXPECTED_BYTES["win11_26h2_en_us_x64"], 8225329152)
        for key, value in mod.EXPECTED.items():
            with self.subTest(profile=key):
                self.assertEqual(profiles[key]["sha256"], value)
                self.assertEqual(profiles[key]["expectedProductType"], 1)
                self.assertFalse(profiles[key]["releaseReady"])

    def test_without_explicit_disposable_ci_consent_fails_before_download(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "windows-iso-digest-evidence"
            root.mkdir()
            env = dict(os.environ)
            env.pop("GASLUX_ISO_BYTES_CONSENT", None)
            env.pop("GITHUB_ACTIONS", None)
            with patch.dict(os.environ, env, clear=True), patch.object(
                mod, "download_verified_iso", side_effect=AssertionError(
                    "download should never happen")
            ):
                old_args = sys.argv
                try:
                    sys.argv = ["tool", "--profile", "win10_22h2_en_us_x64",
                                "--evidence-dir", str(root)]
                    status = mod.main()
                finally:
                    sys.argv = old_args
            self.assertEqual(status, 2)
            self.assertEqual(list(root.iterdir()), [])

    def test_never_upload_disks_or_claim_boot_from_hash(self):
        code = SRC.read_text()
        for required in (
            '"isoSha256Verified": False',
            '"windows10InstalledAndBooted": False',
            '"windows11InstalledAndBooted": False',
            '"windowsClientFirstBootVerified": False',
            '"dualBootVerified": False',
            '"windowsRecoveryVerified": False',
            '"stable": False',
            'download_verified_iso',
            'expected_size + 4 * 1024**3',
            'TemporaryDirectory',
        ):
            self.assertIn(required, code)
        for forbidden in ("-accel kvm", "Format-Volume",
                          "Clear-Disk", "/dev/sda", "/dev/nvme",
                          "upload-artifact", "print(exc)"):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
