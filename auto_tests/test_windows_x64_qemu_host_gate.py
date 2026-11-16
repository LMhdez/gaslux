"""Negative tests: official Windows x64 ISO and hosted-QEMU prerequisites."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "auto_tests/tools/windows_x64_qemu_host_gate.py"
CATALOG = ROOT / "auto_tests/fixtures/windows_x64_official_evaluation_isos.json"

spec = importlib.util.spec_from_file_location("gaslux_win_x64_host_gate", SCRIPT)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)


class MicrosoftEvaluationX64Contract(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(CATALOG.read_text())

    def edited(self, callback):
        modified = copy.deepcopy(self.fixture)
        callback(modified)
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "catalog.json"
            file.write_text(json.dumps(modified), encoding="utf-8")
            return gate.load_catalog(file)

    def test_official_windows10_and_windows11_pins(self):
        pins = gate.load_catalog()["profiles"]
        self.assertEqual(set(pins), set(gate.EXPECTED))
        self.assertEqual(pins["win10_22h2_en_us_x64"]["sha256"],
                         "ef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668")
        self.assertEqual(pins["win11_26h2_en_us_x64"]["sha256"],
                         "bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38")
        self.assertTrue(all(p["expectedProductType"] == 1 for p in pins.values()))
        self.assertTrue(all(p["releaseReady"] is False for p in pins.values()))
        self.assertTrue(all(p["firmware"] == "uefi" for p in pins.values()))
        self.assertTrue(all(p["partitionStyle"] == "gpt" for p in pins.values()))

    def test_changed_windows10_hash_refused(self):
        with self.assertRaisesRegex(ValueError, "hash deviates"):
            self.edited(lambda v: v["profiles"]["win10_22h2_en_us_x64"].update(
                sha256="0" * 64))

    def test_changed_windows11_hash_refused(self):
        with self.assertRaisesRegex(ValueError, "hash deviates"):
            self.edited(lambda v: v["profiles"]["win11_26h2_en_us_x64"].update(
                sha256="0" * 64))

    def test_fake_hash_authority_refused(self):
        with self.assertRaisesRegex(ValueError, "incorrect client"):
            self.edited(lambda v: v["profiles"]["win11_26h2_en_us_x64"].update(
                hashAuthorityUrl="https://example.com/not-microsoft"))

    def test_server_masquerading_as_windows_client_refused(self):
        with self.assertRaisesRegex(ValueError, "incorrect client"):
            self.edited(lambda v: v["profiles"]["win11_26h2_en_us_x64"].update(
                expectedProductType=3))

    def test_http_or_foreign_iso_links_refused(self):
        for link in ("http://go.microsoft.com/fwlink/?LinkId=2382600",
                     "https://example.com/fwlink",
                     "https://go.microsoft.com.evil.org/fwlink",
                     "https://username:password@go.microsoft.com/fwlink"):
            with self.subTest(link=link), self.assertRaisesRegex(
                ValueError, "official HTTPS Microsoft fwlink"
            ):
                self.edited(lambda v: v["profiles"]["win11_26h2_en_us_x64"].update(
                    downloadUrl=link))

    def test_json_metadata_never_claims_client_boot(self):
        p = subprocess.run(
            [sys.executable, str(SCRIPT), "--mode", "metadata"],
            capture_output=True, text=True, timeout=8,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        record = json.loads(p.stdout)
        self.assertFalse(record["windowsClientBootVerified"])
        self.assertFalse(record["stableForWindows10Or11"])

    def test_no_ci_consent_prevents_virtualization_approval(self):
        env = os.environ.copy()
        env.pop("GASLUX_VM_TEST_CONSENT", None)
        env.pop("GITHUB_ACTIONS", None)
        env.pop("RUNNER_OS", None)
        with patch.dict(os.environ, env, clear=True):
            report = gate.host_report()
        self.assertFalse(report["ok"] if "ok" in report else report["readyForWindows10X64Guest"])
        self.assertIn("dedicated authorized GitHub-hosted Linux runner absent",
                      report["blockers"])
        self.assertFalse(report["windowsAndLinuxDualBootVerified"])
        self.assertFalse(report["productionStable"])

    def test_missing_kvm_is_hard_blocker(self):
        with patch.object(gate, "kvm_accessible", return_value=False):
            report = gate.host_report()
        self.assertFalse(report["readyForWindows11X64Guest"])
        self.assertTrue(any("KVM" in b for b in report["blockers"]))

    def test_existing_report_file_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "report.json"
            output.write_text("marker", encoding="utf-8")
            p = subprocess.run(
                [sys.executable, str(SCRIPT), "--mode", "metadata",
                 "--report", str(output)],
                capture_output=True, text=True, timeout=8,
            )
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(output.read_text(), "marker")

    def test_symlink_report_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / "original.json"
            original.write_text("do not touch", encoding="utf-8")
            link = Path(d) / "report.json"
            link.symlink_to(original)
            p = subprocess.run(
                [sys.executable, str(SCRIPT), "--mode", "metadata",
                 "--report", str(link)],
                capture_output=True, text=True, timeout=8,
            )
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(original.read_text(), "do not touch")


if __name__ == "__main__":
    unittest.main()
