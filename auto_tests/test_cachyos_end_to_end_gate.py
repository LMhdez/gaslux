"""Tests of the external Windows/CachyOS evidence gate (never runs VMs).

These tests prove that malformed, missing and tampered E2E evidence is
rejected. They DO NOT prove any dual-boot scenario has actually run.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "auto_tests/tools/cachyos_release_gate.py"
SPEC = importlib.util.spec_from_file_location("gaslux_cachyos_release_gate", FILE)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
COMMIT = "a" * 40


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
class CachyosEndToEndGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.private = self.root / "reviewer-private.pem"
        self.public = self.root / "reviewer-public.pem"
        self.report = self.root / "report.json"
        self.signature = self.root / "report.sig"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                        "-out", str(self.private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.private),
                        "-pubout", "-out", str(self.public)], check=True, capture_output=True)
        self.data = {
            "schemaVersion": 1,
            "repository": "LMhdez/gaslux",
            "sourceCommit": COMMIT,
            "installerSha256": "b" * 64,
            "labs": [],
        }
        for index, profile in enumerate(sorted(gate.PROFILES), start=1):
            rows = {}
            for case in sorted(gate.CASES):
                evidence = []
                for label in ("windows-state", "linux-and-recovery"):
                    path = f"{profile}/{case}/{label}.log"
                    dest = self.artifacts / path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(f"synthetic fixture: {profile}/{case}/{label}".encode())
                    evidence.append({
                        "path": path,
                        "sha256": hashlib.sha256(dest.read_bytes()).hexdigest(),
                    })
                rows[case] = {
                    "status": "passed",
                    "runId": f"simulated-{profile}-{case}",
                    "checks": {name: True for name in gate.CASES[case]},
                    "artifacts": evidence,
                }
            self.data["labs"].append({
                "profile": profile,
                "vmId": 500 + index,
                "snapshot": "preinstall-test",
                "cases": rows,
            })

    def sign(self, content=None):
        data = self.data if content is None else content
        self.report.write_bytes(gate.canonical_json(data))
        result = subprocess.run(["openssl", "pkeyutl", "-sign",
                                 "-inkey", str(self.private), "-rawin",
                                 "-in", str(self.report), "-out", str(self.signature)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def checked(self):
        self.sign()
        data = gate.verify_reviewer_signature(self.report, self.signature, self.public)
        return gate.check_report(data, artifacts=self.artifacts, expected_commit=COMMIT)

    def test_signed_fixture_structure_accepted_but_not_released(self):
        result = self.checked()
        self.assertEqual(result["verifiedScenarios"], 2 * len(gate.CASES))
        self.assertEqual(result["validatedArtifactFiles"], 4 * len(gate.CASES))
        self.assertTrue(result["reviewerSignatureValid"])
        self.assertFalse(result["realDiskInstallerReleased"])

    def test_missing_reviewer_key_rejected(self):
        self.sign()
        with self.assertRaisesRegex(gate.GateError, "trusted reviewer key"):
            gate.verify_reviewer_signature(
                self.report, self.signature, self.root / "missing-public.pem"
            )

    def test_unsigned_report_rejected(self):
        self.sign()
        self.signature.write_bytes(b"\x00" * 64)
        with self.assertRaisesRegex(gate.GateError, "signature rejected"):
            gate.verify_reviewer_signature(self.report, self.signature, self.public)

    def test_modified_signed_report_rejected(self):
        self.sign()
        altered = copy.deepcopy(self.data)
        altered["labs"][0]["cases"]["secureboot-refusal"]["status"] = "failed"
        self.report.write_bytes(gate.canonical_json(altered))
        with self.assertRaisesRegex(gate.GateError, "signature rejected"):
            gate.verify_reviewer_signature(self.report, self.signature, self.public)

    def test_wrong_source_commit_rejected(self):
        self.sign()
        with self.assertRaisesRegex(gate.GateError, "exact source commit"):
            gate.check_report(self.data, artifacts=self.artifacts, expected_commit="c" * 40)

    def test_missing_windows11_rejected(self):
        self.data["labs"] = self.data["labs"][:1]
        with self.assertRaisesRegex(gate.GateError, "Windows 10 and Windows 11"):
            gate.check_report(self.data, artifacts=self.artifacts, expected_commit=COMMIT)

    def test_missing_power_loss_case_rejected(self):
        self.data["labs"][0]["cases"].pop("failure-powercut-rollback")
        with self.assertRaisesRegex(gate.GateError, "complete matrix"):
            gate.check_report(self.data, artifacts=self.artifacts, expected_commit=COMMIT)

    def test_false_positive_rollback_rejected(self):
        self.data["labs"][0]["cases"]["postinstall-rollback"]["checks"]["bcd_restored"] = False
        with self.assertRaisesRegex(gate.GateError, "missing independently checked"):
            gate.check_report(self.data, artifacts=self.artifacts, expected_commit=COMMIT)

    def test_duplicate_virtual_machine_id_rejected(self):
        self.data["labs"][1]["vmId"] = self.data["labs"][0]["vmId"]
        with self.assertRaisesRegex(gate.GateError, "duplicated lab VM"):
            gate.check_report(self.data, artifacts=self.artifacts, expected_commit=COMMIT)

    def test_tampered_evidence_log_rejected(self):
        path = self.artifacts / self.data["labs"][0]["cases"]["nominal-linux-first"]["artifacts"][0]["path"]
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(gate.GateError, "hash mismatch"):
            gate.check_report(self.data, artifacts=self.artifacts, expected_commit=COMMIT)

    def test_symlinked_external_evidence_rejected(self):
        path = self.artifacts / self.data["labs"][0]["cases"]["nominal-linux-first"]["artifacts"][0]["path"]
        outside = self.root / "secret.log"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(gate.GateError, "missing or linked evidence"):
            gate.check_report(self.data, artifacts=self.artifacts, expected_commit=COMMIT)

    def test_noncanonical_signed_json_rejected(self):
        self.sign()
        self.report.write_bytes(json.dumps(self.data, indent=2).encode())
        with self.assertRaisesRegex(gate.GateError, "canonical"):
            gate.verify_reviewer_signature(self.report, self.signature, self.public)

    def test_cli_fails_closed_without_pinned_public_key(self):
        self.sign()
        result = subprocess.run(
            ["python3", str(FILE), "--report", str(self.report),
             "--signature", str(self.signature),
             "--artifacts", str(self.artifacts), "--source-commit", COMMIT],
            check=False, capture_output=True, text=True, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["ready"], False)


if __name__ == "__main__":
    unittest.main()
