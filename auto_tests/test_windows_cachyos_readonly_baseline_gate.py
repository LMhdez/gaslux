"""Synthetic evidence-only Windows/CachyOS gate; no Windows VM or disk I/O."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
SOURCE = TOOLS / "windows_cachyos_readonly_baseline_gate.py"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("win_cachyos_baseline_gate", SOURCE)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def synthetic(profile="win11_26h2_en_us_x64"):
    build = "26300" if profile.startswith("win11") else "19045"
    markers = [
        "BdsDxe: starting Boot0001 \"UEFI Misc Device\"",
        "GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
        "GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
        "GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
        "GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
        "GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
        "GASLUX_WINDOWS_X64_BOOT_BUILD=" + build,
        "GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=" + profile,
    ]
    serial = ("\n".join(markers) + "\n").encode()
    report = {
        "profile": profile,
        "accelerator": "kvm",
        "isoHashVerified": True,
        "isoSha256": GATE.EXPECTED[profile],
        "isoSizeBytes": 5 * 1024**3,
        "officialIsoUnmodified": True,
        "labDerivedIsoOnly": True,
        "windowsClientBootVerified": True,
        "dualBootVerified": False,
        "winReAndBcdRecovered": False,
        "stable": False,
        "firstLogonScriptSha256": "a" * 64,
        "labDerivedIsoSha256": "b" * 64,
        "initialDvdGuestSerialSha256": "c" * 64,
    }
    digest = hashlib.sha256(serial).hexdigest()
    manifest = f"{digest}  {profile}-serial.log\n".encode()
    return report, serial, manifest


class WindowsCachyosReadonlyBaselineGateTests(unittest.TestCase):
    def exercise(self, report, serial, manifest):
        return GATE.evaluate(report["profile"], report, serial, manifest)

    def test_windows_11_candidate_never_authorizes_storage(self):
        report, serial, manifest = synthetic()
        got = self.exercise(report, serial, manifest)
        self.assertIs(got["candidateWindowsFirstbootDocumentsConsistent"], True)
        for field in ("windowsBootVerified", "windowsGuestOriginAuthenticated",
                      "windowsBcdWinreRestorationVerified",
                      "sameDiskDualBootVerified", "storageWritesAuthorized",
                      "releaseEligible"):
            self.assertIs(got[field], False)

    def test_windows_10_candidate_never_authorizes_storage(self):
        report, serial, manifest = synthetic("win10_22h2_en_us_x64")
        got = self.exercise(report, serial, manifest)
        self.assertIs(got["storageWritesAuthorized"], False)
        self.assertTrue(got["pinnedMicrosoftIsoDigestMatched"])

    def test_actual_com1_markers_coalesced_on_same_line_are_accepted_as_documents(self):
        report, serial, _ = synthetic()
        first, *markers = serial.splitlines()
        coalesced = first + b"\n" + b" ".join(markers) + b"\n"
        manifest = (hashlib.sha256(coalesced).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        proof = self.exercise(report, coalesced, manifest)
        self.assertTrue(proof["candidateWindowsFirstbootDocumentsConsistent"])
        self.assertIs(proof["windowsBootVerified"], False)
        self.assertIs(proof["storageWritesAuthorized"], False)

    def test_coalesced_markers_without_whitespace_cannot_be_forged(self):
        report, serial, _ = synthetic()
        serial = serial.replace(
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1\nGASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
        )
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaises(GATE.BaselineGateError):
            self.exercise(report, serial, manifest)

    def test_repeated_coalesced_audit_token_rejected(self):
        report, serial, _ = synthetic()
        serial = serial.replace(
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1\n",
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1 GASLUX_WINDOWS_X64_WINRE_ENABLED=1\n",
        )
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "ambiguous"):
            self.exercise(report, serial, manifest)

    def test_conflicting_build_audit_token_rejected_even_with_valid_one(self):
        report, serial, _ = synthetic()
        serial += b"GASLUX_WINDOWS_X64_BOOT_BUILD=19045\n"
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "ambiguous"):
            self.exercise(report, serial, manifest)

    def test_failure_early_in_over_400kb_serial_is_never_lost(self):
        report, serial, _ = synthetic()
        serial = (b"GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL_STAGE=WinRE\n" +
                  b"firmware-debug " * 42000 + b"\n" + serial)
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "firstboot failure"):
            self.exercise(report, serial, manifest)

    def test_oversized_audit_token_rejected_before_consistency_claim(self):
        report, serial, _ = synthetic()
        serial += b"GASLUX_WINDOWS_X64_UNEXPECTED=" + b"A" * 300 + b"\n"
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "oversized"):
            self.exercise(report, serial, manifest)

    def test_wrong_profile_rejected(self):
        report, serial, manifest = synthetic()
        with self.assertRaises(GATE.BaselineGateError):
            GATE.evaluate("win10_22h2_en_us_x64", report, serial, manifest)

    def test_unknown_profile_rejected(self):
        report, serial, manifest = synthetic()
        with self.assertRaises(GATE.BaselineGateError):
            GATE.evaluate("win-server-2022", report, serial, manifest)

    def test_unverified_client_rejected(self):
        report, serial, manifest = synthetic()
        report["windowsClientBootVerified"] = False
        with self.assertRaisesRegex(GATE.BaselineGateError, "windowsClientBootVerified"):
            self.exercise(report, serial, manifest)

    def test_windows_server_product_type_marker_rejected(self):
        report, serial, manifest = synthetic()
        serial = serial.replace(b"BOOT_PRODUCTTYPE=1", b"BOOT_PRODUCTTYPE=3")
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "PRODUCTTYPE"):
            self.exercise(report, serial, manifest)

    def test_winre_disabled_marker_rejected(self):
        report, serial, manifest = synthetic()
        serial = serial.replace(b"WINRE_ENABLED=1", b"WINRE_ENABLED=0")
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "WINRE"):
            self.exercise(report, serial, manifest)

    def test_bcd_missing_rejected(self):
        report, serial, _ = synthetic()
        serial = serial.replace(b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1\n", b"")
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "BCD"):
            self.exercise(report, serial, manifest)

    def test_firstboot_witness_replayed_twice_rejected(self):
        report, serial, _ = synthetic()
        line = ("GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=" +
                report["profile"] + "\n").encode()
        serial += line
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "ambiguous"):
            self.exercise(report, serial, manifest)

    def test_wrong_iso_sha_rejected(self):
        report, serial, manifest = synthetic()
        report["isoSha256"] = "0" * 64
        with self.assertRaisesRegex(GATE.BaselineGateError, "pinned Microsoft"):
            self.exercise(report, serial, manifest)

    def test_claimed_dualboot_or_restored_winre_rejected(self):
        report, serial, manifest = synthetic()
        for field in ("dualBootVerified", "winReAndBcdRecovered", "stable"):
            with self.subTest(field=field):
                row = copy.deepcopy(report)
                row[field] = True
                with self.assertRaises(GATE.BaselineGateError):
                    self.exercise(row, serial, manifest)

    def test_missing_guest_origin_sha256_rejected(self):
        report, serial, manifest = synthetic()
        report["initialDvdGuestSerialSha256"] = None
        with self.assertRaisesRegex(GATE.BaselineGateError, "SHA256"):
            self.exercise(report, serial, manifest)

    def test_any_official_dvd_in_second_stage_rejected(self):
        report, serial, _ = synthetic()
        serial += b'BdsDxe: starting Boot00EF "UEFI QEMU DVD-ROM"\n'
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "DVD"):
            self.exercise(report, serial, manifest)

    def test_forged_manifest_digest_rejected(self):
        report, serial, manifest = synthetic()
        with self.assertRaisesRegex(GATE.BaselineGateError, "serial SHA256"):
            self.exercise(report, serial, b"0" * 64 + manifest[64:])

    def test_foreign_manifest_file_rejected(self):
        report, serial, manifest = synthetic()
        manifest = manifest.replace(b"-serial.log", b"-other.log")
        with self.assertRaises(GATE.BaselineGateError):
            self.exercise(report, serial, manifest)

    def test_prompt_or_echo_with_fake_marker_rejected(self):
        report, serial, _ = synthetic()
        serial = serial.replace(
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1\n",
            b"some fake login: GASLUX_WINDOWS_X64_WINRE_ENABLED=1\n",
        )
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "WINRE"):
            self.exercise(report, serial, manifest)

    def test_build_prefix_extension_rejected(self):
        report, serial, _ = synthetic()
        serial = serial.replace(b"BOOT_BUILD=26300", b"BOOT_BUILD=263000")
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "BUILD"):
            self.exercise(report, serial, manifest)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(GATE.BaselineGateError, "duplicate"):
            json.loads('{"profile":"win11","profile":"win10"}',
                       object_pairs_hook=GATE.unique_keys)

    def test_cli_valid_synthetic_candidate_only(self):
        report, serial, manifest = synthetic()
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            (root / "report.json").write_text(json.dumps(report))
            (root / "guest.log").write_bytes(serial)
            (root / "guest.sha256").write_bytes(manifest)
            cmd = [sys.executable, str(SOURCE), "--profile", report["profile"],
                   "--result", str(root / "report.json"),
                   "--serial", str(root / "guest.log"),
                   "--serial-sha256", str(root / "guest.sha256")]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=10, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            outcome = json.loads(proc.stdout)
            self.assertIs(outcome["storageWritesAuthorized"], False)

    def test_cli_symlink_and_missing_evidence_rejected(self):
        report, serial, manifest = synthetic()
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            (root / "report.json").write_text(json.dumps(report))
            (root / "guest.log").write_bytes(serial)
            (root / "manifest.real").write_bytes(manifest)
            (root / "guest.sha256").symlink_to(root / "manifest.real")
            proc = subprocess.run(
                [sys.executable, str(SOURCE), "--profile", report["profile"],
                 "--result", str(root / "report.json"),
                 "--serial", str(root / "guest.log"),
                 "--serial-sha256", str(root / "guest.sha256")],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(json.loads(proc.stdout)["storageWritesAuthorized"])

    def test_no_disk_mutation_imports_or_calls(self):
        source = SOURCE.read_text()
        for forbidden in ("qemu-img", "sgdisk", "mkfs", "wipefs",
                          "subprocess.run(", "os.system(", "shutil.rmtree(",
                          "storageWritesAuthorized\": True",
                          "releaseEligible\": True"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
