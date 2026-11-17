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

INITIAL_SERIAL = b'BdsDxe: starting Boot00AF "UEFI QEMU DVD-ROM LAB"\r\n'


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
        "diagnostic": "installed Windows client audit and clean VM poweroff verified",
        "dualBootVerified": False,
        "winReAndBcdRecovered": False,
        "stable": False,
        "firstLogonScriptSha256": hashlib.sha256((
            GATE.witness_powershell(profile, build) + "\n"
        ).encode("utf-8")).hexdigest(),
        "labDerivedIsoSha256": "b" * 64,
        "initialDvdGuestSerialSha256": hashlib.sha256(INITIAL_SERIAL).hexdigest(),
    }
    digest = hashlib.sha256(serial).hexdigest()
    manifest = f"{digest}  {profile}-serial.log\n".encode()
    return report, serial, manifest



def synthetic_post_overlay():
    """Document-only fixture: independent CI verifies the actual third serial."""
    report, serial, manifest = synthetic("win10_22h2_en_us_x64")
    build = "19045"
    first = GATE.witness_powershell(
        report["profile"], build, arm_post_overlay=True) + "\n"
    second = GATE.witness_powershell(
        report["profile"], build, post_overlay=True) + "\n"
    report["firstLogonScriptSha256"] = hashlib.sha256(
        first.encode("utf-8")).hexdigest()
    report["postOverlayGuestAuditScriptSha256"] = hashlib.sha256(
        second.encode("utf-8")).hexdigest()
    report["windowsPostOverlaySerialSha256"] = "b" * 64
    report["windowsPostOverlayBootVerified"] = True
    report["disposableOverlayExperiment"] = {
        "overlayFaultRejected": True,
        "overlayDiscarded": True,
        "backingWindowsGptUnchanged": True,
        "windowsRebootAfterFaultVerified": True,
        "windowsBcdWinreReobservedAfterDiscard": True,
        "windowsBcdWinreRestorationVerified": False,
        "linuxInstalled": False,
        "dualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }
    return report, serial, manifest



class WindowsCachyosReadonlyBaselineGateTests(unittest.TestCase):

    def test_post_overlay_win10_both_guest_scripts_pinned_by_source(self):
        report, serial, manifest = synthetic_post_overlay()
        result = self.exercise(report, serial, manifest)
        self.assertTrue(result["candidateWindowsFirstbootDocumentsConsistent"])
        for field in ("storageWritesAuthorized", "releaseEligible",
                      "windowsBcdWinreRestorationVerified", "sameDiskDualBootVerified"):
            self.assertFalse(result[field])

    def test_post_overlay_rejects_edited_first_or_second_guest_script_sha(self):
        for key in ("firstLogonScriptSha256", "postOverlayGuestAuditScriptSha256"):
            with self.subTest(key=key):
                report, serial, manifest = synthetic_post_overlay()
                report[key] = "0" * 64
                with self.assertRaises(GATE.BaselineGateError):
                    self.exercise(report, serial, manifest)

    def test_post_overlay_rejects_missing_or_unauthorized_lab_proof(self):
        for key in ("overlayFaultRejected", "overlayDiscarded",
                    "backingWindowsGptUnchanged", "windowsRebootAfterFaultVerified",
                    "windowsBcdWinreReobservedAfterDiscard"):
            with self.subTest(key=key):
                report, serial, manifest = synthetic_post_overlay()
                report["disposableOverlayExperiment"][key] = False
                with self.assertRaisesRegex(
                        GATE.BaselineGateError, "post-overlay lab flags"):
                    self.exercise(report, serial, manifest)
        report, serial, manifest = synthetic_post_overlay()
        report["disposableOverlayExperiment"]["storageWritesAuthorized"] = True
        with self.assertRaisesRegex(GATE.BaselineGateError, "authority"):
            self.exercise(report, serial, manifest)

    def test_post_overlay_rejects_missing_mode_or_malformed_sha(self):
        report, serial, manifest = synthetic_post_overlay()
        del report["windowsPostOverlayBootVerified"]
        with self.assertRaises(GATE.BaselineGateError):
            self.exercise(report, serial, manifest)
        report, serial, manifest = synthetic_post_overlay()
        report["windowsPostOverlaySerialSha256"] = "not-sha"
        with self.assertRaisesRegex(GATE.BaselineGateError, "post-overlay serial"):
            self.exercise(report, serial, manifest)

    def test_default_firstlogon_requires_original_hash(self):
        report, serial, manifest = synthetic("win10_22h2_en_us_x64")
        report["firstLogonScriptSha256"] = hashlib.sha256((
            GATE.witness_powershell(report["profile"], "19045",
                                    arm_post_overlay=True) + "\n"
        ).encode()).hexdigest()
        with self.assertRaisesRegex(GATE.BaselineGateError, "FirstLogon"):
            self.exercise(report, serial, manifest)


    def exercise(self, report, serial, manifest, initial_serial=INITIAL_SERIAL,
                 initial_manifest=None):
        if initial_manifest is None:
            initial_manifest = (
                hashlib.sha256(initial_serial).hexdigest() + "  " +
                report["profile"] + "-initial-dvd-serial.log\n"
            ).encode("ascii")
        return GATE.evaluate(
            report["profile"], report, serial, manifest,
            initial_serial, initial_manifest,
        )

    def exercise_with_profile(self, profile, report, serial, manifest):
        initial_manifest = (
            hashlib.sha256(INITIAL_SERIAL).hexdigest() + "  " +
            report["profile"] + "-initial-dvd-serial.log\n"
        ).encode("ascii")
        return GATE.evaluate(
            profile, report, serial, manifest, INITIAL_SERIAL, initial_manifest,
        )

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

    def test_original_microsoft_iso_candidate_never_authorizes_writes(self):
        for profile in ("win10_22h2_en_us_x64", "win11_26h2_en_us_x64"):
            with self.subTest(profile=profile):
                report, serial, manifest = synthetic(profile)
                report["labDerivedIsoOnly"] = False
                report.pop("labDerivedIsoSha256")
                proof = self.exercise(report, serial, manifest)
                self.assertIs(
                    proof["candidateWindowsFirstbootDocumentsConsistent"], True
                )
                self.assertIs(proof["windowsGuestOriginAuthenticated"], False)
                self.assertIs(proof["windowsBootVerified"], False)
                self.assertIs(proof["sameDiskDualBootVerified"], False)
                self.assertIs(proof["storageWritesAuthorized"], False)
                self.assertIs(proof["releaseEligible"], False)

    def test_original_iso_with_derivative_sha_rejected(self):
        report, serial, manifest = synthetic()
        report["labDerivedIsoOnly"] = False
        with self.assertRaisesRegex(GATE.BaselineGateError, "cannot claim"):
            self.exercise(report, serial, manifest)

    def test_missing_or_incorrect_media_mode_rejected(self):
        report, serial, manifest = synthetic()
        for value in (None, 0, 1, "true", "false", [], {}):
            with self.subTest(value=value):
                candidate = copy.deepcopy(report)
                candidate["labDerivedIsoOnly"] = value
                with self.assertRaisesRegex(
                    GATE.BaselineGateError, "explicit boolean"
                ):
                    self.exercise(candidate, serial, manifest)
        candidate = copy.deepcopy(report)
        del candidate["labDerivedIsoOnly"]
        with self.assertRaises(GATE.BaselineGateError):
            self.exercise(candidate, serial, manifest)

    def test_derived_iso_without_sha_rejected(self):
        report, serial, manifest = synthetic()
        del report["labDerivedIsoSha256"]
        with self.assertRaisesRegex(GATE.BaselineGateError, "distinct SHA256"):
            self.exercise(report, serial, manifest)

    def test_derived_iso_same_sha_as_original_rejected(self):
        report, serial, manifest = synthetic()
        report["labDerivedIsoSha256"] = GATE.EXPECTED[report["profile"]]
        with self.assertRaisesRegex(GATE.BaselineGateError, "distinct SHA256"):
            self.exercise(report, serial, manifest)

    def test_original_iso_bad_sha_rejected(self):
        report, serial, manifest = synthetic()
        report["labDerivedIsoOnly"] = False
        del report["labDerivedIsoSha256"]
        report["isoSha256"] = "0" * 64
        with self.assertRaisesRegex(GATE.BaselineGateError, "pinned Microsoft"):
            self.exercise(report, serial, manifest)

    def test_original_iso_unverified_source_rejected(self):
        report, serial, manifest = synthetic()
        report["labDerivedIsoOnly"] = False
        del report["labDerivedIsoSha256"]
        for field in ("isoHashVerified", "officialIsoUnmodified"):
            with self.subTest(field=field):
                candidate = copy.deepcopy(report)
                candidate[field] = False
                with self.assertRaisesRegex(
                    GATE.BaselineGateError, "missing Windows lab proof"
                ):
                    self.exercise(candidate, serial, manifest)

    def test_actual_original_microsoft_dvd_timeout_never_certifies_firstboot(self):
        for profile in ("win10_22h2_en_us_x64", "win11_26h2_en_us_x64"):
            with self.subTest(profile=profile):
                report, serial, manifest = synthetic(profile)
                report["labDerivedIsoOnly"] = False
                del report["labDerivedIsoSha256"]
                first = (INITIAL_SERIAL +
                    b'Press any key to boot from CD or DVD......\r\n'
                    b'BdsDxe: failed to start Boot00AF "UEFI QEMU DVD-ROM QM00003": Time out\r\n')
                report["initialDvdGuestSerialSha256"] = (
                    hashlib.sha256(first).hexdigest()
                )
                with self.assertRaisesRegex(
                    GATE.BaselineGateError, "firmware reported a boot timeout"
                ):
                    self.exercise(report, serial, manifest, first)

    def test_derived_microsoft_dvd_timeout_never_certifies_firstboot(self):
        report, serial, manifest = synthetic()
        first = (INITIAL_SERIAL +
                 b'BdsDxe: failed to start Boot0001 "UEFI QEMU DVD-ROM": Time out\n')
        report["initialDvdGuestSerialSha256"] = hashlib.sha256(first).hexdigest()
        with self.assertRaisesRegex(
            GATE.BaselineGateError, "firmware reported a boot timeout"
        ):
            self.exercise(report, serial, manifest, first)

    def test_original_iso_prompt_without_boot_timeout_stays_document_only(self):
        report, serial, manifest = synthetic("win10_22h2_en_us_x64")
        report["labDerivedIsoOnly"] = False
        del report["labDerivedIsoSha256"]
        first = INITIAL_SERIAL + b"Press any key to boot from CD or DVD......\r\n"
        report["initialDvdGuestSerialSha256"] = hashlib.sha256(first).hexdigest()
        result = self.exercise(report, serial, manifest, first)
        self.assertTrue(result["candidateWindowsFirstbootDocumentsConsistent"])
        self.assertFalse(result["windowsBootVerified"])
        self.assertFalse(result["storageWritesAuthorized"])

    def test_timeout_in_other_firmware_boot_id_rejected(self):
        report, serial, manifest = synthetic("win10_22h2_en_us_x64")
        first = INITIAL_SERIAL + (
            b'BdsDxe: failed to start Boot12AB "UEFI QEMU DVD-ROM": Time out\n'
        )
        report["initialDvdGuestSerialSha256"] = hashlib.sha256(first).hexdigest()
        with self.assertRaisesRegex(
            GATE.BaselineGateError, "firmware reported a boot timeout"
        ):
            self.exercise(report, serial, manifest, first)

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

    def test_weak_qemu_exit_without_verified_audit_rejected(self):
        report, serial, manifest = synthetic()
        report["diagnostic"] = (
            "QEMU exited before installed Windows first-logon witness "
            "(QEMU exit code 0; Windows still unverified)"
        )
        with self.assertRaisesRegex(GATE.BaselineGateError, "clean guest shutdown"):
            self.exercise(report, serial, manifest)

    def test_missing_clean_shutdown_witness_rejected(self):
        report, serial, manifest = synthetic()
        report.pop("diagnostic")
        with self.assertRaisesRegex(GATE.BaselineGateError, "clean guest shutdown"):
            self.exercise(report, serial, manifest)

    def test_arbitrary_firstlogon_script_digest_rejected(self):
        report, serial, manifest = synthetic()
        report["firstLogonScriptSha256"] = "a" * 64
        with self.assertRaisesRegex(GATE.BaselineGateError, "FirstLogon script SHA256"):
            self.exercise(report, serial, manifest)

    def test_altered_firstlogon_script_digest_rejected(self):
        report, serial, manifest = synthetic()
        actual = report["firstLogonScriptSha256"]
        report["firstLogonScriptSha256"] = (
            ("0" if actual[0] != "0" else "1") + actual[1:]
        )
        with self.assertRaisesRegex(GATE.BaselineGateError, "FirstLogon script SHA256"):
            self.exercise(report, serial, manifest)

    def test_unknown_prefixed_token_rejected_even_with_all_seven_proofs(self):
        report, serial, _ = synthetic()
        serial += b"GASLUX_WINDOWS_X64_EXTRA_PROOF=1\n"
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "unrecognized"):
            self.exercise(report, serial, manifest)

    def test_twelve_thousand_distinct_untrusted_markers_fail_closed(self):
        report, serial, _ = synthetic()
        noise = b"".join(
            f"GASLUX_WINDOWS_X64_NOISE_{i}=1\n".encode()
            for i in range(12000)
        )
        serial = noise + serial
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        with self.assertRaisesRegex(GATE.BaselineGateError, "unrecognized"):
            self.exercise(report, serial, manifest)

    def test_unrelated_firmware_output_is_not_a_windows_proof(self):
        report, serial, _ = synthetic()
        serial = (
            b"BdsDxe: starting Boot00AF \"UEFI Misc Device\"\n"
            b"firmware-debug log 0001\n" + serial
        )
        manifest = (hashlib.sha256(serial).hexdigest() + "  " +
                    report["profile"] + "-serial.log\n").encode()
        proof = self.exercise(report, serial, manifest)
        self.assertTrue(proof["candidateWindowsFirstbootDocumentsConsistent"])
        self.assertFalse(proof["windowsGuestOriginAuthenticated"])

    def test_wrong_profile_rejected(self):
        report, serial, manifest = synthetic()
        with self.assertRaises(GATE.BaselineGateError):
            self.exercise_with_profile("win10_22h2_en_us_x64", report, serial, manifest)

    def test_unknown_profile_rejected(self):
        report, serial, manifest = synthetic()
        with self.assertRaises(GATE.BaselineGateError):
            self.exercise_with_profile("win-server-2022", report, serial, manifest)

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
        with self.assertRaisesRegex(GATE.BaselineGateError, "unexpected prefix"):
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
            (root / "initial-dvd.log").write_bytes(INITIAL_SERIAL)
            (root / "initial-dvd.sha256").write_bytes((
                hashlib.sha256(INITIAL_SERIAL).hexdigest() + "  " +
                report["profile"] + "-initial-dvd-serial.log\n"
            ).encode("ascii"))
            cmd = [sys.executable, str(SOURCE), "--profile", report["profile"],
                   "--result", str(root / "report.json"),
                   "--serial", str(root / "guest.log"),
                   "--serial-sha256", str(root / "guest.sha256"),
                   "--initial-dvd-serial", str(root / "initial-dvd.log"),
                   "--initial-dvd-serial-sha256", str(root / "initial-dvd.sha256")]
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
                 "--serial-sha256", str(root / "guest.sha256"),
                 "--initial-dvd-serial", str(root / "initial-dvd.log"),
                 "--initial-dvd-serial-sha256", str(root / "initial-dvd.sha256")],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(json.loads(proc.stdout)["storageWritesAuthorized"])

    def test_initial_dvd_serial_hash_binds_to_report(self):
        report, serial, manifest = synthetic()
        changed = INITIAL_SERIAL + b"firmware debug change\n"
        with self.assertRaisesRegex(GATE.BaselineGateError, "Windows report"):
            self.exercise(report, serial, manifest, initial_serial=changed)

    def test_initial_dvd_serial_manifest_hash_is_required(self):
        report, serial, manifest = synthetic()
        with self.assertRaisesRegex(GATE.BaselineGateError, "evidence manifest"):
            self.exercise(report, serial, manifest,
                          initial_manifest=b"0" * 64 + b"  foreign.log\n")

    def test_initial_dvd_serial_manifest_rejects_cross_profile(self):
        report, serial, manifest = synthetic()
        wrong = (
            hashlib.sha256(INITIAL_SERIAL).hexdigest() +
            "  win10_22h2_en_us_x64-initial-dvd-serial.log\n"
        ).encode("ascii")
        with self.assertRaisesRegex(GATE.BaselineGateError, "evidence manifest"):
            self.exercise(report, serial, manifest, initial_manifest=wrong)

    def test_missing_initial_uefi_dvd_start_is_rejected(self):
        report, serial, manifest = synthetic()
        initial = b"BdsDxe: starting Boot00AF UEFI Misc Device\n"
        report["initialDvdGuestSerialSha256"] = hashlib.sha256(initial).hexdigest()
        with self.assertRaisesRegex(GATE.BaselineGateError, "exactly one"):
            self.exercise(report, serial, manifest, initial_serial=initial)

    def test_repeated_initial_dvd_start_is_rejected(self):
        report, serial, manifest = synthetic()
        initial = INITIAL_SERIAL + INITIAL_SERIAL
        report["initialDvdGuestSerialSha256"] = hashlib.sha256(initial).hexdigest()
        with self.assertRaisesRegex(GATE.BaselineGateError, "exactly one"):
            self.exercise(report, serial, manifest, initial_serial=initial)

    def test_initial_dvd_log_size_limit_is_consistent_with_archive(self):
        report, serial, manifest = synthetic()
        initial = INITIAL_SERIAL + b"X" * GATE.MAX_INITIAL_SERIAL
        with self.assertRaisesRegex(GATE.BaselineGateError, "oversized initial"):
            self.exercise(report, serial, manifest, initial_serial=initial)

    def test_initial_dvd_candidate_never_claims_authenticity(self):
        report, serial, manifest = synthetic()
        proof = self.exercise(report, serial, manifest)
        self.assertTrue(proof["initialDvdSerialManifestVerified"])
        self.assertTrue(proof["firstStageSingleDvdStartObserved"])
        self.assertFalse(proof["windowsGuestOriginAuthenticated"])
        self.assertFalse(proof["windowsBootVerified"])

    def test_no_disk_mutation_imports_or_calls(self):
        source = SOURCE.read_text()
        for forbidden in ("qemu-img", "sgdisk", "mkfs", "wipefs",
                          "subprocess.run(", "os.system(", "shutil.rmtree(",
                          "storageWritesAuthorized\": True",
                          "releaseEligible\": True"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
