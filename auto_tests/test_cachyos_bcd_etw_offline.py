"""Synthetic ETW exported-event contracts; no ETL, Windows or collection."""
from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import cachyos_bcd_etw_contract_offline as etw


def evidence() -> dict:
    return {
        "session": {
            "sessionId": "20d447ba-5f4e-43bf-9fa9-c7a60db843f2",
            "windowsBuild": 19045,
            "bootIdentitySha256": "a" * 64,
            "traceSha256": "b" * 64,
            "clockKind": "QPC",
            "qpcFrequencyHz": 10000000,
            "sessionStartNs": 1000000000,
            "sessionEndNs": 3000000000,
            "lostEvents": 0,
            "lostBuffers": 0,
        },
        "events": [
            {"kind": "ProcessStart", "timestampNs": 1100000000, "pid": 42},
            {"kind": "FileIoName", "timestampNs": 1200000000,
             "fileObject": "0xa123", "fileName":
             r"\Device\HarddiskVolume1\EFI\Microsoft\Boot\BCD"},
            {"kind": "FileIoWrite", "timestampNs": 1300000000,
             "fileObject": "0xa123", "pid": 42, "irp": "0xbbb"},
            {"kind": "DiskIoWrite", "timestampNs": 1350000000,
             "irp": "0xbbb", "diskOffset": 1048576,
             "length": 512, "diskNumber": 0},
            {"kind": "ProcessStop", "timestampNs": 2000000000, "pid": 42},
        ],
    }


class EtwOfflineTests(unittest.TestCase):
    def test_complete_fixture_has_candidate_not_process_attribution(self):
        result = etw.normalize_etw_fixture(evidence())
        self.assertEqual(result["plausibleIrpLifetimeMatches"], 1)
        self.assertEqual(result["status"], "PROCESS_ATTRIBUTION_UNPROVEN")
        self.assertTrue(result["sessionCompleteWithinDeclaredWindow"])
        self.assertFalse(result["processAttributionProven"])
        self.assertFalse(result["qemuDiskNodeAuthenticated"])
        self.assertFalse(result["diskNumberBoundToGptIdentity"])
        self.assertFalse(result["approvedMutation"])
        self.assertNotIn("fileName", repr(result))
        self.assertNotIn("HarddiskVolume", repr(result))

    def test_no_pid_or_lifetime_is_unattributed(self):
        for key in ("pid", "irp"):
            with self.subTest(missing=key):
                fixture = evidence()
                del fixture["events"][2][key]
                result = etw.normalize_etw_fixture(fixture)
                self.assertEqual(result["plausibleIrpLifetimeMatches"], 0)
                self.assertFalse(result["processAttributionProven"])
        fixture = evidence()
        fixture["events"] = [event for event in fixture["events"]
                             if event["kind"] != "ProcessStart"]
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_missing_timestamps_are_reported_not_guessed(self):
        fixture = evidence()
        fixture["events"][3]["timestampNs"] = None
        result = etw.normalize_etw_fixture(fixture)
        self.assertEqual(result["missingTimestampCount"], 1)
        self.assertFalse(result["sessionCompleteWithinDeclaredWindow"])
        self.assertEqual(result["plausibleIrpLifetimeMatches"], 0)
        self.assertFalse(result["processAttributionProven"])

    def test_etw_lost_events_forbid_session_complete(self):
        for key in ("lostBuffers", "lostEvents"):
            with self.subTest(key=key):
                fixture = evidence()
                fixture["session"][key] = 1
                r = etw.normalize_etw_fixture(fixture)
                self.assertFalse(r["sessionCompleteWithinDeclaredWindow"])
                self.assertFalse(r["processAttributionProven"])

    def test_no_shared_irp_is_no_association(self):
        fixture = evidence()
        fixture["events"][3]["irp"] = "0xccc"
        result = etw.normalize_etw_fixture(fixture)
        self.assertEqual(result["plausibleIrpLifetimeMatches"], 0)
        self.assertFalse(result["processAttributionProven"])

    def test_ambiguous_name_reuse_prevents_candidate(self):
        fixture = evidence()
        fixture["events"].insert(2, {
            "kind": "FileIoName", "timestampNs": 1250000000,
            "fileObject": "0xa123", "fileName":
            r"\Device\HarddiskVolume1\EFI\Microsoft\Boot\BCD",
        })
        result = etw.normalize_etw_fixture(fixture)
        self.assertEqual(result["plausibleIrpLifetimeMatches"], 0)

    def test_session_constraints_and_unknown_fields_are_refused(self):
        for key, value in (
            ("windowsBuild", 22621), ("clockKind", "SYNTHETIC_CLOCK"),
            ("qpcFrequencyHz", 0), ("lostEvents", -1),
            ("traceSha256", "broken"),
        ):
            with self.subTest(field=key):
                fixture = evidence()
                fixture["session"][key] = value
                with self.assertRaises(etw.EtwContractError):
                    etw.normalize_etw_fixture(fixture)
        fixture = evidence()
        fixture["events"][2]["secret"] = "not allowed"
        with self.assertRaisesRegex(etw.EtwContractError, "fields"):
            etw.normalize_etw_fixture(fixture)

    def test_disk_offset_requires_device_and_bounded_write(self):
        for disk_number, offset, length in (
            (None, 1048576, 512), (0, -1, 512),
            (0, 1048576, 0), (0, 8 * 1024**4, 512),
        ):
            with self.subTest(case=(disk_number, offset, length)):
                fixture = evidence()
                event = fixture["events"][3]
                event["diskNumber"], event["diskOffset"], event["length"] = (
                    disk_number, offset, length)
                with self.assertRaisesRegex(etw.EtwContractError, "DiskIo"):
                    etw.normalize_etw_fixture(fixture)

    def test_sessions_before_start_not_observable(self):
        fixture = evidence()
        fixture["events"][3]["timestampNs"] = 999999999
        with self.assertRaisesRegex(etw.EtwContractError, "outside"):
            etw.normalize_etw_fixture(fixture)

    def test_etw01_red_01_diskio_before_fileio_not_plausible(self):
        fixture = evidence()
        fixture["events"][3]["timestampNs"] = 1250000000
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_red_02_pid_generation_overlaps_after_fileio(self):
        fixture = evidence()
        fixture["events"].insert(4, {
            "kind": "ProcessStart", "timestampNs": 1400000000, "pid": 42,
        })
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_repeated_irp_has_no_plausible_causal_pair(self):
        fixture = evidence()
        fixture["events"].insert(4, {
            "kind": "FileIoWrite", "timestampNs": 1420000000,
            "fileObject": "0xb456", "pid": 42, "irp": "0xbbb",
        })
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_reused_fileobject_later_name_invalidates_lifetime(self):
        fixture = evidence()
        fixture["events"].insert(4, {
            "kind": "FileIoName", "timestampNs": 1400000000,
            "fileObject": "0xa123", "fileName": "not-bcd",
        })
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_reused_irp_diskio_must_not_count(self):
        fixture = evidence()
        fixture["events"].insert(4, {
            "kind": "DiskIoWrite", "timestampNs": 1370000000,
            "irp": "0xbbb", "diskOffset": 1049088,
            "length": 512, "diskNumber": 0,
        })
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_stop_before_start_remains_unattributed(self):
        fixture = evidence()
        fixture["events"][0]["timestampNs"] = 1700000000
        fixture["events"][4]["timestampNs"] = 1600000000
        result = etw.normalize_etw_fixture(fixture)
        self.assertEqual(result["plausibleIrpLifetimeMatches"], 0)
        self.assertEqual(result["status"], "PROCESS_ATTRIBUTION_UNPROVEN")

    def test_etw01_overlapping_pid_generations_not_plausible(self):
        fixture = evidence()
        fixture["events"].insert(1, {
            "kind": "ProcessStart", "timestampNs": 1150000000, "pid": 42,
        })
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_multiple_process_stops_not_plausible(self):
        fixture = evidence()
        fixture["events"].append({
            "kind": "ProcessStop", "timestampNs": 2200000000, "pid": 42,
        })
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_far_apart_diskio_no_justified_bound(self):
        fixture = evidence()
        fixture["events"][3]["timestampNs"] = 1999999000
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_session_loss_disallows_plausible_pair(self):
        for field in ("lostEvents", "lostBuffers"):
            with self.subTest(field=field):
                fixture = evidence()
                fixture["session"][field] = 1
                result = etw.normalize_etw_fixture(fixture)
                self.assertFalse(result["sessionCompleteWithinDeclaredWindow"])
                self.assertEqual(result["plausibleIrpLifetimeMatches"], 0)

    def test_etw01_event_presentation_order_is_not_clock_proof(self):
        fixture = evidence()
        fixture["events"].reverse()
        self.assertEqual(
            etw.normalize_etw_fixture(fixture)["plausibleIrpLifetimeMatches"], 0
        )

    def test_etw01_structural_invalid_not_silent_denial(self):
        fixture = evidence()
        fixture["events"][3]["timestampNs"] = -1
        with self.assertRaisesRegex(etw.EtwContractError, "timestamp"):
            etw.normalize_etw_fixture(fixture)
        fixture = evidence()
        fixture["events"][2]["kind"] = "NotAnEtwEvent"
        with self.assertRaisesRegex(etw.EtwContractError, "unknown ETW"):
            etw.normalize_etw_fixture(fixture)

    def test_no_events_still_cannot_prove_process(self):
        fixture = evidence()
        fixture["events"] = []
        r = etw.normalize_etw_fixture(fixture)
        self.assertEqual(r["status"], "PROCESS_ATTRIBUTION_UNPROVEN")
        self.assertEqual(r["plausibleIrpLifetimeMatches"], 0)
        self.assertFalse(r["processAttributionProven"])


if __name__ == "__main__":
    unittest.main()
