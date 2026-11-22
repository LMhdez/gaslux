"""Synthetic ETW exported-event contracts; no ETL, Windows or collection."""
from __future__ import annotations

import copy
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

    def test_no_events_still_cannot_prove_process(self):
        fixture = evidence()
        fixture["events"] = []
        r = etw.normalize_etw_fixture(fixture)
        self.assertEqual(r["status"], "PROCESS_ATTRIBUTION_UNPROVEN")
        self.assertEqual(r["plausibleIrpLifetimeMatches"], 0)
        self.assertFalse(r["processAttributionProven"])


if __name__ == "__main__":
    unittest.main()
