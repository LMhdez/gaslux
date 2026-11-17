"""No-write candidate plan for two independently owned Pop GPT partitions."""
from __future__ import annotations

import copy
import pathlib
import sys
import unittest
import uuid

TOOLS = pathlib.Path(__file__).parent / "tools"
sys.path.insert(0, str(TOOLS))
from windows10_popos_gpt_mirror_gate import (  # noqa: E402
    parse_windows_pop_gpt, WINDOW_BYTES, SECTOR, DiskAuditError,
)
from windows10_popos_independent_esp_plan import propose_owned_esp_root  # noqa: E402
from test_windows10_popos_gpt_mirror_gate import make_pair  # noqa: E402

GIB = 1024**3
MIB = 1024**2
ESP_GUID = uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-pop-test-esp")
ROOT_GUID = uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-pop-test-root")


def fixture():
    front, back, _ = make_pair(linux=False)
    gpt = parse_windows_pop_gpt(front, back, expected_count=4)
    parts = []
    for part in gpt["windowsPartitions"]:
        parts.append({
            "number": part["number"],
            "typeGuid": part["type"],
            "partitionGuid": part["guid"],
            "offsetBytes": part["startLba"] * SECTOR,
            "sizeBytes": (part["endLba"]-part["startLba"]+1)*SECTOR,
        })
    windows = {
        "schemaVersion": 1,
        "profile": "win10_22h2_en_us_x64",
        "partitionCount": 4,
        "diskVirtualSizeBytes": 128*GIB,
        "storageWritesAuthorized": False,
        "partitions": parts,
    }
    return windows, gpt


class IndependentPopEspRootTests(unittest.TestCase):
    def test_two_owned_partitions_preserve_original_four_windows_records(self):
        win, gpt = fixture()
        snapshot = copy.deepcopy((win, gpt))
        plan = propose_owned_esp_root(win, gpt, ESP_GUID, ROOT_GUID)
        self.assertEqual(snapshot, (win, gpt))
        self.assertEqual([x["index"] for x in plan["partitions"]], [5, 6])
        self.assertEqual([x["sizeBytes"] for x in plan["partitions"]], [GIB, 24*GIB])
        self.assertEqual([x["formatRequested"] for x in plan["partitions"]], [False, False])
        self.assertEqual(plan["windowsProtectiveMbrSha256"], gpt["mbrSha256"])
        self.assertTrue(plan["windowsEspToRemainUntouched"])
        for flag in ("secureBootVerified", "signedHandoffVerified",
                     "productionInstallationAuthorized", "stable",
                     "linuxSystemInstalled", "sameDiskDualBootVerified"):
            self.assertIs(plan[flag], False)
        esp, root = plan["partitions"]
        self.assertEqual(esp["startSector"] % 2048, 0)
        self.assertEqual(root["startSector"] % 2048, 0)
        self.assertLess(esp["endSector"], root["startSector"])

    def test_refuse_false_gpt_proof_or_mutated_windows(self):
        for key, value in (
            ("primaryAndBackupCrcVerified", False),
            ("productionInstallationAuthorized", True),
            ("linuxRoot", {"number": 5}),
            ("mbrSha256", None),
        ):
            with self.subTest(field=key):
                win, gpt = fixture()
                gpt[key] = value
                with self.assertRaises(DiskAuditError):
                    propose_owned_esp_root(win, gpt, ESP_GUID, ROOT_GUID)
        for field, value in (
            ("offsetBytes", 0), ("sizeBytes", 1234),
            ("partitionGuid", str(uuid.uuid4())),
            ("typeGuid", "00000000-0000-0000-0000-000000000000"),
        ):
            with self.subTest(field=field):
                win, gpt = fixture()
                win["partitions"][0][field] = value
                with self.assertRaises(DiskAuditError):
                    propose_owned_esp_root(win, gpt, ESP_GUID, ROOT_GUID)

    def test_refuse_duplicate_foreign_or_non_uuid_partition_identity(self):
        win, gpt = fixture()
        for esp, root in (
            (ESP_GUID, ESP_GUID),
            (uuid.UUID(gpt["windowsPartitions"][0]["guid"]), ROOT_GUID),
            (ESP_GUID, uuid.UUID(int=0)),
            ("not-uuid", ROOT_GUID),
        ):
            with self.subTest(esp=str(esp), root=str(root)):
                with self.assertRaises(DiskAuditError):
                    propose_owned_esp_root(win, gpt, esp, root)

    def test_refuse_insufficient_space(self):
        win, gpt = fixture()
        win["partitions"][3]["sizeBytes"] = 90*GIB
        with self.assertRaises(DiskAuditError):
            propose_owned_esp_root(win, gpt, ESP_GUID, ROOT_GUID)

    def test_reject_gpt_crc_corruption_before_proposal(self):
        win, _ = fixture()
        front, back, _ = make_pair(linux=False)
        tampered = bytearray(front)
        tampered[SECTOR+50] ^= 1
        with self.assertRaises(DiskAuditError):
            gpt = parse_windows_pop_gpt(bytes(tampered), back, expected_count=4)
            propose_owned_esp_root(win, gpt, ESP_GUID, ROOT_GUID)


if __name__ == "__main__":
    unittest.main()
