"""Negative tests for read-only three-way disk identity agreement."""
import copy
import unittest

from auto_tests.tools.disk_identity_crosscheck import IdentityMismatch, compare_evidence


def fixture():
    record = {
        "transactionId": "a" * 32,
        "diskId": "disk-serial-1",
        "partitionTableId": "gpt-guid-1",
        "partitionStyle": "GPT",
        "sizeBytes": 10485760,
        "logicalSectorBytes": 512,
        "physicalSectorBytes": 4096,
        "partitionTableSha256": "b" * 64,
        "partitions": [
            {"id": "part-guid-1", "offsetBytes": 1048576,
             "sizeBytes": 1048576, "typeId": "efi",
             "contentSha256": "c" * 64},
            {"id": "part-guid-2", "offsetBytes": 2097152,
             "sizeBytes": 1048576, "typeId": "windows",
             "contentSha256": "d" * 64},
        ],
    }
    return {name: copy.deepcopy(record) for name in ("windows", "host", "guest")}


class CrosscheckTests(unittest.TestCase):
    def test_identical_evidence(self):
        self.assertTrue(compare_evidence(fixture()))

    def test_missing_source(self):
        records = fixture()
        del records["guest"]
        with self.assertRaises(IdentityMismatch):
            compare_evidence(records)

    def test_wrong_disk(self):
        records = fixture()
        records["guest"]["diskId"] = "foreign"
        with self.assertRaises(IdentityMismatch):
            compare_evidence(records)

    def test_sector_size_mismatch(self):
        records = fixture()
        records["host"]["logicalSectorBytes"] = 4096
        with self.assertRaises(IdentityMismatch):
            compare_evidence(records)

    def test_partition_content_mismatch(self):
        records = fixture()
        records["guest"]["partitions"][0]["contentSha256"] = "e" * 64
        with self.assertRaises(IdentityMismatch):
            compare_evidence(records)

    def test_overlapping_partitions(self):
        records = fixture()
        records["windows"]["partitions"][1]["offsetBytes"] = 1048576
        with self.assertRaises(IdentityMismatch):
            compare_evidence(records)

    def test_boolean_geometry_rejected(self):
        records = fixture()
        records["host"]["sizeBytes"] = True
        with self.assertRaises(IdentityMismatch):
            compare_evidence(records)

    def test_missing_digest_rejected(self):
        records = fixture()
        del records["host"]["partitionTableSha256"]
        with self.assertRaises(IdentityMismatch):
            compare_evidence(records)


if __name__ == "__main__":
    unittest.main()
