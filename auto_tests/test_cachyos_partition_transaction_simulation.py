"""Fail-closed, no-I/O partition transaction simulation tests."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
gpt = load("gpt_windows_fixture", HERE / "test_windows_cachyos_qcow2_gpt_readonly.py")
sim = load("transaction_simulation", HERE / "tools/cachyos_partition_transaction_simulation.py")


def fixture():
    front, back = gpt.create_disk_windows()
    report = gpt.gpt.inspect_gpt_windows(front, back)

    # The newer read-only GPT auditor intentionally does NOT publish a
    # candidate write extent or canonical PMBR authority. The *test fixture*
    # can reconstruct the old simulation-only fields from these known,
    # synthetic and already CRC-validated GPT bytes. Never use this adapter
    # for an actual Windows disk or as proof that writes are permitted.
    total_sectors = report["virtualDiskBytes"] // 512
    last_usable = struct.unpack_from("<Q", front, 512 + 48)[0]
    assert last_usable == total_sectors - 34
    last_windows_lba = report["windowsPartitions"][-1]["lastLba"]
    alignment = 2048  # 1 MiB, synthetic GPT only
    first = ((last_windows_lba + alignment) // alignment) * alignment
    last = ((last_usable + 1) // alignment) * alignment - 1
    assert last_windows_lba < first <= last <= last_usable
    assert (last - first + 1) * 512 >= 40 * 1024**3

    pmbr_start, pmbr_size = struct.unpack_from("<II", front, 446 + 8)
    canonical_pmbr = pmbr_start == 1 and pmbr_size == total_sectors - 1
    report["protectiveMbrCanonical"] = canonical_pmbr
    report["protectiveMbrOversizedWindowsLabException"] = not canonical_pmbr
    report["gptAuditWindowsSha256"] = hashlib.sha256(front + back).hexdigest()
    report["observedPostWindowsFreeExtent"] = {
        "firstLba": first,
        "lastLba": last,
        "lengthBytes": (last - first + 1) * 512,
        "alignmentBytes": alignment * 512,
        "readOnlyObservation": True,
        "partitionCreated": False,
        "linuxWriteAuthorized": False,
        "recoveryAndOwnershipProofRequired": True,
    }
    area = report["observedPostWindowsFreeExtent"]
    plan = {
        "transactionId": "a" * 32,
        "expectedDiskGuidSha256": report["diskGuidSha256"],
        "expectedGptAuditWindowsSha256": report["gptAuditWindowsSha256"],
        "expectedFirstLba": area["firstLba"],
        "expectedLastLba": area["lastLba"],
    }
    return report, plan


class TransactionSimulationTests(unittest.TestCase):
    def test_valid_report_yields_no_authority_and_deterministic_digest(self):
        report, plan = fixture()
        result = sim.propose(report, plan)
        self.assertEqual(result, sim.propose(report, plan))
        self.assertTrue(result["simulationOnly"])
        for key in ("storageWritesAuthorized", "partitionCreated", "recoveryPrepared",
                    "recoveryVerified", "windowsBootAfterLinuxVerified",
                    "sameDiskDualBootVerified", "releaseEligible"):
            self.assertIs(result[key], False)
        self.assertEqual(len(result["proposalSha256"]), 64)
        self.assertEqual(result["identity"]["firstLba"], plan["expectedFirstLba"])

    def test_foreign_disk_or_stale_gpt_bytes_rejected(self):
        for key in ("expectedDiskGuidSha256", "expectedGptAuditWindowsSha256"):
            with self.subTest(key=key):
                report, plan = fixture()
                plan[key] = "0" * 64
                with self.assertRaisesRegex(sim.ProposalRejected, "stale or foreign"):
                    sim.propose(report, plan)

    def test_wrong_partition_extent_rejected(self):
        for field, adjustment in (("expectedFirstLba", 2048),
                                  ("expectedLastLba", -2048)):
            report, plan = fixture()
            plan[field] += adjustment
            with self.assertRaisesRegex(sim.ProposalRejected, "stale extent"):
                sim.propose(report, plan)

    def test_noncanonical_pmbr_read_only_exception_still_rejected(self):
        report, plan = fixture()
        report["protectiveMbrCanonical"] = False
        report["protectiveMbrOversizedWindowsLabException"] = True
        with self.assertRaisesRegex(sim.ProposalRejected, "noncanonical"):
            sim.propose(report, plan)

    def test_missing_or_claimed_recovery_and_authority_rejected(self):
        for key, replacement in (("readOnlyObservation", False),
                                 ("partitionCreated", True),
                                 ("linuxWriteAuthorized", True),
                                 ("recoveryAndOwnershipProofRequired", False)):
            report, plan = fixture()
            report["observedPostWindowsFreeExtent"][key] = replacement
            with self.subTest(key=key), self.assertRaisesRegex(
                    sim.ProposalRejected, "protected read-only"):
                sim.propose(report, plan)
        report, plan = fixture()
        report["storageWritesAuthorized"] = True
        with self.assertRaisesRegex(sim.ProposalRejected, "authority"):
            sim.propose(report, plan)

    def test_geometry_overlap_and_length_corruption_rejected(self):
        for field, replacement in (("firstLba", 2048),
                                   ("lengthBytes", 0),
                                   ("lastLba", 2**32)):
            report, plan = fixture()
            report["observedPostWindowsFreeExtent"][field] = replacement
            if field in ("firstLba", "lastLba"):
                plan["expectedFirstLba" if field == "firstLba" else "expectedLastLba"] = replacement
            with self.subTest(field=field), self.assertRaises(sim.ProposalRejected):
                sim.propose(report, plan)

    def test_invalid_plan_types_and_extra_keys_rejected(self):
        for field, value in (("transactionId", "../tmp"),
                             ("expectedFirstLba", True),
                             ("expectedGptAuditWindowsSha256", "BAD")):
            report, plan = fixture()
            plan[field] = value
            with self.subTest(field=field), self.assertRaises(sim.ProposalRejected):
                sim.propose(report, plan)
        report, plan = fixture()
        plan["device"] = "/dev/sda"
        with self.assertRaisesRegex(sim.ProposalRejected, "unknown/missing"):
            sim.propose(report, plan)

    def test_missing_gpt_proof_rejected(self):
        report, plan = fixture()
        report["candidateWindowsGptPrimaryAndBackupConsistent"] = False
        with self.assertRaisesRegex(sim.ProposalRejected, "unproven"):
            sim.propose(report, plan)


if __name__ == "__main__":
    unittest.main()
