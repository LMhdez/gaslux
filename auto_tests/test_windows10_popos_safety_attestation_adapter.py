"""No writer: Safety #265 schema adaptation and distinst trace negative cases."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).parent / "tools"))
from test_windows10_popos_native_write_set import lab_fixture
from windows10_popos_native_write_set import propose_native_write_set, _digest
from windows10_popos_safety_attestation_adapter import (
    safety_snapshot_from_existing_gpt, compare_safety_snapshot,
    assess_pop_safety_handoff, classify_distinst_trace,
    interpret_safety267_no_writer,
)
import hashlib
import json
from windows_x64_installed_gpt_ro_audit import DiskAuditError


class PopSafetyAttestationNegativeContracts(unittest.TestCase):
    def setUp(self):
        self.inputs = lab_fixture()
        self.proposal = propose_native_write_set(*self.inputs)
        self.snapshot = safety_snapshot_from_existing_gpt(self.inputs[1])

    def test_safety265_shape_adapts_existing_crc_verified_gpt(self):
        after = self.inputs[1]
        self.assertEqual(self.snapshot["partitionTableId"], "gpt:" + after["diskGuid"])
        self.assertEqual(self.snapshot["partitionStyle"], "GPT")
        self.assertEqual([p["number"] for p in self.snapshot["partitions"]],
                         [1, 2, 3, 4, 5, 6])
        self.assertEqual(self.snapshot["partitions"][4]["partGuid"], after["popEsp"]["guid"])
        self.assertTrue(compare_safety_snapshot(self.snapshot, copy.deepcopy(self.snapshot)))

    def test_safety265_rejects_diskswap_geometry_partitionuuid(self):
        for name in ("disk", "size", "offset", "guid", "extra", "missing"):
            observed = copy.deepcopy(self.snapshot)
            if name == "disk":
                observed["partitionTableId"] = "gpt:" + str(uuid.uuid4())
            elif name == "size":
                observed["sizeBytes"] += 512
            elif name == "offset":
                observed["partitions"][5]["offsetBytes"] += 512
            elif name == "guid":
                observed["partitions"][4]["partGuid"] = str(uuid.uuid4())
            elif name == "extra":
                observed["partitions"].append(copy.deepcopy(observed["partitions"][-1]))
            else:
                observed["partitions"][4].pop("partGuid")
            with self.subTest(name=name), self.assertRaises(DiskAuditError):
                compare_safety_snapshot(self.snapshot, observed)

    def test_safety265_rejects_missing_malformed_unverified_layout(self):
        for invalid in (None, {}, {"diskSnapshot": self.snapshot},
                        {"schemaVersion": 1, "transactionId": "bogus"}):
            with self.subTest(candidate=invalid), self.assertRaises(DiskAuditError):
                assess_pop_safety_handoff(self.proposal, invalid)
        after = copy.deepcopy(self.inputs[1])
        after["primaryAndBackupCrcVerified"] = False
        with self.assertRaises(DiskAuditError):
            safety_snapshot_from_existing_gpt(after)

    def test_safety_full_shaped_self_asserted_provenance_is_not_auth(self):
        att = {
            "schemaVersion": 1,
            "transactionId": self.proposal["transactionId"],
            "diskSnapshot": self.snapshot,
            "writeSetSha256": _digest(self.proposal),
            "provenance": {
                "producer": "GASLUX-SAFETY",
                "independentHostMeasurement": True,
                "independentGuestMeasurement": True,
                "physicalGuestBindingVerified": True,
            },
            "issuedAtUtc": "2026-11-20T09:00:00Z",
            "expiresAtUtc": "2026-11-20T10:00:00Z",
            "authenticator": {"verified": True, "algorithm": "Ed25519",
                              "signature": "f" * 128},
        }
        with self.assertRaisesRegex(DiskAuditError, "independently authenticated"):
            assess_pop_safety_handoff(self.proposal, att)
        for key, value in [
            ("transactionId", str(uuid.uuid4())),
            ("writeSetSha256", "0" * 64),
            ("authenticator", {}),
            ("provenance", {"producer": "unknown"}),
        ]:
            forged = copy.deepcopy(att)
            forged[key] = value
            with self.subTest(key=key), self.assertRaises(DiskAuditError):
                assess_pop_safety_handoff(self.proposal, forged)

    def _event(self, item):
        return {**item, "diskGuid": self.proposal["disk"]["guid"],
                "measurement": "block-write",
                "source": "independent-qemu-observer"}

    def test_syntactic_comparison_is_never_write_authorization(self):
        ev = [self._event(item) for item in self.proposal["ownedOperations"]]
        report = classify_distinst_trace(self.proposal, ev)
        self.assertTrue(report["eventsSyntacticallyWithinProposal"])
        self.assertFalse(report["allWritesObserved"])
        self.assertFalse(report["distinstExecutionAuthorized"])
        self.assertFalse(report["safetyAttestationAuthenticated"])

    def test_distinst_unknown_and_unowned_mutations_refused(self):
        original = self._event(self.proposal["ownedOperations"][0])
        for name in ("gpt", "windows_esp", "implicit_format",
                     "wrong_efi", "nvram", "disk_swap", "unknown",
                     "missing_provenance", "foreign_offset", "rootfs_overlap"):
            event = copy.deepcopy(original)
            if name == "gpt":
                event.update(operation="rewrite-gpt", partitionIndex=0,
                             offsetBytes=512, lengthBytes=512)
            elif name == "windows_esp":
                event.update(partitionIndex=1, partuuid=self.snapshot["partitions"][0]["partGuid"])
            elif name == "implicit_format":
                event["operation"] = "mkfs.vfat-implicit"
            elif name == "wrong_efi":
                event["mount"] = "/boot/efi/EFI/Microsoft"
            elif name == "nvram":
                event["operation"] = "write-efi-nvram"
            elif name == "disk_swap":
                event["diskGuid"] = str(uuid.uuid4())
            elif name == "unknown":
                event["operation"] = "unknown-op"
            elif name == "missing_provenance":
                event.pop("source")
            elif name == "foreign_offset":
                event["offsetBytes"] += 512
            else:
                event["lengthBytes"] += 512
            with self.subTest(name=name), self.assertRaises(DiskAuditError):
                classify_distinst_trace(self.proposal, [event])

    def test_trace_partial_crash_backing_drift_and_no_measurements_refuse(self):
        with self.assertRaises(DiskAuditError):
            classify_distinst_trace(self.proposal, [])
        partial = self._event(self.proposal["ownedOperations"][0])
        partial["source"] = "installer-self-log"
        with self.assertRaises(DiskAuditError):
            classify_distinst_trace(self.proposal, [partial])
        # Existing proposed transaction binds checkpoint SHA; changing either
        # backing before a new proposal MUST fail before writer runs.
        for name in ("snapshotOfGenuineWindowsParentSha256",
                     "snapshotOfSixGptWindowsStageSha256"):
            changed = copy.deepcopy(self.inputs)
            changed[6][name] = "f" * 64
            with self.subTest(parent=name), self.assertRaises(DiskAuditError):
                propose_native_write_set(*changed)



class Safety267NoWriterConsumerTests(unittest.TestCase):
    def setUp(self):
        self.inputs = lab_fixture()
        self.proposal = propose_native_write_set(*self.inputs)
        d = self.proposal["disk"]
        self.plan = {
            "planId": self.proposal["transactionId"].replace("-", ""),
            "firmware": "uefi",
            "disk": {"partitionStyle": "GPT",
                     "partitionTableId": "gpt:" + d["guid"],
                     "sizeBytes": d["sizeBytes"],
                     "logicalSectorSizeBytes": d["logicalSectorBytes"]},
        }
        self.vm_id = "verified-disposable-qemu-lab-001"

    def _decision(self, p=None):
        if p is None:
            p = self.plan
        canonical = json.dumps(p, sort_keys=True, separators=(",", ":"),
                               allow_nan=False).encode()
        return (canonical, {
            "decision": "ACCEPT_NO_WRITER",
            "transactionId": p["planId"],
            "planSha256": hashlib.sha256(canonical).hexdigest(),
            "vmId": self.vm_id,
            "writeCount": 1,
        })

    def test_safety267_accept_no_writer_is_never_pop_format_permission(self):
        payload, decision = self._decision()
        report = interpret_safety267_no_writer(
            self.proposal, decision, self.plan, payload, self.vm_id)
        self.assertTrue(report["decisionConformsToNoWriterShape"])
        self.assertFalse(report["evidenceCryptographicallyAuthenticatedByThisAdapter"])
        self.assertFalse(report["existingPopPartitionsWithinSafety267AllocateFreeSpace"])
        self.assertFalse(report["nativePartitionFormatterAllowed"])
        self.assertFalse(report["distinstExecutionAuthorized"])

    def test_safety267_missing_wrong_decision_and_foreign_transaction_denied(self):
        original, decision = self._decision()
        for field, value in [
            ("decision", "ACCEPT_WRITER"),
            ("transactionId", "b" * 32),
            ("planSha256", "0" * 64),
            ("vmId", "foreign-qemu-guest"),
            ("writeCount", 0),
            ("writeCount", True),
        ]:
            bad = {**decision, field: value}
            with self.subTest(field=field), self.assertRaises(DiskAuditError):
                interpret_safety267_no_writer(
                    self.proposal, bad, self.plan, original, self.vm_id)
        for unknown in (None, {}, {"decision": "ACCEPT_NO_WRITER"}):
            with self.assertRaises(DiskAuditError):
                interpret_safety267_no_writer(
                    self.proposal, unknown, self.plan, original, self.vm_id)

    def test_safety267_changed_disk_vm_plan_or_canonical_bytes_denied(self):
        canonical, decision = self._decision()
        with self.assertRaises(DiskAuditError):
            interpret_safety267_no_writer(self.proposal, decision, self.plan,
                                          canonical + b"\n", self.vm_id)
        with self.assertRaises(DiskAuditError):
            interpret_safety267_no_writer(self.proposal, decision, self.plan,
                                          canonical, "other-authorized-qemu-999")
        for field, value in [
            ("partitionTableId", "gpt:" + str(uuid.uuid4())),
            ("sizeBytes", 1), ("logicalSectorSizeBytes", 4096),
            ("partitionStyle", "MBR"),
        ]:
            p = copy.deepcopy(self.plan)
            p["disk"][field] = value
            data, dec = self._decision(p)
            with self.subTest(field=field), self.assertRaises(DiskAuditError):
                interpret_safety267_no_writer(
                    self.proposal, dec, p, data, self.vm_id)


if __name__ == "__main__":
    unittest.main()
