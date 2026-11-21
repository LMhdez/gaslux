"""Fail-closed adversarial no-writer tests. No real disk or writer used."""
import copy
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "assets/live"))
import libertix_prewrite_no_writer as guard  # noqa: E402

TX, VM, NONCE = "a" * 32, "authorized-qemu-vm-001", "nonce" * 10
HOST_KEY, GUEST_KEY = b"h" * 32, b"g" * 32
PART = {"number": 1, "typeGuid": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
        "partGuid": "87654321-4321-4321-4321-cba987654321",
        "offsetBytes": 1048576, "sizeBytes": 4194304, "attributes": 0}
DISK = {"partitionStyle": "GPT",
        "partitionTableId": "gpt:12345678-1234-1234-1234-123456789abc",
        "sizeBytes": 16777216, "logicalSectorSizeBytes": 512,
        "partitions": [PART]}


def case():
    plan = {"planId": TX, "firmware": "uefi",
            "disk": {k: DISK[k] for k in
                     ("partitionStyle", "partitionTableId", "sizeBytes",
                      "logicalSectorSizeBytes")}}
    raw = guard.canonical(plan)
    def evidence(source, key):
        return guard.authenticated_record({
            "source": source, "transactionId": TX, "vmId": VM,
            "planSha256": hashlib.sha256(raw).hexdigest(), "nonce": NONCE,
            "snapshot": copy.deepcopy(DISK)}, key)
    return {"plan": plan, "plan_bytes": raw, "transaction_id": TX, "vm_id": VM,
            "host_evidence": evidence("host", HOST_KEY),
            "guest_evidence": evidence("guest", GUEST_KEY),
            "immediate_evidence": evidence("guest-immediate", GUEST_KEY),
            "host_key": HOST_KEY, "guest_key": GUEST_KEY, "fresh_nonce": NONCE,
            "owned_regions": [{"offsetBytes": 8388608, "sizeBytes": 1048576,
                               "ownerTransactionId": TX}],
            "write_set": [{"offsetBytes": 8388608, "sizeBytes": 1048576,
                           "operation": "allocate-free-space"}]}


def resign(case, field, key):
    case[field] = guard.authenticated_record(case[field]["payload"], key)


def test_correct_transaction_returns_no_writer_only():
    result = guard.decide_no_writer(**case())
    assert result["decision"] == "ACCEPT_NO_WRITER"
    assert "writer" not in result


@pytest.mark.parametrize("fault", [
    "other_disk", "same_size_other_guid", "partuuid", "offset", "size",
    "missing_partition", "plan_changed", "transaction_missing", "transaction_other",
    "write_outside", "missing_provenance", "changed_between_checks", "foreign_owner",
    "overlap_with_windows", "wrong_vm", "stale_nonce", "missing_key",
    "wrong_firmware", "wrong_part_table", "bad_mac", "missing_plan_bytes",
])
def test_adversarial_cases_never_reach_writer(fault):
    inputs = case()
    if fault == "other_disk":
        inputs["guest_evidence"]["payload"]["snapshot"]["sizeBytes"] += 512
        resign(inputs, "guest_evidence", GUEST_KEY)
    elif fault == "same_size_other_guid":
        inputs["guest_evidence"]["payload"]["snapshot"]["partitionTableId"] = (
            "gpt:00000000-1234-1234-1234-123456789abc")
        resign(inputs, "guest_evidence", GUEST_KEY)
    elif fault in ("partuuid", "offset", "size", "missing_partition"):
        part = inputs["guest_evidence"]["payload"]["snapshot"]["partitions"][0]
        if fault == "partuuid":
            part["partGuid"] = "00000000-4321-4321-4321-cba987654321"
        elif fault == "offset":
            part["offsetBytes"] += 512
        elif fault == "size":
            part["sizeBytes"] += 512
        else:
            part.pop("partGuid")
        resign(inputs, "guest_evidence", GUEST_KEY)
    elif fault == "plan_changed":
        inputs["plan"]["disk"]["sizeBytes"] += 512
    elif fault == "transaction_missing":
        inputs["transaction_id"] = ""
    elif fault == "transaction_other":
        inputs["transaction_id"] = "b" * 32
    elif fault == "write_outside":
        inputs["write_set"][0]["offsetBytes"] = 10485760
    elif fault == "missing_provenance":
        inputs["host_evidence"].pop("mac")
    elif fault == "changed_between_checks":
        inputs["immediate_evidence"]["payload"]["snapshot"]["partitions"][0][
            "offsetBytes"] += 512
        resign(inputs, "immediate_evidence", GUEST_KEY)
    elif fault == "foreign_owner":
        inputs["owned_regions"][0]["ownerTransactionId"] = "b" * 32
    elif fault == "overlap_with_windows":
        inputs["owned_regions"][0]["offsetBytes"] = 1048576
        inputs["write_set"][0]["offsetBytes"] = 1048576
    elif fault == "wrong_vm":
        inputs["guest_evidence"]["payload"]["vmId"] = "another-qemu-vm-111"
        resign(inputs, "guest_evidence", GUEST_KEY)
    elif fault == "stale_nonce":
        inputs["guest_evidence"]["payload"]["nonce"] = "x" * 40
        resign(inputs, "guest_evidence", GUEST_KEY)
    elif fault == "missing_key":
        inputs["host_key"] = b""
    elif fault == "wrong_firmware":
        inputs["plan"]["firmware"] = "bios"
        inputs["plan_bytes"] = guard.canonical(inputs["plan"])
    elif fault == "wrong_part_table":
        inputs["plan"]["disk"]["partitionStyle"] = "MBR"
        inputs["plan_bytes"] = guard.canonical(inputs["plan"])
    elif fault == "bad_mac":
        inputs["guest_evidence"]["mac"] = "0" * 64
    elif fault == "missing_plan_bytes":
        inputs["plan_bytes"] = b""
    with pytest.raises(guard.DiskIdentityError):
        guard.decide_no_writer(**inputs)
