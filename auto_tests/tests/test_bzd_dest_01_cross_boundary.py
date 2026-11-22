"""BZD-DEST-01 independent adversarial contract tests, no disk or writer.

The real experimental #267 no-writer gate is imported at an immutable SHA
in CI; no gate is reimplemented here. Known-gap tests positively assert that the current gate lacks a required
interface; these MUST NOT be misread as a passed operational DENY gate.
"""
from __future__ import annotations

import copy
import hashlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(os.environ["GASLUX_267_SOURCE"]).resolve()
sys.path.insert(0, str(ROOT / "assets/live"))
sys.path.insert(0, str(ROOT / "auto_tests/tests"))
import libertix_prewrite_no_writer as gate  # noqa: E402
from test_prewrite_no_writer import GUEST_KEY, TX, case, resign  # noqa: E402


def _deny(value):
    with pytest.raises(gate.DiskIdentityError):
        gate.decide_no_writer(**value)


def _resign_snapshot(value, source="guest_evidence"):
    resign(value, source, GUEST_KEY)


def test_positive_well_formed_is_structural_only_and_never_authorizes_write():
    """Positive control makes an unconditional DENY implementation fail."""
    result = gate.decide_no_writer(**case())
    assert result["decision"] == "ACCEPT_NO_WRITER"
    assert "writerAuthorized" not in result
    assert "installationAuthorized" not in result
    assert "rollbackProven" not in result


@pytest.mark.parametrize("change", ["disk_guid", "disk_size", "part_guid"])
def test_a_foreign_disk_identity_in_authenticated_snapshot_denied(change):
    value = case()
    snapshot = value["guest_evidence"]["payload"]["snapshot"]
    if change == "disk_guid":
        snapshot["partitionTableId"] = "gpt:12345678-1234-1234-1234-123456789abd"
    elif change == "disk_size":
        snapshot["sizeBytes"] += 512
    else:
        snapshot["partitions"][0]["partGuid"] = "87654321-4321-4321-4321-cba987654322"
    _resign_snapshot(value)
    _deny(value)


def test_a_same_claims_different_qcow2_actual_destination_must_deny():
    """Same signed JSON is not proof that the selected QCOW2 is still the same."""
    value = case()
    selected_qcow2 = {"dev": 7, "inode": 200, "size": 16777216}
    swapped_qcow2 = {"dev": 7, "inode": 201, "size": 16777216}
    assert selected_qcow2 != swapped_qcow2
    # No destination/FD input exists in decide_no_writer; this MUST NOT pass.
    assert gate.decide_no_writer(**value)["decision"] == "ACCEPT_NO_WRITER"
    assert "destinationFdAuthenticated" not in gate.decide_no_writer(**value)


def test_b_fd_alias_same_claims_different_open_description_must_deny():
    value = case()
    pinned_fd = {"fd": 7, "dev": 11, "inode": 71}
    aliased_fd = {"fd": 9, "dev": 11, "inode": 72}
    assert pinned_fd["inode"] != aliased_fd["inode"]
    assert gate.decide_no_writer(**value)["decision"] == "ACCEPT_NO_WRITER"
    assert "qemuBackendFdBound" not in gate.decide_no_writer(**value)


@pytest.mark.parametrize("field", ["partitionTableId", "logicalSectorSizeBytes", "sizeBytes"])
def test_c_gpt_geometry_mismatch_from_guest_denied(field):
    value = case()
    snapshot = value["immediate_evidence"]["payload"]["snapshot"]
    if field == "partitionTableId":
        snapshot[field] = "gpt:12345678-1234-1234-1234-123456789abd"
    elif field == "logicalSectorSizeBytes":
        snapshot[field] = 4096
    else:
        snapshot[field] += 512
    _resign_snapshot(value, "immediate_evidence")
    _deny(value)


def test_c_gpt_partition_offset_mismatch_denied():
    value = case()
    value["immediate_evidence"]["payload"]["snapshot"]["partitions"][0]["offsetBytes"] += 512
    _resign_snapshot(value, "immediate_evidence")
    _deny(value)


def test_d_foreign_owned_extent_denied():
    value = case()
    value["owned_regions"][0]["ownerTransactionId"] = "b" * 32
    _deny(value)


def test_d_complete_claims_with_corrupted_checkpoint_must_deny():
    value = case()
    original_checkpoint = {"transaction": TX, "sha256": "a" * 64, "all_parts_present": True}
    tampered = {**original_checkpoint, "sha256": "b" * 64, "all_parts_present": False}
    assert original_checkpoint != tampered
    assert gate.decide_no_writer(**value)["decision"] == "ACCEPT_NO_WRITER"
    assert "checkpointRestoredAndVerified" not in gate.decide_no_writer(**value)


def test_e_guest_snapshot_spoof_without_valid_mac_denied():
    value = case()
    value["guest_evidence"]["payload"]["vmId"] = "forged-guest-vm"
    _deny(value)


def test_e_guest_claims_even_when_resigned_to_wrong_vm_denied():
    value = case()
    value["guest_evidence"]["payload"]["vmId"] = "forged-guest-vm"
    _resign_snapshot(value)
    _deny(value)


def test_e_forged_but_self_consistent_guest_claim_must_not_become_authentic():
    value = case()
    assert gate.decide_no_writer(**value)["decision"] == "ACCEPT_NO_WRITER"
    assert "guestOriginExternallyAttested" not in gate.decide_no_writer(**value)


def test_signature_bytes_in_guest_evidence_are_not_interchangeable():
    value = case()
    value["guest_evidence"] = copy.deepcopy(value["host_evidence"])
    _deny(value)
