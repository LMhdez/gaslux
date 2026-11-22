"""Real paused QEMU/FD/QCOW2 destination tests, no guest or writer.

Requires pinned Safety #267 and GPT #286 immutable sources plus qemu-img/sgdisk.
All filesystem mutations occur in an authorized private CI temp directory.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from assets.live.libertix_disk_identity_gate import inspect_gpt_image
from auto_tests.installer_observer.authenticated_destination import (
    DestinationRefused,
    assess_authenticated_destination,
)
from auto_tests.tests import test_observer_qemu_real_disk_readonly as helpers


@pytest.fixture(scope="module")
def canonical_pins():
    return helpers.pinned.__wrapped__()


@pytest.fixture
def workspace(tmp_path):
    directory = tmp_path.resolve(strict=True)
    directory.chmod(0o700)
    return directory


def prepare(workspace, canonical_pins):
    _, lab = canonical_pins
    root267 = Path(os.environ["GASLUX_QEMU_PIN267_ROOT"]).resolve(strict=True)
    sys.path.insert(0, str(root267 / "assets/live"))
    from libertix_prewrite_no_writer import authenticated_record, canonical

    fixture = helpers.load(
        "destination_no_writer_fixture",
        root267 / "auto_tests/tests/test_prewrite_no_writer.py",
    )
    raw = helpers.make_raw(workspace, lab)
    overlay = helpers.make_qcow(workspace, lab, raw)
    gpt = inspect_gpt_image(raw, logical_sector_size=512)

    prewrite = fixture.case()
    plan = prewrite["plan"]
    plan["disk"] = {
        field: gpt[field]
        for field in (
            "partitionStyle",
            "partitionTableId",
            "sizeBytes",
            "logicalSectorSizeBytes",
        )
    }
    prewrite["plan_bytes"] = canonical(plan)
    plan_hash = hashlib.sha256(prewrite["plan_bytes"]).hexdigest()
    for key, secret in (
        ("host_evidence", fixture.HOST_KEY),
        ("guest_evidence", fixture.GUEST_KEY),
        ("immediate_evidence", fixture.GUEST_KEY),
    ):
        payload = prewrite[key]["payload"]
        payload["planSha256"] = plan_hash
        payload["snapshot"] = copy.deepcopy(gpt)
        prewrite[key] = authenticated_record(payload, secret)

    child = helpers.start_qemu(workspace, overlay, "qcow2")
    pins = helpers.pins_for(child, workspace, overlay, "qcow2")
    pins = __import__("dataclasses").replace(pins, transaction_id=fixture.TX)
    receipt_path = workspace / "checkpoint.json"
    overlay_hash = lab.sha256(overlay)
    backing_hash = lab.sha256(raw)
    receipt_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "transactionId": fixture.TX,
                "qcow2Sha256": overlay_hash,
                "backingSha256": backing_hash,
                "gptPartitionTableId": gpt["partitionTableId"],
                "restoreProven": False,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    return {
        "child": child,
        "paths": (overlay, raw, receipt_path),
        "pins": pins,
        "prewrite": prewrite,
        "gpt": gpt,
        "hashes": (overlay_hash, backing_hash, lab.sha256(receipt_path)),
    }


@pytest.fixture
def destination(workspace, canonical_pins):
    sample = prepare(workspace, canonical_pins)
    o, b, c = sample["paths"]
    fds = [os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW) for p in (o, b, c)]
    sample["fds"] = fds
    try:
        yield sample
    finally:
        for fd in fds:
            os.close(fd)
        helpers.shutdown(sample["child"])


def assess(sample, **updates):
    overlay, raw, checkpoint = sample["paths"]
    overlay_fd, backing_fd, checkpoint_fd = sample["fds"]
    overlay_hash, backing_hash, checkpoint_hash = sample["hashes"]
    kwargs = {
        "pins": sample["pins"],
        "qcow2_fd": overlay_fd,
        "backing_fd": backing_fd,
        "backing_path": raw,
        "checkpoint_fd": checkpoint_fd,
        "checkpoint_path": checkpoint,
        "expected_overlay_sha256": overlay_hash,
        "expected_backing_sha256": backing_hash,
        "expected_checkpoint_sha256": checkpoint_hash,
        "expected_gpt": sample["gpt"],
        "prewrite_inputs": sample["prewrite"],
    }
    kwargs.update(updates)
    return assess_authenticated_destination(**kwargs)


def test_i_valid_readonly_inspection_is_not_authority(destination):
    result = assess(destination, source_claim={"kind": "iso", "digest": "a" * 64})
    assert result["status"] == "READONLY_STRUCTURE_OBSERVED"
    assert result["authorization"] == "DENY_NO_WRITER"
    assert result["properties"]["qcow2FdIdentity"] == "PROVEN"
    assert result["properties"]["backingGptPrimaryBackup"] == "PROVEN"
    assert result["properties"]["qemuBackendToFdInternalBinding"] == "UNPROVEN"
    assert result["properties"]["checkpointIndependentAuthenticity"] == "UNPROVEN"
    assert result["properties"]["guestOrigin"] == "DENIED"
    for key in (
        "productionStorageWritesAuthorized",
        "guestCommandChannelAuthorized",
        "rollbackProven",
        "sameDiskDualBootVerified",
        "stable",
    ):
        assert result[key] is False


def test_a_destination_swap_with_unchanged_claimed_metadata_is_refused(destination, workspace):
    original = destination["paths"][0]
    parked = workspace / "original.qcow2"
    os.replace(original, parked)
    shutil.copyfile(parked, original)
    assert original.stat().st_size == parked.stat().st_size
    with pytest.raises(DestinationRefused):
        assess(destination)


def test_b_foreign_fd_alias_same_size_is_refused(destination, workspace):
    path = destination["paths"][0]
    foreign = workspace / "foreign.qcow2"
    shutil.copyfile(path, foreign)
    with foreign.open("rb") as stream:
        with pytest.raises(DestinationRefused, match="FD_ALIAS|SWAP"):
            assess(destination, qcow2_fd=stream.fileno())


def test_c_qcow2_backing_path_swap_is_refused(destination, workspace):
    backing = destination["paths"][1]
    parked = workspace / "previous-base.raw"
    os.replace(backing, parked)
    shutil.copyfile(parked, backing)
    with pytest.raises(DestinationRefused):
        assess(destination)


def test_d_gpt_geometry_mismatch_is_refused(destination):
    wrong = copy.deepcopy(destination["gpt"])
    wrong["sizeBytes"] += 512
    with pytest.raises(DestinationRefused):
        assess(destination, expected_gpt=wrong)


def test_e_transaction_mismatch_is_refused(destination):
    prewrite = copy.deepcopy(destination["prewrite"])
    prewrite["transaction_id"] = "b" * 32
    with pytest.raises(DestinationRefused, match="TRANSACTION"):
        assess(destination, prewrite_inputs=prewrite)


def test_f_unowned_writeset_is_refused(destination):
    prewrite = copy.deepcopy(destination["prewrite"])
    prewrite["owned_regions"][0]["ownerTransactionId"] = "b" * 32
    with pytest.raises(DestinationRefused):
        assess(destination, prewrite_inputs=prewrite)


def test_g_checkpoint_content_tamper_without_changing_claims_is_refused(destination):
    path = destination["paths"][2]
    with path.open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(DestinationRefused):
        assess(destination)


def test_h_self_consistent_spoofed_guest_without_independent_root_is_refused(destination):
    claim = {
        "transactionId": destination["pins"].transaction_id,
        "gptPartitionTableId": destination["gpt"]["partitionTableId"],
        "guestAuthenticated": True,
        "collectorAuthenticated": True,
    }
    with pytest.raises(DestinationRefused, match="GUEST_ORIGIN"):
        assess(destination, guest_claim=claim)


def test_backing_fd_alias_is_refused(destination, workspace):
    raw = destination["paths"][1]
    foreign = workspace / "other.raw"
    shutil.copyfile(raw, foreign)
    with foreign.open("rb") as stream:
        with pytest.raises(DestinationRefused, match="FD_ALIAS"):
            assess(destination, backing_fd=stream.fileno())


def test_checkpoint_fd_alias_is_refused(destination, workspace):
    cp = destination["paths"][2]
    foreign = workspace / "foreign-checkpoint.json"
    shutil.copyfile(cp, foreign)
    with foreign.open("rb") as stream:
        with pytest.raises(DestinationRefused, match="FD_ALIAS"):
            assess(destination, checkpoint_fd=stream.fileno())
