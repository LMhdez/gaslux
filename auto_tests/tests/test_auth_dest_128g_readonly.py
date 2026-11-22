"""Real paused QEMU and sparse 128-GiB RAW/overlay adversarial tests.

All writes create private disposable test files only; no guest OS boots.
No 128-GiB whole-file digest is attempted or claimed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from assets.live.libertix_disk_identity_gate import inspect_gpt_image
from auto_tests.installer_observer import authenticated_destination as small
from auto_tests.installer_observer import large_sparse_destination as large
from auto_tests.tests import test_observer_qemu_real_disk_readonly as helpers

CAPACITY = 128 * 1024**3


@pytest.fixture(scope="module")
def pins():
    return helpers.pinned.__wrapped__()


@pytest.fixture
def workspace(tmp_path):
    result = tmp_path.resolve(strict=True)
    result.chmod(0o700)
    return result


def _make_sparse(workspace):
    backing = workspace / "base-128g.raw"
    fd = os.open(backing, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, CAPACITY)
        os.fsync(fd)
    finally:
        os.close(fd)
    disk_guid, part_guid = str(uuid.uuid4()), str(uuid.uuid4())
    subprocess.run(
        [
            "sgdisk",
            "--clear",
            "--new=1:2048:4095",
            "--typecode=1:0700",
            f"--disk-guid={disk_guid}",
            f"--partition-guid=1:{part_guid}",
            str(backing),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    assert backing.stat().st_size == CAPACITY
    assert backing.stat().st_blocks * 512 < 32 * 1024**2
    return backing


def _make_overlay(workspace, backing):
    overlay = workspace / "overlay.qcow2"
    subprocess.run(
        [
            "/usr/bin/qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "raw",
            "-b",
            str(backing),
            str(overlay),
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )
    with overlay.open("ab") as target:
        target.write(b"\0" * (-overlay.stat().st_size % 512))
    assert overlay.stat().st_size < 64 * 1024**2
    return overlay


def _prewrite_for(gpt):
    root267 = Path(os.environ["GASLUX_QEMU_PIN267_ROOT"]).resolve(strict=True)
    sys.path.insert(0, str(root267 / "assets/live"))
    from libertix_prewrite_no_writer import authenticated_record, canonical

    fixtures = helpers.load(
        "sparse128_gpt_prewrite_fixture",
        root267 / "auto_tests/tests/test_prewrite_no_writer.py",
    )
    value = fixtures.case()
    value["plan"]["disk"] = {
        key: gpt[key]
        for key in (
            "partitionStyle",
            "partitionTableId",
            "sizeBytes",
            "logicalSectorSizeBytes",
        )
    }
    value["plan_bytes"] = canonical(value["plan"])
    digest = hashlib.sha256(value["plan_bytes"]).hexdigest()
    for key, secret in (
        ("host_evidence", fixtures.HOST_KEY),
        ("guest_evidence", fixtures.GUEST_KEY),
        ("immediate_evidence", fixtures.GUEST_KEY),
    ):
        payload = value[key]["payload"]
        payload["planSha256"] = digest
        payload["snapshot"] = copy.deepcopy(gpt)
        value[key] = authenticated_record(payload, secret)
    return value


@pytest.fixture
def sample(workspace, pins):
    backing = _make_sparse(workspace)
    qcow2 = _make_overlay(workspace, backing)
    gpt = inspect_gpt_image(backing, logical_sector_size=512)
    prewrite = _prewrite_for(gpt)
    child = helpers.start_qemu(workspace, qcow2, "qcow2")
    qpins = replace(
        helpers.pins_for(child, workspace, qcow2, "qcow2"),
        transaction_id=prewrite["transaction_id"],
    )
    overlay_sha = hashlib.sha256(qcow2.read_bytes()).hexdigest()
    receipt = workspace / "checkpoint.json"
    receipt.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "transactionId": qpins.transaction_id,
                "virtualBytes": CAPACITY,
                "gptPartitionTableId": gpt["partitionTableId"],
                "qcow2Sha256": overlay_sha,
                "restoreProven": False,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    receipt.chmod(0o600)
    file_paths = (qcow2, backing, receipt)
    opened = [os.open(path, os.O_RDONLY | os.O_NOFOLLOW) for path in file_paths]
    item = {
        "workspace": workspace,
        "paths": file_paths,
        "fds": opened,
        "gpt": gpt,
        "prewrite": prewrite,
        "pins": qpins,
        "overlay_sha": overlay_sha,
        "receipt_sha": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "budget": large.LargeReadOnlyBudget(known_quota_bytes=64 * 1024**2),
    }
    try:
        yield item
    finally:
        for fd in opened:
            os.close(fd)
        helpers.shutdown(child)


def assess(item, **changes):
    qcow2, raw, cp = item["paths"]
    qfd, rfd, cfd = item["fds"]
    kwargs = {
        "pins": item["pins"],
        "qcow2_fd": qfd,
        "backing_fd": rfd,
        "backing_path": raw,
        "checkpoint_fd": cfd,
        "checkpoint_path": cp,
        "expected_overlay_sha256": item["overlay_sha"],
        "expected_checkpoint_sha256": item["receipt_sha"],
        "expected_gpt": item["gpt"],
        "prewrite_inputs": item["prewrite"],
        "budget": item["budget"],
    }
    kwargs.update(changes)
    return large.assess_sparse_128g_readonly(**kwargs)


def refused(item, expected, **changes):
    with pytest.raises(large.LargeDestinationRefused, match=expected) as caught:
        assess(item, **changes)
    return caught.value


def test_128g_sparse_qcow2_backing_gpt_is_structurally_observed_but_hash_denied(sample):
    denied = refused(sample, "FULL_BACKING_HASH_NOT_COMPLETED")
    evidence = denied.observed
    assert evidence["status"] == "STRUCTURE_OBSERVED_FULL_HASH_DENIED"
    assert evidence["authorization"] == "DENY_NO_WRITER"
    assert evidence["virtualCapacityBytes"] == CAPACITY
    assert evidence["rawApparentBytes"] == CAPACITY
    assert evidence["rawAllocatedBytes"] < 32 * 1024**2
    assert evidence["qcow2ApparentBytes"] < 64 * 1024**2
    assert evidence["locallyMeasuredRawSampleBytes"] == 65536
    assert evidence["rawBackingFullSha256Verified"] is False
    assert evidence["fullRawContentBytesAuthenticated"] == 0
    assert evidence["qemuBackendFdIndependentlyProven"] is False
    assert evidence["guestProvenanceAuthenticated"] is False
    for key in (
        "productionStorageWritesAuthorized",
        "guestCommandChannelAuthorized",
        "rollbackProven",
        "sameDiskDualBootVerified",
        "stable",
    ):
        assert evidence[key] is False


def test_resource_limit_refuses_allocated_blocks_even_if_virtual_is_sparse(sample):
    budget = replace(sample["budget"], max_total_allocated_bytes=1024)
    refused(sample, "ALLOCATION_BUDGET_EXCEEDED", budget=budget)


def test_unknown_quota_refused_before_any_observation(sample):
    budget = replace(sample["budget"], known_quota_bytes=None)
    refused(sample, "QUOTA_UNKNOWN", budget=budget)


def test_tight_qemu_json_output_cap_refused(sample):
    budget = replace(sample["budget"], max_qemu_info_bytes=256)
    refused(sample, "QEMU_INFO_OUTPUT_LIMIT", budget=budget)


def test_timeout_budget_refused_without_treating_partial_inspection_as_valid(sample, monkeypatch):
    times = iter([0.0, 50.0])
    monkeypatch.setattr(large.time, "monotonic", lambda: next(times, 50.0))
    refused(sample, "READONLY_INSPECTION_TIMEOUT")


def test_real_short_read_on_sparse_raw_fd_refused(sample, monkeypatch):
    original = large.os.pread
    backing_fd = sample["fds"][1]

    def short(fd, count, offset):
        if fd == backing_fd and count == 32768:
            return original(fd, count // 2, offset)
        return original(fd, count, offset)

    monkeypatch.setattr(large.os, "pread", short)
    refused(sample, "SPARSE_SHORT_READ")


def test_integral_qcow2_hash_pin_mismatch_refused(sample):
    refused(sample, "FULL_QCOW2_HASH_MISMATCH", expected_overlay_sha256="a" * 64)


def test_foreign_raw_fd_same_size_refused(sample, workspace):
    wrong = workspace / "foreign.raw"
    shutil.copyfile(sample["paths"][1], wrong)
    with wrong.open("rb") as fd:
        refused(sample, "SPARSE_FOREIGN_FD_OR_GEOMETRY", backing_fd=fd.fileno())


def test_backing_path_replaced_after_fd_pinned_is_refused(sample, workspace):
    raw = sample["paths"][1]
    old = workspace / "old.raw"
    os.replace(raw, old)
    shutil.copyfile(old, raw)
    refused(sample, "SPARSE_FOREIGN_FD_OR_GEOMETRY")


def test_mismatched_gpt_geometry_refused(sample):
    mismatch = copy.deepcopy(sample["gpt"])
    mismatch["sizeBytes"] += 512
    refused(sample, "LARGE_DESTINATION_INSPECTION_REFUSED", expected_gpt=mismatch)


def test_checkpoint_for_foreign_transaction_rejected_even_if_hash_matches(sample):
    cp = sample["paths"][2]
    data = json.loads(cp.read_text(encoding="utf-8"))
    data["transactionId"] = "b" * 32
    cp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    new_hash = hashlib.sha256(cp.read_bytes()).hexdigest()
    refused(sample, "CHECKPOINT_TRANSACTION_MISMATCH", expected_checkpoint_sha256=new_hash)


def test_guest_claim_even_self_consistent_refused(sample):
    denied = {
        "transactionId": sample["pins"].transaction_id,
        "gptPartitionTableId": sample["gpt"]["partitionTableId"],
        "guestChannelAuthenticated": True,
    }
    refused(sample, "GUEST_ORIGIN_UNPROVEN", guest_claim=denied)


def test_in_place_backing_mutation_detected_by_fd_identity(sample, monkeypatch):
    original = large.inspect_gpt_fd
    raw = sample["paths"][1]

    def mutate(fd, *, logical_sector_size):
        snapshot = original(fd, logical_sector_size=logical_sector_size)
        with raw.open("r+b") as writable:
            writable.seek(4 * 1024**2)
            writable.write(b"unsafe-concurrent-mutation")
        return snapshot

    monkeypatch.setattr(large, "inspect_gpt_fd", mutate)
    refused(sample, "RESOURCE_MUTATED_DURING_INSPECTION")


def test_legacy_digest_full_read_positive_and_partial_nonempty_refused(tmp_path, monkeypatch):
    path = tmp_path / "small.bin"
    data = b"x" * 1024
    path.write_bytes(data)
    with path.open("rb") as stream:
        assert small._digest(stream.fileno(), hashlib.sha256(data).hexdigest())
        original = small.os.pread

        def partial(fd, count, offset):
            if fd == stream.fileno() and count == len(data) and offset == 0:
                return original(fd, 512, 0)
            return original(fd, count, offset)

        monkeypatch.setattr(small.os, "pread", partial)
        with pytest.raises(small.DestinationRefused, match="FD_SHORT_READ"):
            small._digest(stream.fileno(), hashlib.sha256(data[:512]).hexdigest())


def test_legacy_digest_eio_refused(tmp_path, monkeypatch):
    path = tmp_path / "small.bin"
    path.write_bytes(b"x" * 1024)
    with path.open("rb") as stream:
        original = small.os.pread

        def faulty(fd, count, offset):
            if fd == stream.fileno():
                raise OSError(5, "simulated EIO")
            return original(fd, count, offset)

        monkeypatch.setattr(small.os, "pread", faulty)
        with pytest.raises(small.DestinationRefused, match="FD_HASH_IO_FAILED"):
            small._digest(stream.fileno(), hashlib.sha256(b"x" * 1024).hexdigest())
