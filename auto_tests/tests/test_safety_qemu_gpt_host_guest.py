"""QEMU host/guest lab: synthetic positive/negative contract tests (not VM boot)."""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))
sys.path.insert(0, str(ROOT / "assets" / "live"))
from tests.test_disk_identity_gate import make_image
import safety_qemu_gpt_host_guest as lab
from libertix_disk_identity_gate import DiskIdentityError


@pytest.fixture
def records(tmp_path):
    raw = tmp_path / "disk.img"
    make_image(raw)
    snap = lab.inspect_gpt_image(raw, logical_sector_size=512)
    return snap, {"virtualSizeBytes": snap["sizeBytes"], "backingSha256": "a" * 64}, {
        "guestDiskLabel": "gaslux123456789abc", "qemuPid": 12345,
    }


def test_replay_registry_blocks_same_transaction_vm_nonce():
    state = lab.NonceRegistry()
    state.consume("a" * 32, "gaslux-qemu-abc", "f" * 48)
    with pytest.raises(lab.PrewriteDenied, match="replayed"):
        state.consume("a" * 32, "gaslux-qemu-abc", "f" * 48)


@pytest.mark.parametrize("value", ["", "a" * 16, "zz" * 48])
def test_nonce_registry_requires_full_challenge(value):
    with pytest.raises(lab.PrewriteDenied, match="nonce"):
        lab.NonceRegistry().consume("a" * 32, "gaslux-qemu-abc", value)


def test_matching_snapshots_return_only_lab_no_writer(records):
    snap, chain, identity = records
    result = lab.evaluate((snap, snap, snap), chain, identity, lab.NonceRegistry())
    assert result["result"]["decision"] == "ACCEPT_NO_WRITER"
    assert result["planSignatureVerified"] is False
    assert result["keysPublished"] is False
    assert result["trustBoundary"] == "NOT_INDEPENDENT"
    assert result["writerCalled"] is False


@pytest.mark.parametrize("tamper", ["mac", "vm", "immediate", "host_guest"])
def test_adversarial_records_denied(records, tamper):
    snap, chain, identity = records
    with pytest.raises(DiskIdentityError):
        lab.evaluate((snap, snap, snap), chain, identity, lab.NonceRegistry(), tamper=tamper)


@pytest.mark.parametrize("change", ["guid", "partuuid", "offset", "length"])
def test_different_guest_partitions_denied(records, change):
    snap, chain, identity = records
    other = deepcopy(snap)
    if change == "guid":
        other["partitionTableId"] = "gpt:00000000-0000-0000-0000-000000000001"
    elif change == "partuuid":
        other["partitions"][0]["partGuid"] = "00000000-0000-0000-0000-000000000002"
    elif change == "offset":
        other["partitions"][0]["offsetBytes"] += 512
    else:
        other["partitions"][0]["sizeBytes"] += 512
    with pytest.raises(DiskIdentityError):
        lab.evaluate((snap, other, snap), chain, identity, lab.NonceRegistry())


def test_guest_gpt_samples_reuse_existing_parser(tmp_path):
    raw = tmp_path / "disk.img"
    make_image(raw)
    target = tmp_path / "guest-read.img"
    data = raw.read_bytes()
    snapshot = lab.reconstruct_guest_sample(
        data[:lab.GUEST_SLICE], data[-lab.GUEST_SLICE:],
        len(data), target, tmp_path,
    )
    lab.assert_snapshot_matches(lab.inspect_gpt_image(raw, logical_sector_size=512), snapshot)


def test_guest_gpt_incoherent_samples_fail_crc(tmp_path):
    raw = tmp_path / "disk.img"
    make_image(raw)
    data = bytearray(raw.read_bytes())
    data[512 + 56] ^= 1
    with pytest.raises(DiskIdentityError):
        lab.reconstruct_guest_sample(
            bytes(data[:lab.GUEST_SLICE]), bytes(data[-lab.GUEST_SLICE:]),
            len(data), tmp_path / "guest.img", tmp_path,
        )


@pytest.mark.parametrize("case", ["symlink", "hardlink", "replacement"])
def test_file_ownership_fail_closed(tmp_path, case):
    disk = tmp_path / "own.img"
    disk.write_bytes(b"file")
    old = lab.own_regular(disk, tmp_path)
    if case == "symlink":
        disk.unlink()
        disk.symlink_to(tmp_path / "missing.img")
    elif case == "hardlink":
        (tmp_path / "another.img").hardlink_to(disk)
    else:
        disk.unlink()
        disk.write_bytes(b"replacement")
    with pytest.raises((lab.PrewriteDenied, FileNotFoundError)):
        lab.same_file(disk, tmp_path, old)


def test_qcow_backing_path_change_is_denied(tmp_path, monkeypatch):
    base = tmp_path / "base.raw"
    child = tmp_path / "child.qcow2"
    base.write_bytes(b"base")
    child.write_bytes(b"child")
    chain = [
        {"format": "qcow2", "virtual-size": lab.SIZE, "backing-filename-format": "raw",
         "full-backing-filename": str(tmp_path / "other.raw")},
        {"format": "raw", "virtual-size": lab.SIZE},
    ]
    monkeypatch.setattr(lab, "run", lambda *args: json.dumps(chain))
    with pytest.raises(lab.PrewriteDenied, match="backing path"):
        lab.verify_chain(child, base, tmp_path)


def test_qcow_backing_format_change_is_denied(tmp_path, monkeypatch):
    base = tmp_path / "base.raw"
    child = tmp_path / "child.qcow2"
    base.write_bytes(b"base")
    child.write_bytes(b"child")
    chain = [
        {"format": "qcow2", "virtual-size": lab.SIZE, "backing-filename-format": "qcow2",
         "full-backing-filename": str(base)},
        {"format": "raw", "virtual-size": lab.SIZE},
    ]
    monkeypatch.setattr(lab, "run", lambda *args: json.dumps(chain))
    with pytest.raises(lab.PrewriteDenied, match="backing format"):
        lab.verify_chain(child, base, tmp_path)


def test_unproved_qemu_identity_fails(tmp_path):
    with pytest.raises(lab.PrewriteDenied, match="PID"):
        lab.qemu_identity(0, tmp_path / "disk.qcow2")


def test_no_writer_callable_exists():
    assert not hasattr(lab, "write_disk")
    assert not hasattr(lab, "authorize_write")
