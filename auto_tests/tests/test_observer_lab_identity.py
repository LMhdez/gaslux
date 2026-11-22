"""Adversarial contracts for the non-input QEMU identity witness.

These tests use synthetic QMP structures, never claim a QEMU boot or guest input.
"""

from __future__ import annotations

import io
import os
from dataclasses import replace

import pytest

from auto_tests.installer_observer.evidence import Refusal, digest
from auto_tests.installer_observer.lab_identity import (
    LocalQemuAttestor,
    ProcessSeal,
    QemuRunSeal,
    _execute,
    _read_response,
    process_seal,
    seal_file,
    verify_qmp_report,
)
from auto_tests.installer_observer.models import DistributionIdentity
from auto_tests.installer_observer.state_machine import LabAuthority


@pytest.fixture
def contract(tmp_path):
    iso = tmp_path / "synthetic.iso"
    iso.write_bytes(b"synthetic-fixture-not-Q4OS")
    cow = tmp_path / "overlay.qcow2"
    cow.write_bytes(bytes.fromhex("514649fb") + b"\x00" * 64)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    identity = DistributionIdentity("fixture", "0", digest(iso.read_bytes()), iso.stat().st_size)
    authority = LabAuthority("run-123", identity, "test-commit", "snap-123", True, False)
    seal = QemuRunSeal(
        authority,
        ProcessSeal(987654, os.geteuid(), 12345, "abc", 1, 2),
        private / "qmp.sock",
        5905,
        seal_file(iso),
        seal_file(cow),
    )
    blocks = [
        {
            "device": "lab-iso",
            "inserted": {
                "file": str(seal.iso.path),
                "ro": True,
                "image": {"filename": str(seal.iso.path), "format": "raw"},
            },
        },
        {
            "device": "lab-cow",
            "inserted": {
                "file": str(seal.cow.path),
                "ro": False,
                "image": {
                    "filename": str(seal.cow.path),
                    "format": "qcow2",
                    "snapshots": [{"id": "1", "name": "snap-123"}],
                },
            },
        },
    ]
    vnc = {"enabled": True, "host": "127.0.0.1", "service": "5905", "clients": []}
    status = {"status": "running"}
    return seal, blocks, vnc, status


def test_pure_qmp_contract_can_validate_exactly_two_synthetic_media(contract):
    verify_qmp_report(*contract)


@pytest.mark.parametrize(
    "mutation",
    (
        "third-disk",
        "removed-iso",
        "iso-writable",
        "cow-readonly",
        "cow-raw",
        "backing",
        "snapshot",
        "duplicate-snapshot",
        "missing-snapshots",
        "vnc-client",
        "vnc-host",
        "vnc-port",
        "stopped",
        "iso-replaced",
        "cow-replaced",
    ),
)
def test_qmp_drift_refuses_before_any_input(contract, mutation):
    seal, original, original_vnc, original_status = contract
    blocks = [
        {
            "device": b["device"],
            "inserted": {**b["inserted"], "image": dict(b["inserted"]["image"])},
        }
        for b in original
    ]
    vnc = dict(original_vnc)
    status = dict(original_status)
    if mutation == "third-disk":
        blocks.append({"device": "windows", "inserted": {"file": "/dev/sda"}})
    elif mutation == "removed-iso":
        blocks.pop(0)
    elif mutation == "iso-writable":
        blocks[0]["inserted"]["ro"] = False
    elif mutation == "cow-readonly":
        blocks[1]["inserted"]["ro"] = True
    elif mutation == "cow-raw":
        blocks[1]["inserted"]["image"]["format"] = "raw"
    elif mutation == "backing":
        blocks[1]["inserted"]["image"]["backing-image"] = {"filename": "/other"}
    elif mutation == "snapshot":
        blocks[1]["inserted"]["image"]["snapshots"] = [{"name": "swapped"}]
    elif mutation == "duplicate-snapshot":
        blocks[1]["inserted"]["image"]["snapshots"] = [{"name": "snap-123"}, {"name": "snap-123"}]
    elif mutation == "missing-snapshots":
        blocks[1]["inserted"]["image"].pop("snapshots")
    elif mutation == "vnc-client":
        vnc["clients"] = [{"host": "another-controller"}]
    elif mutation == "vnc-host":
        vnc["host"] = "0.0.0.0"
    elif mutation == "vnc-port":
        vnc["service"] = "5906"
    elif mutation == "stopped":
        status["status"] = "shutdown"
    elif mutation == "iso-replaced":
        blocks[0]["inserted"]["file"] = "/tmp/different.iso"
    elif mutation == "cow-replaced":
        blocks[1]["inserted"]["image"]["filename"] = "/tmp/different.qcow2"
    with pytest.raises(Refusal):
        verify_qmp_report(seal, blocks, vnc, status)


def test_same_pid_name_not_sufficient_and_missing_process_refused():
    with pytest.raises(Refusal):
        process_seal(os.getpid())  # Python, never mistaken for QEMU
    with pytest.raises(Refusal):
        process_seal(-1)


def test_iso_rewrite_after_sealing_prevents_attestor_creation(contract):
    seal, *_ = contract
    seal.iso.path.write_bytes(b"same-size-different-data")
    with pytest.raises(Refusal):
        LocalQemuAttestor(seal)


def test_iso_metadata_and_seal_are_both_required(contract):
    seal, *_ = contract
    LocalQemuAttestor(seal)  # Hash, length and one-link regular-file proof, not live VM proof.
    with pytest.raises(Refusal):
        LocalQemuAttestor(
            replace(
                seal,
                authority=replace(
                    seal.authority, media=replace(seal.authority.media, sha256="0" * 64)
                ),
            )
        )


def test_replaced_cow_and_changed_snapshot_refused(contract):
    seal, blocks, vnc, status = contract
    with pytest.raises(Refusal):
        verify_qmp_report(
            replace(seal, authority=replace(seal.authority, snapshot_id="other")),
            blocks,
            vnc,
            status,
        )
    seal.cow.path.unlink()
    seal.cow.path.write_bytes(b"another file")
    with pytest.raises(Refusal):
        LocalQemuAttestor(seal).verify(float("inf"))


def test_symlink_and_hardlink_escapes_refused(contract, tmp_path):
    seal, *_ = contract
    alias = tmp_path / "alias.iso"
    alias.symlink_to(seal.iso.path)
    with pytest.raises(Refusal):
        seal_file(alias)
    hardlink = tmp_path / "hard.iso"
    os.link(seal.iso.path, hardlink)
    with pytest.raises(Refusal):
        seal_file(seal.iso.path)


def test_unexpected_authority_fields_refused(contract):
    seal, *_ = contract
    for changed in (
        replace(seal.authority, synthetic_cow_only=False),
        replace(seal.authority, physical_disk_attached=True),
        replace(seal.authority, run_id=""),
    ):
        with pytest.raises(Refusal):
            replace(seal, authority=changed)


def test_qmp_replies_are_bounded_and_no_arbitrary_command_is_emitted():
    for raw in (b"", b"not-json\n", b"[]\n", b'{"event":"x"}\n' * 20):
        with pytest.raises(Refusal):
            _read_response(io.BytesIO(raw))

    class NoSend:
        def sendall(self, _data):
            pytest.fail("Unreviewed QMP command sent")

    with pytest.raises(Refusal):
        _execute(NoSend(), io.BytesIO(b""), "human-monitor-command")


def test_expired_deadline_has_no_qmp_attempt(contract):
    seal, *_ = contract
    with pytest.raises(Refusal, match="deadline"):
        LocalQemuAttestor(seal).verify(-1.0)
