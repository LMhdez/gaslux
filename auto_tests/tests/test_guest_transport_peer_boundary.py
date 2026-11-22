"""Adversarial real Linux process/Unix FD tests. No QEMU or guest input."""

from __future__ import annotations

import copy
import hashlib
import os
import socket
import subprocess
import sys
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from auto_tests.installer_observer.guest_transport_peer_boundary import (
    LocalSessionPins,
    LocalTransportWitness,
    TransportBoundaryRefused,
)
from auto_tests.installer_observer.host_fd_boundary import ProcessSeal

CHILD = """
import socket
import sys
import time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
print("CONNECTED", flush=True)
for command in sys.stdin:
    if command.strip() == "close":
        s.close()
        print("CLOSED", flush=True)
        time.sleep(60)
        break
"""


def pinned_process(pid: int) -> ProcessSeal:
    root = Path("/proc") / str(pid)
    raw = (root / "stat").read_text(encoding="ascii")
    fields = raw[raw.rfind(") ") + 2 :].split()
    exe = (root / "exe").stat()
    return ProcessSeal(
        pid,
        root.stat().st_uid,
        int(fields[19]),
        hashlib.sha256((root / "cmdline").read_bytes()).hexdigest(),
        exe.st_dev,
        exe.st_ino,
    )


@pytest.fixture
def peer(tmp_path):
    directory = tmp_path / "owned"
    directory.mkdir(mode=0o700)
    path = directory / "synthetic.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    listener.settimeout(5)
    conn, _ = listener.accept()
    assert child.stdout is not None
    assert child.stdout.readline().strip() == "CONNECTED"
    st = os.fstat(conn.fileno())
    pins = LocalSessionPins(
        process=pinned_process(child.pid),
        transport_dev=st.st_dev,
        transport_inode=st.st_ino,
        session_id=str(uuid.uuid4()),
        transaction_id=str(uuid.uuid4()),
        host_vm_id="synthetic-not-a-guest",
        disk_identity_sha256="a" * 64,
        collector_sha256="b" * 64,
        challenge="c" * 64,
    )
    try:
        yield child, conn, pins
    finally:
        conn.close()
        listener.close()
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=3)


def claimed(pins: LocalSessionPins) -> dict[str, str]:
    return {
        "sessionId": pins.session_id,
        "transactionId": pins.transaction_id,
        "hostVmId": pins.host_vm_id,
        "diskIdentitySha256": pins.disk_identity_sha256,
        "collectorSha256": pins.collector_sha256,
        "challenge": pins.challenge,
        "provenance": "CLAIMED",
    }


def test_actual_kernel_peer_descriptor_but_guest_always_denied(peer):
    child, conn, pins = peer
    report = LocalTransportWitness(conn, pins).finish(claimed(pins))
    assert report["status"] == "BLOCKED_TRUST_ROOT"
    assert report["classification"] == "NOT_INDEPENDENT"
    assert report["safetyAssessment"] == "DIAGNOSTIC_ONLY"
    assert report["localKernelPeerObserved"] is True
    assert report["peer"]["pid"] == child.pid
    assert report["transportDescriptor"]["inode"] == pins.transport_inode
    assert all(v["assurance"] == "CLAIMED" for v in report["sessionContext"].values())
    for field in (
        "guestChannelAuthenticated",
        "guestProcessAuthenticated",
        "anacondaProcessVerified",
        "collectorAuthenticated",
        "qemuVmIdentityAuthenticated",
        "diskBackendFdAssociationProven",
        "externallyAttested",
        "freshnessAuthenticated",
        "replayProtected",
        "persistentLedgerVerified",
        "operationalApprovalVerified",
        "inputAuthorized",
        "diskWritesAuthorized",
        "productionInstallationAuthorized",
        "productionWriteAuthorized",
        "installationAuthorized",
        "guestCommandChannelAuthorized",
        "windowsRecoveryVerified",
        "rollbackProven",
    ):
        assert report[field] is False, field


@pytest.mark.parametrize(
    "change",
    ["pid", "start", "cmdline", "uid", "exe", "transport_dev", "transport_ino"],
)
def test_mismatched_kernel_peer_or_fd_refused(peer, change):
    _, conn, pins = peer
    if change in ("pid", "start", "cmdline", "uid", "exe"):
        expected = pins.process
        mutations = {
            "pid": ("pid", 999999),
            "start": ("start_ticks", expected.start_ticks + 1),
            "cmdline": ("command_sha256", "0" * 64),
            "uid": ("uid", expected.uid + 1),
            "exe": ("executable_ino", expected.executable_ino + 1),
        }
        name, value = mutations[change]
        pins = replace(pins, process=replace(expected, **{name: value}))
    else:
        name = "transport_dev" if change == "transport_dev" else "transport_inode"
        pins = replace(pins, **{name: getattr(pins, name) + 1})
    with pytest.raises(TransportBoundaryRefused):
        LocalTransportWitness(conn, pins)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostVmId", "other-vm"),
        ("diskIdentitySha256", "d" * 64),
        ("collectorSha256", "e" * 64),
        ("transactionId", "00000000-0000-4000-8000-000000000000"),
        ("sessionId", "00000000-0000-4000-8000-000000000000"),
        ("challenge", "f" * 64),
        ("provenance", "LOCALLY_MEASURED"),
    ],
)
def test_claim_substitution_and_forged_guest_origin_refused(peer, field, value):
    _, conn, pins = peer
    witness = LocalTransportWitness(conn, pins)
    foreign = claimed(pins)
    foreign[field] = value
    with pytest.raises(TransportBoundaryRefused, match="UNTRUSTED_CONTEXT_MISMATCH"):
        witness.finish(foreign)
    with pytest.raises(TransportBoundaryRefused, match="SESSION_ALREADY_USED_LOCAL_ONLY"):
        witness.finish(claimed(pins))


def test_missing_origin_and_attempted_write_grant_refused(peer):
    _, conn, pins = peer
    missing = claimed(pins)
    del missing["provenance"]
    with pytest.raises(TransportBoundaryRefused, match="MISSING_OR_EXTRA"):
        LocalTransportWitness(conn, pins).finish(missing)
    elevated = claimed(pins)
    elevated["diskWritesAuthorized"] = True
    with pytest.raises(TransportBoundaryRefused, match="MISSING_OR_EXTRA"):
        LocalTransportWitness(conn, pins).finish(elevated)


def test_replayed_session_same_local_witness_is_denied(peer):
    _, conn, pins = peer
    witness = LocalTransportWitness(conn, pins)
    assert witness.finish(claimed(pins))["replayProtected"] is False
    with pytest.raises(TransportBoundaryRefused, match="SESSION_ALREADY_USED_LOCAL_ONLY"):
        witness.finish(copy.deepcopy(claimed(pins)))


def test_original_transport_fd_closed_after_start_refused(peer):
    _, conn, pins = peer
    witness = LocalTransportWitness(conn, pins)
    conn.close()
    with pytest.raises(TransportBoundaryRefused):
        witness.finish(claimed(pins))


def test_original_fd_replaced_with_other_socket_refused(peer):
    _, conn, pins = peer
    witness = LocalTransportWitness(conn, pins)
    other, remote = socket.socketpair()
    try:
        os.dup2(other.fileno(), conn.fileno())
        with pytest.raises(TransportBoundaryRefused):
            witness.finish(claimed(pins))
    finally:
        other.close()
        remote.close()


def test_peer_process_terminated_after_start_refused(peer):
    child, conn, pins = peer
    witness = LocalTransportWitness(conn, pins)
    child.terminate()
    child.wait(timeout=3)
    with pytest.raises(TransportBoundaryRefused):
        witness.finish(claimed(pins))


def test_peer_closed_connection_but_process_remains_refused(peer):
    child, conn, pins = peer
    witness = LocalTransportWitness(conn, pins)
    assert child.stdin is not None and child.stdout is not None
    child.stdin.write("close\n")
    child.stdin.flush()
    assert child.stdout.readline().strip() == "CLOSED"
    with pytest.raises(TransportBoundaryRefused):
        witness.finish(claimed(pins))


def test_malformed_session_pin_is_denied(peer):
    _, conn, pins = peer
    with pytest.raises(TransportBoundaryRefused, match="INVALID_EXTERNAL_SESSION_CLAIMS"):
        replace(pins, challenge="invalid")
    with pytest.raises(TransportBoundaryRefused):
        LocalTransportWitness(conn, replace(pins, transport_inode=-1))


def test_replayed_claim_with_self_asserted_external_attestation_refused(peer):
    _, conn, pins = peer
    witness = LocalTransportWitness(conn, pins)
    forged = claimed(pins)
    forged["externallyAttested"] = True
    with pytest.raises(TransportBoundaryRefused):
        witness.finish(forged)
    with pytest.raises(TransportBoundaryRefused):
        witness.finish(claimed(pins))


def test_forged_socket_getsockopt_cannot_self_certify_kernel_peer(peer):
    _, conn, pins = peer

    class ForgedSocket:
        def fileno(self):
            return conn.fileno()

        def getsockopt(self, *_args):
            raise AssertionError("fake getsockopt must never be consulted")

    with pytest.raises(TransportBoundaryRefused, match="UNTRUSTED_SOCKET_WRAPPER"):
        LocalTransportWitness(ForgedSocket(), pins)


def test_subclass_override_cannot_self_certify_local_measurement(peer):
    _, conn, pins = peer

    class ForgedWitness(LocalTransportWitness):
        def _checked_sample(self):
            raise AssertionError("overridden observer must never run")

    with pytest.raises(TransportBoundaryRefused, match="UNTRUSTED_WITNESS_OVERRIDE"):
        ForgedWitness(conn, pins)
