"""Adversarial tests for the explicitly synthetic Observer API contract."""

import uuid

import pytest

from auto_tests.installer_observer.boundary_model import (
    BoundaryEvidence,
    ObservationBoundaryModel,
    PeerIdentity,
)
from auto_tests.installer_observer.evidence import Refusal, digest


@pytest.fixture
def boundary():
    peer = PeerIdentity(uid=2201, pid=4102, start_ticks=99001)
    session_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    evidence = BoundaryEvidence(
        controller_artifact_sha256="a" * 64,
        policy_sha256="b" * 64,
        qemu_identity_sha256="c" * 64,
        source_commit="reviewed-fixture-commit",
    )
    def clock():
        return 100.0
    model = ObservationBoundaryModel(
        peer=peer,
        session_id=session_id,
        transaction_id=transaction_id,
        expires_at=200.0,
        evidence=evidence,
        state={"screen": "synthetic-login", "read_only": True},
        framebuffer_png=b"synthetic-png-fixture",
        clock=clock,
    )
    return model, peer, session_id, transaction_id


def request(session_id, transaction_id, operation, sequence=0, request_id=None):
    return {
        "protocol": 1,
        "operation": operation,
        "session_id": session_id,
        "transaction_id": transaction_id,
        "request_id": request_id or str(uuid.uuid4()),
        "sequence": sequence,
    }


def test_identify_returns_explicitly_unverified_provenance(boundary):
    model, peer, session, transaction = boundary
    result = model.dispatch(peer, request(session, transaction, "session.identify"))
    assert result["provenance"] == "synthetic-model-fixture"
    assert result["signature_verified"] is False
    assert result["trust_boundary"] == "not-established-by-this-model"


def test_state_and_frame_are_read_only_and_hash_bound(boundary):
    model, peer, session, transaction = boundary
    state = model.dispatch(peer, request(session, transaction, "state.read", 0))
    frame = model.dispatch(peer, request(session, transaction, "frame.read", 1))
    assert state["state"] == {"screen": "synthetic-login", "read_only": True}
    assert frame["framebuffer_png"] == b"synthetic-png-fixture"
    assert frame["framebuffer_sha256"] == digest(frame["framebuffer_png"])


@pytest.mark.parametrize(
    "operation", ["qmp.execute", "rfb.input", "shell.exec", "install", "partition"]
)
def test_mutating_or_arbitrary_operations_are_refused(boundary, operation):
    model, peer, session, transaction = boundary
    with pytest.raises(Refusal, match="allowlist"):
        model.dispatch(peer, request(session, transaction, operation))


def test_wrong_uid_pid_or_process_start_is_refused(boundary):
    model, peer, session, transaction = boundary
    for hostile in (
        PeerIdentity(peer.uid + 1, peer.pid, peer.start_ticks),
        PeerIdentity(peer.uid, peer.pid + 1, peer.start_ticks),
        PeerIdentity(peer.uid, peer.pid, peer.start_ticks + 1),
    ):
        with pytest.raises(Refusal, match="peer identity"):
            model.dispatch(hostile, request(session, transaction, "state.read"))


def test_foreign_transaction_and_stale_session_are_refused(boundary):
    model, peer, session, transaction = boundary
    bad_transaction = request(session, str(uuid.uuid4()), "state.read")
    with pytest.raises(Refusal, match="transaction"):
        model.dispatch(peer, bad_transaction)
    bad_session = request(str(uuid.uuid4()), transaction, "state.read")
    with pytest.raises(Refusal, match="session"):
        model.dispatch(peer, bad_session)


def test_replayed_request_id_and_sequence_are_refused(boundary):
    model, peer, session, transaction = boundary
    request_id = str(uuid.uuid4())
    first = request(session, transaction, "state.read", 0, request_id)
    model.dispatch(peer, first)
    with pytest.raises(Refusal, match="replay"):
        model.dispatch(peer, first)
    with pytest.raises(Refusal, match="sequence"):
        model.dispatch(peer, request(session, transaction, "state.read", 0))


def test_extra_request_fields_are_refused(boundary):
    model, peer, session, transaction = boundary
    payload = request(session, transaction, "state.read")
    payload["qmp_command"] = "query-status"
    with pytest.raises(Refusal, match="fixed observation contract"):
        model.dispatch(peer, payload)


def test_close_revokes_model_session_and_old_requests(boundary):
    model, peer, session, transaction = boundary
    closed = model.dispatch(peer, request(session, transaction, "session.close"))
    assert closed["closed"] is True
    assert closed["revocation"] == "in-memory-model-only"
    with pytest.raises(Refusal, match="closed or expired"):
        model.dispatch(peer, request(session, transaction, "state.read", 1))


def test_expired_session_is_refused():
    peer = PeerIdentity(2201, 4102, 99001)
    with pytest.raises(Refusal, match="Incomplete or invalid"):
        ObservationBoundaryModel(
            peer=peer,
            session_id=str(uuid.uuid4()),
            transaction_id=str(uuid.uuid4()),
            expires_at=99.0,
            evidence=BoundaryEvidence("a" * 64, "b" * 64, "c" * 64, "fixture"),
            state={"read_only": True},
            framebuffer_png=b"fixture",
            clock=lambda: 100.0,
        )


def test_nonfinite_expiry_is_refused():
    peer = PeerIdentity(2201, 4102, 99001)
    with pytest.raises(Refusal, match="Incomplete or invalid"):
        ObservationBoundaryModel(
            peer=peer,
            session_id=str(uuid.uuid4()),
            transaction_id=str(uuid.uuid4()),
            expires_at=float("nan"),
            evidence=BoundaryEvidence("a" * 64, "b" * 64, "c" * 64, "fixture"),
            state={"read_only": True},
            framebuffer_png=b"fixture",
            clock=lambda: 1.0,
        )
