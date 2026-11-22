"""Deny-only integration checks: no runtime guest channel or disk writer."""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

from auto_tests.installer_observer.boundary_model import (
    BoundaryEvidence,
    ObservationBoundaryModel,
    PeerIdentity,
)
from auto_tests.installer_observer.evidence import Refusal, digest

ROOT = Path(__file__).resolve().parents[2]


def synthetic_boundary():
    peer = PeerIdentity(2201, 4102, 99001)
    session = str(uuid.uuid4())
    transaction = str(uuid.uuid4())
    model = ObservationBoundaryModel(
        peer=peer,
        session_id=session,
        transaction_id=transaction,
        expires_at=200.0,
        evidence=BoundaryEvidence("a" * 64, "b" * 64, "c" * 64, "untrusted-fixture"),
        state={"screen": "fixture", "installationAuthorized": False},
        framebuffer_png=b"not-a-live-frame",
        clock=lambda: 100.0,
    )
    return model, peer, session, transaction


def request(session, transaction, operation, *, sequence=0):
    return {
        "protocol": 1,
        "operation": operation,
        "session_id": session,
        "transaction_id": transaction,
        "request_id": str(uuid.uuid4()),
        "sequence": sequence,
    }


@pytest.mark.parametrize(
    "operation",
    (
        "install",
        "click",
        "input.send",
        "qmp.execute",
        "rfb.input",
        "disk.write",
        "session.approve",
        "controller.lease",
    ),
)
def test_no_operational_guest_authority(operation):
    model, peer, session, transaction = synthetic_boundary()
    with pytest.raises(Refusal, match="allowlist"):
        model.dispatch(peer, request(session, transaction, operation))


def test_no_local_network_process_or_writer_imports():
    for relative_path in (
        "auto_tests/installer_observer/boundary_model.py",
        "auto_tests/installer_observer/evidence.py",
    ):
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(
                    name.name.split(".")[0] in {"subprocess", "socket", "paramiko", "vncdotool"}
                    for name in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in {
                    "subprocess",
                    "socket",
                    "paramiko",
                    "vncdotool",
                }
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                assert not (
                    node.value.id == "os"
                    and node.attr in {"O_CREAT", "O_TRUNC", "O_WRONLY", "O_RDWR"}
                )


def test_declared_provenance_cannot_be_promoted_to_attestation():
    model, peer, session, transaction = synthetic_boundary()
    claim = model.dispatch(peer, request(session, transaction, "session.identify"))
    assert claim["provenance"] == "synthetic-model-fixture"
    assert claim["signature_verified"] is False
    assert claim["trust_boundary"] == "not-established-by-this-model"
    assert "input_authorized" not in claim
    state = model.dispatch(peer, request(session, transaction, "state.read", sequence=1))
    assert state["state"]["installationAuthorized"] is False
    state["state"]["installationAuthorized"] = True
    fresh = model.dispatch(peer, request(session, transaction, "state.read", sequence=2))
    assert fresh["state"]["installationAuthorized"] is False


@pytest.mark.parametrize("invalid", (True, False, 0, 1, "4102"))
def test_noncanonical_process_identity_is_rejected(invalid):
    peer = PeerIdentity(2201, invalid, 99001)
    with pytest.raises(Refusal, match="invalid simulation fixture"):
        ObservationBoundaryModel(
            peer=peer,
            session_id=str(uuid.uuid4()),
            transaction_id=str(uuid.uuid4()),
            expires_at=200.0,
            evidence=BoundaryEvidence("a" * 64, "b" * 64, "c" * 64, "fixture"),
            state={},
            framebuffer_png=b"fixture",
            clock=lambda: 100.0,
        )


def test_frame_is_synthetic_and_session_closure_is_only_local():
    model, peer, session, transaction = synthetic_boundary()
    frame = model.dispatch(peer, request(session, transaction, "frame.read"))
    assert frame["framebuffer_png"] == b"not-a-live-frame"
    assert frame["framebuffer_sha256"] == digest(frame["framebuffer_png"])
    closed = model.dispatch(peer, request(session, transaction, "session.close", sequence=1))
    assert closed == {
        "protocol": 1,
        "operation": "session.close",
        "session_id": session,
        "transaction_id": transaction,
        "closed": True,
        "revocation": "in-memory-model-only",
    }
    with pytest.raises(Refusal, match="closed or expired"):
        model.dispatch(peer, request(session, transaction, "state.read", sequence=2))
