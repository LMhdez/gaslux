"""Adversarial private-endpoint checks, never an input authorization."""

import os
import socket
from dataclasses import replace

import pytest

from auto_tests.installer_observer import endpoint_gates
from auto_tests.installer_observer.evidence import Refusal
from auto_tests.installer_observer.lab_identity import ProcessSeal


@pytest.fixture
def endpoint(tmp_path):
    tmp_path.chmod(0o700)
    target = tmp_path / "rfb.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(target))
        target.chmod(0o600)
        yield endpoint_gates.seal_endpoint(target, os.geteuid())


def test_private_socket_is_sealed(endpoint):
    endpoint_gates.verify_endpoint(endpoint)


def test_unexpected_socket_owner_rejected(endpoint):
    with pytest.raises(Refusal, match="not private"):
        endpoint_gates.seal_endpoint(endpoint.path, endpoint.uid + 1)


def test_world_accessible_socket_rejected(endpoint):
    endpoint.path.chmod(0o666)
    with pytest.raises(Refusal, match="not private"):
        endpoint_gates.verify_endpoint(endpoint)


def test_replaced_socket_is_rejected(endpoint):
    endpoint.path.unlink()
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(endpoint.path))
        endpoint.path.chmod(0o600)
        with pytest.raises(Refusal, match="replaced"):
            endpoint_gates.verify_endpoint(endpoint)


def test_symlink_and_parent_symlink_refused(endpoint):
    link = endpoint.path.with_name("alias.sock")
    link.symlink_to(endpoint.path)
    with pytest.raises(Refusal, match="not private"):
        endpoint_gates.seal_endpoint(link, endpoint.uid)
    alias_dir = endpoint.path.parent.with_name(endpoint.path.parent.name + "-alias")
    alias_dir.symlink_to(endpoint.path.parent, target_is_directory=True)
    with pytest.raises(Refusal, match="not private"):
        endpoint_gates.seal_endpoint(alias_dir / endpoint.path.name, endpoint.uid)


def test_stale_session_or_foreign_endpoint_cannot_cleanup(endpoint):
    with pytest.raises(Refusal, match="replaced"):
        endpoint_gates.clean_owned_endpoint(replace(endpoint, inode=endpoint.inode + 1))
    assert endpoint.path.exists()


def test_owned_endpoint_cleanup(endpoint):
    endpoint_gates.clean_owned_endpoint(endpoint)
    assert not endpoint.path.exists()
    endpoint_gates.clean_owned_endpoint(endpoint)


def test_process_replacement_refused_by_tcp_gate(monkeypatch):
    expected = ProcessSeal(1234, os.geteuid(), 7, "x", 1, 2)
    monkeypatch.setattr(
        endpoint_gates, "process_seal", lambda _pid: replace(expected, start_ticks=8)
    )
    with pytest.raises(Refusal, match="identity changed"):
        endpoint_gates.assert_no_qemu_tcp_listeners(expected)


def test_wrong_process_refused_by_peer_gate(monkeypatch, endpoint):
    expected = ProcessSeal(1234, os.geteuid(), 7, "x", 1, 2)
    monkeypatch.setattr(
        endpoint_gates, "process_seal", lambda _pid: replace(expected, start_ticks=8)
    )
    import time

    with pytest.raises(Refusal, match="identity"):
        endpoint_gates.verified_unix_peer(endpoint, expected, time.monotonic() + 1)
