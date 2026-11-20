"""No-input adversarial contracts for the dedicated laboratory host launcher."""

import os
import socket
from pathlib import Path

import pytest

from auto_tests.installer_observer import isolation_host
from auto_tests.installer_observer.evidence import Refusal


def test_closed_unix_endpoint_never_counts_as_eacces(tmp_path):
    assert isolation_host._connect_as_runner(str(tmp_path / "missing.sock")) == 14


def test_same_uid_open_unix_endpoint_is_not_isolated(tmp_path):
    endpoint = tmp_path / "open.sock"
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(endpoint))
        server.listen(1)
        assert isolation_host._connect_as_runner(str(endpoint)) == 0


def test_original_uid_denied_by_private_directory_simulation(monkeypatch, tmp_path):
    def forbidden(*_args, **_kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(isolation_host.socket.socket, "connect", forbidden, raising=False)
    assert isolation_host._connect_as_runner(str(tmp_path / "private.sock")) == 13


def test_launcher_refuses_root(monkeypatch, tmp_path):
    monkeypatch.setattr(isolation_host.os, "geteuid", lambda: 0)
    with pytest.raises(Refusal, match="Unprivileged"):
        isolation_host.run(tmp_path.absolute(), "gaslux_observer_ci", tmp_path / "evidence")


def test_launcher_refuses_unexpected_identity(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("The observer contracts require unprivileged Linux CI")
    with pytest.raises(Refusal, match="Unexpected isolated service"):
        isolation_host.run(tmp_path.absolute(), "nobody", tmp_path / "evidence")


def test_launcher_refuses_nonprivate_scratch_name(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("The observer contracts require unprivileged Linux CI")
    with pytest.raises(Refusal, match="Unexpected private scratch root"):
        isolation_host.run(
            Path("/tmp/another-user-session"), "gaslux_observer_ci", tmp_path / "evidence"
        )
