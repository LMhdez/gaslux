"""Negative contracts for cooperative controller ownership; no guest input."""

from dataclasses import replace

import pytest

from auto_tests.installer_observer import controller_lease as module
from auto_tests.installer_observer.evidence import Refusal
from auto_tests.installer_observer.lab_identity import ProcessSeal


def fixture_lease(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    identity = ProcessSeal(9999, 1000, 123, "a" * 64, 1, 2)
    monkeypatch.setattr(module, "process_seal", lambda _pid: identity)
    monkeypatch.setattr(module.os, "geteuid", lambda: tmp_path.stat().st_uid)
    return module.ControllerLease(tmp_path, identity), identity


def test_second_cooperating_controller_refused(tmp_path, monkeypatch):
    first, identity = fixture_lease(tmp_path, monkeypatch)
    with first:
        first.verify()
        with pytest.raises(Refusal, match="second controller"):
            with module.ControllerLease(tmp_path, identity):
                pass
        first.verify()
    with module.ControllerLease(tmp_path, identity) as second:
        second.verify()


def test_qemu_restart_revokes_lease(tmp_path, monkeypatch):
    lease, identity = fixture_lease(tmp_path, monkeypatch)
    with lease:
        monkeypatch.setattr(
            module, "process_seal", lambda _pid: replace(identity, start_ticks=124)
        )
        with pytest.raises(Refusal, match="diverged"):
            lease.verify()


def test_replaced_lockfile_revokes_lease(tmp_path, monkeypatch):
    lease, _identity = fixture_lease(tmp_path, monkeypatch)
    with lease:
        lock = tmp_path / ".observer-controller.lock"
        lock.unlink()
        lock.write_text("different inode")
        with pytest.raises(Refusal, match="diverged"):
            lease.verify()


def test_world_accessible_directory_is_rejected(tmp_path, monkeypatch):
    lease, _identity = fixture_lease(tmp_path, monkeypatch)
    tmp_path.chmod(0o755)
    with pytest.raises(Refusal, match="not private"):
        with lease:
            pass


def test_symlink_controller_directory_rejected(tmp_path, monkeypatch):
    lease, _identity = fixture_lease(tmp_path, monkeypatch)
    link = tmp_path.parent / (tmp_path.name + "-link")
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(Refusal, match="Noncanonical"):
        with module.ControllerLease(link, lease.expected):
            pass


def test_lease_never_exposes_guest_input(tmp_path, monkeypatch):
    lease, _identity = fixture_lease(tmp_path, monkeypatch)
    assert not hasattr(lease, "click")
    assert not hasattr(lease, "send_key")
    with pytest.raises(Refusal, match="Missing"):
        lease.verify()
