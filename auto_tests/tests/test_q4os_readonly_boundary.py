"""Deny-only geometry, QMP allowlist and public run_lab contract (no QEMU)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import q4os_qemu_fd_compat_lab as lab  # noqa: E402
import q4os_win10_qmp_supervisor as supervisor  # noqa: E402


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("format", "raw"),
        ("virtual-size", 32 * 1024 * 1024),
        ("cluster-size", 4096),
        ("backing-filename", "foreign.img"),
        ("full-backing-filename", "foreign.img"),
    ],
)
def test_readonly_geometry_contract_rejects_unowned_or_wrong_image(field, value):
    info = {
        "format": "qcow2",
        "virtual-size": 64 * 1024 * 1024,
        "cluster-size": 65536,
    }
    info[field] = value
    with pytest.raises(lab.LabRefusal, match="QCOW2_GEOMETRY_OR_BACKING_INVALID"):
        lab.verify_qcow2_contract(info)


def test_readonly_geometry_contract_accepts_exact_backing_free_image():
    lab.verify_qcow2_contract(
        {"format": "qcow2", "virtual-size": 64 * 1024 * 1024, "cluster-size": 65536}
    )


def test_diagnostic_qmp_allowlist_contains_no_guest_or_media_commands():
    assert lab.ALLOWED_QMP == {
        "qmp_capabilities",
        "query-status",
        "query-block",
        "query-fdsets",
    }
    assert not supervisor.QEMU_FD_BACKING_VERIFIED


@pytest.mark.parametrize("factory_name", ["popen_factory", "pidfd_factory"])
def test_public_runlab_denies_untrusted_factory_before_effects(tmp_path, factory_name):
    """Even explicit imports cannot grant operational spawn or write rights."""
    called = []

    def forbidden(*_args, **_kwargs):
        called.append(True)
        raise AssertionError("factory must not be called")

    path = tmp_path / "never-created"
    kwargs = {factory_name: forbidden}
    result = supervisor.run_lab(path, path, path, path, path, path, "tcg", **kwargs)
    assert result["decision"] == "refuse"
    assert result["qemuSpawned"] is False
    assert result["qmpSendKeyAcknowledged"] is False
    assert result["diskWritesAuthorized"] is False
    assert result["installationAuthorized"] is False
    assert not called
    assert not path.exists()


def test_public_runlab_denied_without_factory_and_without_creating_paths(tmp_path):
    path = tmp_path / "never-created"
    result = supervisor.run_lab(path, path, path, path, path, path, "tcg")
    assert result["decision"] == "refuse"
    assert result["qemuSpawned"] is False
    assert not path.exists()
