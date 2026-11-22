"""Fail-closed Gaslux source identity checks before any laboratory connection."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from app.config import Settings
from app.models import AutomationRequest
from app.services.automation import AutomationService
from app.errors import WorkflowError
from app.services.common import ResultBuilder
from app.services.validation import ValidationService
from pydantic import ValidationError


def _settings(**overrides: object) -> Settings:
    """Standalone fake laboratory configuration; all addresses are reserved examples."""

    values: dict[str, object] = {
        "main_ssh_host": "192.0.2.10",
        "main_ssh_user": "test",
        "main_ssh_password": "example",
        "windows_ssh_password": "example",
        "samba_unc": r"\\192.0.2.10\share",
        "samba_username": "test",
        "samba_password": "example",
        "build_vm_host": "192.0.2.11",
        "build_vm_user": "test",
        "build_vm_password": "example",
        "ssh_known_hosts": "/tmp/gaslux-test-known-hosts",
        "filepool_base_url": "http://192.0.2.12:8000/filepool",
        "development_static_ipv4_prefix_length": 24,
        "development_static_ipv4_gateway": "192.0.2.1",
        "development_dns_servers": ("192.0.2.53",),
        "repository_url": "https://github.com/LMhdez/gaslux.git",
        "smb_root": "/srv/gaslux-test",
        "allowed_smb_roots": ("/srv/gaslux-test",),
        "allowed_proxmox_vmids": (501,),
        "llm_api_url": "http://192.0.2.13:8000/v1",
        "llm_api_key": "example",
        "llm_model": "example",
        "proxmox_url": "https://192.0.2.14:8006",
        "proxmox_token_id": "test@pve!fake",
        "proxmox_token_secret": "example",
        "vms": (
            {
                "name": "vm2",
                "host": "192.0.2.15",
                "os": "Windows 10 UEFI",
                "vnc": "192.0.2.14:11",
                "screen_width": 1280,
                "screen_height": 800,
                "vmid": 501,
                "firmware": "uefi",
                "automation_enabled": True,
            },
        ),
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def _checkout(tmp_path: Path, origin: str) -> tuple[Path, str]:
    root = tmp_path / "checkout"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "seed.txt").write_text("test-only checkout\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "seed.txt"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=Gaslux CI",
            "-c",
            "user.email=ci@example.invalid",
            "commit",
            "-qm",
            "Synthetic test source",
        ],
        check=True,
    )
    subprocess.run(["git", "-C", str(root), "remote", "add", "origin", origin], check=True)
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return root, revision


@pytest.mark.parametrize(
    "origin",
    [
        "https://github.com/ekimiateam/libertix.git",
        "https://github.com/LMhdez/gaslux.evil.git",
        "https://github.com/LMhdez/gaslux.git?ref=upstream",
    ],
)
def test_gaslux_source_rejects_foreign_remote_config(origin: str) -> None:
    with pytest.raises(ValidationError, match="Gaslux"):
        _settings(repository_url=origin)


def test_gaslux_source_has_no_inherited_published_endpoint() -> None:
    assert _settings().published_dev_metadata_base_url is None


def test_gaslux_source_local_upstream_refused_before_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = _checkout(tmp_path, "https://github.com/ekimiateam/libertix.git")
    service = ValidationService(_settings())
    monkeypatch.setattr(service, "_local_repository_root", lambda: root)

    def forbidden_ssh(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("SSH was attempted before source identity validation")

    monkeypatch.setattr(service, "ssh", forbidden_ssh)
    with pytest.raises(WorkflowError, match="Gaslux"):
        service.prepare_server(ResultBuilder("validation"), source="local")


def test_gaslux_source_published_refused_before_ssh(monkeypatch: pytest.MonkeyPatch) -> None:
    service = ValidationService(_settings())

    def forbidden_ssh(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("SSH was attempted for an unverified published release")

    monkeypatch.setattr(service, "ssh", forbidden_ssh)
    with pytest.raises(WorkflowError, match="Gaslux"):
        service.prepare_server(ResultBuilder("validation"), source="published")


def test_gaslux_source_local_records_revision_before_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, revision = _checkout(tmp_path, "https://github.com/LMhdez/gaslux.git")
    service = ValidationService(_settings())
    monkeypatch.setattr(service, "_local_repository_root", lambda: root)

    class ConnectionAttempt(Exception):
        pass

    def stop_before_ssh(*_args: object, **_kwargs: object) -> None:
        raise ConnectionAttempt

    monkeypatch.setattr(service, "ssh", stop_before_ssh)
    result = ResultBuilder("validation")
    with pytest.raises(ConnectionAttempt):
        service.prepare_server(result, source="local")

    assert result.steps[0].step == "server.source_provenance"
    assert result.steps[0].context["revision"] == revision
    assert result.steps[0].context["repository"] == "LMhdez/gaslux"



@pytest.mark.parametrize("source", ["published", "local"])
@pytest.mark.parametrize("prepared_release", [None, (r"C:\test\Libertix.exe", "0" * 64)])
def test_automation_denies_invalid_source_before_any_vm_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    prepared_release: tuple[str, str] | None,
) -> None:
    """Safety F-361-01: even a prebuilt campaign lane must not restore a VM first."""

    service = AutomationService(_settings())
    if source == "local":
        root, _ = _checkout(tmp_path, "https://github.com/ekimiateam/libertix.git")
        monkeypatch.setattr(service.validation, "_local_repository_root", lambda: root)
    remote_restore = Mock(side_effect=AssertionError("Proxmox snapshot was reached"))
    remote_proxmox = Mock(side_effect=AssertionError("Proxmox client was reached"))
    remote_ssh = Mock(side_effect=AssertionError("SSH client was reached"))
    remote_windows = Mock(side_effect=AssertionError("Windows preparation was reached"))
    remote_secondary = Mock(side_effect=AssertionError("secondary VM boot was reached"))
    monkeypatch.setattr(service, "_restore_clean_snapshots", remote_restore)
    monkeypatch.setattr(service, "_proxmox", remote_proxmox)
    monkeypatch.setattr(service.validation, "ssh", remote_ssh)
    monkeypatch.setattr(service, "_prepare_windows_test_vm", remote_windows)
    monkeypatch.setattr(service, "_prepare_secondary_boot_devices", remote_secondary)

    result = service.run(
        ["vm2"],
        AutomationRequest(apply=True, linux_password="example", source=source),
        run_workspace=tmp_path,
        prepared_release=prepared_release,
    )
    assert result.status == "error"
    assert any(
        step.step == "server.source_provenance" and step.status == "error"
        for step in result.steps
    )
    remote_restore.assert_not_called()
    remote_proxmox.assert_not_called()
    remote_ssh.assert_not_called()
    remote_windows.assert_not_called()
    remote_secondary.assert_not_called()


@pytest.mark.parametrize("source", ["remote", "local"])
def test_valid_automation_source_can_reach_mocked_vm_barrier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    """A valid local checkout or configured remote source must remain admissible."""

    service = AutomationService(_settings())
    if source == "local":
        root, _ = _checkout(tmp_path, "https://github.com/LMhdez/gaslux.git")
        monkeypatch.setattr(service.validation, "_local_repository_root", lambda: root)
    restore = Mock(side_effect=RuntimeError("stop at mock VM barrier"))
    ssh = Mock(side_effect=AssertionError("unexpected SSH before VM barrier"))
    monkeypatch.setattr(service, "_restore_clean_snapshots", restore)
    monkeypatch.setattr(service.validation, "ssh", ssh)

    result = service.run(
        ["vm2"],
        AutomationRequest(apply=True, linux_password="example", source=source),
        run_workspace=tmp_path,
        prepared_release=(r"C:\test\Libertix.exe", "0" * 64),
    )
    assert result.status == "error"  # stopped by the mock, not a live operation
    assert restore.call_count == 1
    ssh.assert_not_called()
    assert any(
        step.step == "server.source_provenance" and step.status == "ok"
        for step in result.steps
    )
