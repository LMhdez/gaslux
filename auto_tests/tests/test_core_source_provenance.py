"""Fail-closed Gaslux source identity checks before any laboratory connection."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.errors import WorkflowError
from app.services.common import ResultBuilder
from app.services.validation import ValidationService
from test_core import settings


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
        settings(repository_url=origin)


def test_gaslux_source_has_no_inherited_published_endpoint() -> None:
    assert settings().published_dev_metadata_base_url is None


def test_gaslux_source_local_upstream_refused_before_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = _checkout(tmp_path, "https://github.com/ekimiateam/libertix.git")
    service = ValidationService(settings())
    monkeypatch.setattr(service, "_local_repository_root", lambda: root)

    def forbidden_ssh(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("SSH was attempted before source identity validation")

    monkeypatch.setattr(service, "ssh", forbidden_ssh)
    with pytest.raises(WorkflowError, match="Gaslux"):
        service.prepare_server(ResultBuilder("validation"), source="local")


def test_gaslux_source_published_refused_before_ssh(monkeypatch: pytest.MonkeyPatch) -> None:
    service = ValidationService(settings())

    def forbidden_ssh(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("SSH was attempted for an unverified published release")

    monkeypatch.setattr(service, "ssh", forbidden_ssh)
    with pytest.raises(WorkflowError, match="Gaslux"):
        service.prepare_server(ResultBuilder("validation"), source="published")


def test_gaslux_source_local_records_revision_before_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, revision = _checkout(tmp_path, "https://github.com/LMhdez/gaslux.git")
    service = ValidationService(settings())
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
