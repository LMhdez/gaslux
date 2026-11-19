"""Integrity tests for the Q4OS GUI evidence manifest."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gaslux_q4os_evidence_manifest import (
    EvidenceManifestError,
    create_manifest,
    verify_manifest,
)  # noqa: E402, I001


def _evidence(tmp_path: Path) -> Path:
    directory = tmp_path / "evidence"
    directory.mkdir(mode=0o700)
    (directory / "serial.log").write_bytes(b"Q4OS live guest boot\\n")
    (directory / "vnc-users-page.png").write_bytes(b"synthetic screenshot bytes")
    (directory / "q4os-audit.json").write_text('{"installationAuthorized":false}\\n')
    return directory


def test_manifest_is_deterministic_and_covers_all_regular_evidence(tmp_path):
    directory = _evidence(tmp_path)
    manifest = create_manifest(directory)
    first = manifest.read_bytes()
    verify_manifest(
        directory,
        {"serial.log", "vnc-users-page.png", "q4os-audit.json"},
    )
    create_manifest(directory)
    assert manifest.read_bytes() == first
    assert [line.split(b"  ", 1)[1] for line in first.splitlines()] == [
        b"q4os-audit.json",
        b"serial.log",
        b"vnc-users-page.png",
    ]


def test_manifest_refuses_modified_evidence(tmp_path):
    directory = _evidence(tmp_path)
    create_manifest(directory)
    (directory / "vnc-users-page.png").write_bytes(b"modified screenshot")
    with pytest.raises(EvidenceManifestError, match="SHA-256 mismatch"):
        verify_manifest(directory)


def test_manifest_refuses_missing_or_unlisted_evidence(tmp_path):
    directory = _evidence(tmp_path)
    create_manifest(directory)
    (directory / "serial.log").unlink()
    with pytest.raises(EvidenceManifestError, match="exactly match"):
        verify_manifest(directory)
    (directory / "serial.log").write_bytes(b"restored")
    (directory / "unexpected.bin").write_bytes(b"unlisted")
    with pytest.raises(EvidenceManifestError, match="exactly match"):
        verify_manifest(directory)


def test_manifest_refuses_symlinked_evidence(tmp_path):
    directory = _evidence(tmp_path)
    (directory / "external.log").symlink_to(directory / "serial.log")
    with pytest.raises(EvidenceManifestError, match="non-regular"):
        create_manifest(directory)


def test_manifest_requires_all_declared_artifacts(tmp_path):
    directory = _evidence(tmp_path)
    create_manifest(directory)
    with pytest.raises(EvidenceManifestError, match="required evidence missing"):
        verify_manifest(directory, {"serial.log", "gpt-audit.txt"})


def test_manifest_refuses_platform_without_o_nofollow(tmp_path, monkeypatch):
    directory = _evidence(tmp_path)
    create_manifest(directory)
    monkeypatch.delattr("os.O_NOFOLLOW", raising=False)
    with pytest.raises(EvidenceManifestError, match="does not expose O_NOFOLLOW"):
        verify_manifest(directory)
    (directory / "evidence.sha256").unlink()
    with pytest.raises(EvidenceManifestError, match="does not expose O_NOFOLLOW"):
        create_manifest(directory)


def test_manifest_refuses_symlinked_manifest(tmp_path):
    directory = _evidence(tmp_path)
    create_manifest(directory)
    manifest = directory / "evidence.sha256"
    manifest.unlink()
    manifest.symlink_to(directory / "serial.log")
    with pytest.raises(EvidenceManifestError, match="manifest is missing or unsafe"):
        verify_manifest(directory)
