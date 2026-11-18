"""Synthetic negative tests for bounded Bazzite diskless OCR evidence review."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_legacy_ocr_audit import REQUIRED, EvidenceRefusal, audit  # noqa: E402


def fixture_dir(tmp_path, text="Install Bazzite"):
    obj = dict(REQUIRED)
    lower = text.lower()
    obj.update(
        bazziteTextObserved="bazzite" in lower,
        anacondaTextObserved="anaconda" in lower,
        blivetTextObserved="blivet" in lower,
        installationUiCandidateObserved="install" in lower,
    )
    (tmp_path / "guest-observation.json").write_text(json.dumps(obj), encoding="utf-8")
    for index in range(1, 5):
        (tmp_path / f"screen-{index}.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes([index]))
        (tmp_path / f"ocr-{index}.txt").write_text(text, encoding="utf-8")
    return tmp_path


def test_generic_install_text_is_not_anaconda_proof(tmp_path):
    report = audit(fixture_dir(tmp_path))
    assert report["screenCount"] == 4
    assert report["anacondaSpecificTextCandidate"] is False
    assert report["blivetSpecificTextCandidate"] is False
    assert report["actualInstallerBinaryVerified"] is False
    assert report["installationAuthorized"] is False


def test_repeated_bazzite_42_welcome_is_ui_evidence_not_payload_identity(tmp_path):
    text = "BAZZITE 42 INSTALLATION\nWELCOME TO BAZZITE 42."
    report = audit(fixture_dir(tmp_path, text))
    assert report["legacyInstallerWelcomeVersionAdvertised"] == "42"
    assert report["repeatedLegacyInstallerWelcomeObserved"] is True
    assert report["advertisedVersionBoundToInstalledPayload"] is False
    assert report["actualInstallerBinaryVerified"] is False
    assert report["installationAuthorized"] is False


def test_conflicting_legacy_welcome_version_refused(tmp_path):
    text = "BAZZITE 42 INSTALLATION\nWELCOME TO BAZZITE 43."
    with pytest.raises(EvidenceRefusal, match="Conflicting"):
        audit(fixture_dir(tmp_path, text))


def test_specific_ui_words_still_do_not_authorize_install(tmp_path):
    report = audit(fixture_dir(tmp_path, "Anaconda Installation Summary Blivet Bazzite"))
    assert report["anacondaSpecificTextCandidate"] is True
    assert report["blivetSpecificTextCandidate"] is True
    assert report["actualInstallerBinaryVerified"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"noGuestHardDisk": False},
        {"noGuestNetwork": False},
        {"isoCryptographicProvenanceVerified": True},
        {"installationAuthorized": True},
        {"windowsEspWriteAuthorized": True},
        {"foreignProperty": True},
    ],
)
def test_unsafe_guest_claim_refused(tmp_path, change):
    path = fixture_dir(tmp_path) / "guest-observation.json"
    record = json.loads(path.read_text())
    record.update(change)
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(EvidenceRefusal):
        audit(tmp_path)


def test_ocr_and_original_report_mismatch_refused(tmp_path):
    path = fixture_dir(tmp_path) / "guest-observation.json"
    record = json.loads(path.read_text())
    record["anacondaTextObserved"] = True
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(EvidenceRefusal, match="OCR"):
        audit(tmp_path)


def test_symlink_png_refused(tmp_path):
    fixture_dir(tmp_path)
    target = tmp_path / "screen-2.png"
    target.unlink()
    target.symlink_to(tmp_path / "screen-1.png")
    with pytest.raises(EvidenceRefusal, match="Symlink"):
        audit(tmp_path)


def test_missing_fourth_ocr_refused(tmp_path):
    fixture_dir(tmp_path)
    (tmp_path / "ocr-4.txt").unlink()
    with pytest.raises(OSError):
        audit(tmp_path)
