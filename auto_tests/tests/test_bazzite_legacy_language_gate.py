"""Negative contracts for OCR-derived, non-authorized legacy installer coordinates."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_legacy_language_gate import (  # noqa: E402
    EXPECTED_SCREEN_SHA,
    ScreenRefusal,
    inspect,
)

FIELDS = "level\tconf\tleft\ttop\twidth\theight\ttext\n"
LINE = "5\t95\t1120\t740\t80\t24\tContinue\n"


def probe(**kwargs):
    args = {
        "width": 1280,
        "height": 800,
        "png_sha": EXPECTED_SCREEN_SHA,
        "ocr": "BAZZITE 42 INSTALLATION\nWELCOME TO BAZZITE 42.\nContinue",
        "tsv": FIELDS + LINE,
    }
    args.update(kwargs)
    return inspect(**args)


def test_target_only_preview_and_install_flags_false():
    result = probe()
    assert result["unambiguousContinueLabelCandidate"] is True
    assert result["candidateCenter"]["x"] == 1160
    assert result["candidateCenter"]["y"] == 752
    for k in (
        "installerInputAuthorized",
        "installationAuthorized",
        "partitionWriteAuthorized",
        "windowsEspWriteAuthorized",
        "secureBootEnrollmentAuthorized",
        "actualInstallerBinaryVerified",
        "blivetGuiVerified",
    ):
        assert result[k] is False


@pytest.mark.parametrize(
    "change",
    [
        {"width": 0},
        {"height": 0},
        {"png_sha": "a" * 64},
        {"ocr": "WELCOME TO BAZZITE 45"},
        {"ocr": "WELCOME TO BAZZITE 42"},
        {"tsv": FIELDS},
        {"tsv": FIELDS + LINE + LINE},
        {"tsv": FIELDS + "5\t95\t100\t740\t80\t24\tContinue\n"},
        {"tsv": FIELDS + "5\t9\t1120\t740\t80\t24\tContinue\n"},
    ],
)
def test_ambiguous_or_mismatched_inputs_deny_navigation(change):
    if "png_sha" in change or "ocr" in change or "width" in change or "height" in change:
        with pytest.raises(ScreenRefusal):
            probe(**change)
    else:
        result = probe(**change)
        assert not result["unambiguousContinueLabelCandidate"]
        assert result["installerInputAuthorized"] is False


def test_missing_tsv_header_refused():
    with pytest.raises(ScreenRefusal):
        probe(tsv="Continue")
