"""Contracts for the GPT guest's one permitted storage-navigation click."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_legacy_gpt_storage_navigation import (  # noqa: E402
    StorageNavigationRefusal,
    locate_storage_tile,
)

OCR = """INSTALLATION SUMMARY,
LOCALISATION
SYSTEM
Installation Destination
Automatic partitioning selected
Network & Host Name
No network devices available
BAZZITE 42 INSTALLATION
Quit Begin Installation
"""
HEADER = "\\t".join(
    ["level", "page_num", "block_num", "par_num", "line_num", "word_num",
     "left", "top", "width", "height", "conf", "text"]
) + "\\n"
TSV = HEADER + (
    "\\t".join(["5", "1", "11", "1", "1", "1", "674", "322", "81", "12", "96.8", "Installation"]) + "\\n"
    + "\\t".join(["5", "1", "11", "1", "1", "2", "759", "322", "83", "12", "92.8", "Destination"]) + "\\n"
)


def test_locates_only_the_unique_destination_navigation_tile():
    result = locate_storage_tile(OCR, TSV, 1280, 800)
    assert result["coordinate"] == {"x": 758, "y": 328}
    assert result["syntheticGptGuestOnly"] is True
    for key in (
        "diskIdentityIndependentlyVerified",
        "installerBinaryIdentityVerified",
        "isoProvenanceSignatureVerified",
        "installationAuthorized",
        "partitionWriteAuthorized",
        "windowsEspWriteAuthorized",
    ):
        assert result[key] is False


@pytest.mark.parametrize(
    "ocr",
    [
        OCR.replace("BAZZITE 42", "BAZZITE 45"),
        OCR.replace("Automatic partitioning selected", "Custom partitioning selected"),
        OCR.replace("Installation Destination", "Installation Storage"),
        OCR.replace("No network devices available", ""),
    ],
)
def test_missing_or_changed_summary_markers_refuse(ocr):
    with pytest.raises(StorageNavigationRefusal):
        locate_storage_tile(ocr, TSV, 1280, 800)


@pytest.mark.parametrize(
    "tsv",
    [
        HEADER,
        TSV + TSV.split(HEADER, 1)[1],
        TSV.replace("674\\t322", "974\\t322"),
        TSV.replace("759\\t322", "900\\t322"),
    ],
)
def test_ambiguous_or_out_of_bounds_tile_refuses(tsv):
    with pytest.raises(StorageNavigationRefusal):
        locate_storage_tile(OCR, tsv, 1280, 800)


def test_wrong_framebuffer_refuses():
    with pytest.raises(StorageNavigationRefusal):
        locate_storage_tile(OCR, TSV, 1024, 768)
