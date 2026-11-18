"""Negative contracts for no-disk Bazzite 42 legacy installer selection."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_legacy_diskless_navigation import (  # noqa: E402
    NavigationRefusal,
    locate_continue,
    locate_english_uk,
)

BANNER = "BAZZITE 42 INSTALLATION\nWELCOME TO BAZZITE 42.\n"
TSV_HEAD = "level\tconf\tleft\ttop\twidth\theight\ttext\n"
LOCALE = (
    "5\t96\t750\t205\t56\t22\tEnglish\n"
    "5\t95\t810\t205\t60\t22\t(United\n"
    "5\t93\t877\t205\t70\t22\tKingdom)\n"
)
CONTINUE = "5\t99\t1110\t740\t90\t24\tContinue\n"


def test_unique_locale_target_only_in_diskless_guest():
    result = locate_english_uk(BANNER, TSV_HEAD + LOCALE, 1280, 800)
    assert result["coordinate"] == {"x": 778, "y": 216}
    assert result["installationAuthorized"] is False
    assert result["partitionWriteAuthorized"] is False


@pytest.mark.parametrize(
    "ocr,tsv,width,height",
    [
        ("WELCOME TO BAZZITE 45", TSV_HEAD + LOCALE, 1280, 800),
        (BANNER, TSV_HEAD + LOCALE, 1024, 768),
        (BANNER, TSV_HEAD, 1280, 800),
        (BANNER, TSV_HEAD + LOCALE + LOCALE, 1280, 800),
        (BANNER, TSV_HEAD + "5\t96\t120\t205\t56\t22\tEnglish\n", 1280, 800),
    ],
)
def test_refuse_ambiguous_or_unknown_locale(ocr, tsv, width, height):
    with pytest.raises(NavigationRefusal):
        locate_english_uk(ocr, tsv, width, height)


def test_continue_requires_unique_lower_right_label():
    result = locate_continue(BANNER, TSV_HEAD + CONTINUE, 1280, 800)
    assert result["targetUniquelyObserved"] is True
    assert result["coordinate"] == {"x": 1155, "y": 752}
    assert result["installationAuthorized"] is False


def test_missing_continue_does_not_forge_a_click():
    result = locate_continue(BANNER, TSV_HEAD + LOCALE, 1280, 800)
    assert result["coordinate"] is None
    assert result["targetUniquelyObserved"] is False


def test_continue_outside_expected_region_not_targeted():
    result = locate_continue(BANNER, TSV_HEAD + "5\t96\t160\t350\t80\t20\tContinue\n", 1280, 800)
    assert result["coordinate"] is None


def test_multiple_continue_controls_refused():
    with pytest.raises(NavigationRefusal):
        locate_continue(BANNER, TSV_HEAD + CONTINUE + CONTINUE, 1280, 800)
