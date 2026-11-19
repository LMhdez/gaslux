"""Fail-closed contracts for the Bazzite Custom radio selection gate."""
import csv
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
import pytest  # noqa: E402
from bazzite_custom_radio_gate import (  # noqa: E402
    CustomSelectionRefusal,
    inspect_custom_before,
    verify_custom_after,
)

OCR = """BAZZITE 42 INSTALLATION
INSTALLATION DESTINATION
70 GiB vda / 61.5 GiB free
Storage Configuration
Automatic Custom Advanced Custom (Blivet-GUI)
"""
HEADER = ["level", "page_num", "block_num", "par_num", "line_num", "word_num",
          "left", "top", "width", "height", "conf", "text"]
ROWS = [
    ["5", "1", "1", "1", "1", "1", "42", "475", "61", "10", "96.0", "Automatic"],
    ["5", "1", "2", "1", "1", "1", "252", "475", "45", "10", "96.0", "Custom"],
    ["5", "1", "3", "1", "1", "1", "522", "475", "45", "10", "96.0", "Custom"],
]


def fixture(tmp_path, *, custom_selected=False, automatic_selected=True):
    png = tmp_path / "screen.png"
    ocr = tmp_path / "screen.ocr"
    tsv = tmp_path / "screen.tsv"
    image = Image.new("RGB", (1280, 800), "white")
    draw = ImageDraw.Draw(image)
    # Radio rings with the same blue family used by the captured GTK screen.
    for cx, selected in ((29, automatic_selected), (239, custom_selected)):
        draw.ellipse((cx - 5, 475, cx + 5, 485), outline=(73, 145, 231), width=2)
        if selected:
            draw.ellipse((cx - 2, 478, cx + 2, 482), fill=(55, 134, 228))
    image.save(png)
    ocr.write_text(OCR, encoding="utf-8")
    with tsv.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\\t")
        writer.writerow(HEADER)
        writer.writerows(ROWS)
    return png, ocr, tsv


def test_before_gate_returns_only_custom_radio_coordinate(tmp_path):
    png, ocr, tsv = fixture(tmp_path)
    result = inspect_custom_before(png, ocr, tsv)
    assert result["coordinate"] == {"x": 239, "y": 480}
    assert result["onlyCustomRadioClickPermitted"] is True
    assert result["installationAuthorized"] is False
    assert result["partitionWriteAuthorized"] is False


def test_after_gate_requires_custom_selected_and_automatic_unselected(tmp_path):
    png, ocr, tsv = fixture(tmp_path, custom_selected=True, automatic_selected=False)
    result = verify_custom_after(png, ocr, tsv)
    assert result["customSelectedObserved"] is True
    assert result["automaticUnselectedObserved"] is True
    assert result["beginInstallationButtonClicked"] is False


def test_refuses_if_custom_was_already_selected_before_click(tmp_path):
    png, ocr, tsv = fixture(tmp_path, custom_selected=True, automatic_selected=False)
    with pytest.raises(CustomSelectionRefusal, match="Expected Automatic"):
        inspect_custom_before(png, ocr, tsv)


def test_refuses_if_custom_selection_not_confirmed_after_click(tmp_path):
    png, ocr, tsv = fixture(tmp_path)
    with pytest.raises(CustomSelectionRefusal, match="not visually confirmed"):
        verify_custom_after(png, ocr, tsv)


def test_refuses_ambiguous_custom_label(tmp_path):
    png, ocr, tsv = fixture(tmp_path)
    with tsv.open("a", encoding="utf-8") as stream:
        stream.write("\\t".join(ROWS[1]) + "\\n")
    with pytest.raises(CustomSelectionRefusal, match="not unique"):
        inspect_custom_before(png, ocr, tsv)


def test_refuses_wrong_ui_version(tmp_path):
    png, ocr, tsv = fixture(tmp_path)
    ocr.write_text(OCR.replace("BAZZITE 42", "BAZZITE 43"), encoding="utf-8")
    with pytest.raises(CustomSelectionRefusal, match="Missing storage UI marker"):
        inspect_custom_before(png, ocr, tsv)
