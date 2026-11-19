"""Fail-closed Blivet-GUI launch and observation contracts."""

import sys
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_blivet_gui_observer import (  # noqa: E402, I001
    BlivetObserverRefusal,
    locate_launch_control,
    verify_advanced_custom_selected,
)


HEADER = "level\tconf\tleft\ttop\twidth\theight\ttext\n"


def tsv(words):
    return HEADER + "".join(f"5\t96\t{x}\t{y}\t{w}\t{h}\t{word}\n" for word, x, y, w, h in words)


def evidence(tmp_path, text, words, name="screen"):
    png = tmp_path / f"{name}.png"
    Image.new("RGB", (1280, 800)).save(png)
    ocr = tmp_path / f"{name}.ocr"
    ocr.write_text(text, encoding="utf-8")
    data = tmp_path / f"{name}.tsv"
    data.write_text(tsv(words), encoding="utf-8")
    return png, ocr, data


BASE = "BAZZITE 42 INSTALLATION INSTALLATION DESTINATION ADVANCED CUSTOM BLIVET-GUI"


def test_unique_advanced_custom_control_is_only_a_launch_coordinate(tmp_path):
    paths = evidence(
        tmp_path,
        BASE,
        [
            ("Advanced", 300, 400, 65, 18),
            ("Custom", 370, 400, 55, 18),
            ("(Blivet-GUI)", 430, 400, 105, 18),
        ],
    )
    result = locate_launch_control(*paths)
    assert result["coordinate"] == {"x": 417, "y": 409}
    assert result["onlyBlivetGuiLaunchClickPermitted"] is True
    assert result["partitionControlClicked"] is False
    assert result["partitionWriteAuthorized"] is False


def test_ambiguous_control_refused(tmp_path):
    paths = evidence(
        tmp_path,
        BASE,
        [
            ("Advanced", 300, 400, 65, 18),
            ("Custom", 370, 400, 55, 18),
            ("(Blivet-GUI)", 430, 400, 105, 18),
            ("Advanced", 300, 500, 65, 18),
            ("Custom", 370, 500, 55, 18),
            ("(Blivet-GUI)", 430, 500, 105, 18),
        ],
    )
    with pytest.raises(BlivetObserverRefusal):
        locate_launch_control(*paths)


def test_missing_blivet_marker_refused(tmp_path):
    paths = evidence(
        tmp_path,
        BASE.replace("BLIVET-GUI", "OTHER"),
        [
            ("Advanced", 300, 400, 65, 18),
            ("Custom", 370, 400, 55, 18),
            ("(Other)", 430, 400, 105, 18),
        ],
    )
    with pytest.raises(BlivetObserverRefusal):
        locate_launch_control(*paths)


def test_advanced_custom_radio_selected_but_editor_not_claimed(tmp_path):
    text = "INSTALLATION DESTINATION BAZZITE 42 INSTALLATION ADVANCED CUSTOM (BLIVET-GUI)"
    png, ocr, data = evidence(tmp_path, text, [("Advanced", 460, 475, 57, 12)])
    image = Image.open(png).convert("RGB")
    for x in range(438, 459):
        for y in range(470, 491):
            image.putpixel((x, y), (63, 137, 228))
    image.save(png)
    result = verify_advanced_custom_selected(png, ocr, data)
    assert result["phase"] == "advanced-custom-selected"
    assert result["advancedCustomRadioSelected"] is True
    assert result["blivetGuiLaunched"] is False
    assert result["partitionEditorContextObserved"] is False
    assert result["partitionMutationAttempted"] is False
    assert result["installationAuthorized"] is False


@pytest.mark.parametrize("selected_region", ["custom", "automatic", "none"])
def test_wrong_or_missing_radio_selection_refused(tmp_path, selected_region):
    text = "INSTALLATION DESTINATION BAZZITE 42 INSTALLATION ADVANCED CUSTOM (BLIVET-GUI)"
    png, ocr, data = evidence(tmp_path, text, [("Advanced", 460, 475, 57, 12)])
    image = Image.open(png).convert("RGB")
    if selected_region != "none":
        x0 = 229 if selected_region == "custom" else 20
        for x in range(x0, x0 + 21):
            for y in range(470, 491):
                image.putpixel((x, y), (63, 137, 228))
    image.save(png)
    with pytest.raises(BlivetObserverRefusal):
        verify_advanced_custom_selected(png, ocr, data)
