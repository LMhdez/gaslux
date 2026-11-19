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
    verify_editor,
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


def test_editor_identity_and_device_context_observed(tmp_path):
    text = "BLAZING BLIVET PARTITION EDITOR DEVICE VDA"
    paths = evidence(
        tmp_path,
        text,
        [("Blivet", 20, 20, 50, 15), ("Partition", 80, 20, 65, 15)],
    )
    result = verify_editor(*paths)
    assert result["blivetGuiIdentityTextObserved"] is True
    assert result["partitionEditorContextObserved"] is True
    assert result["partitionMutationAttempted"] is False
    assert result["installationAuthorized"] is False


@pytest.mark.parametrize("text", ["BLIVET PARTITION", "DEVICE VDA", "BLIVET DEVICE VDA"])
def test_unverified_editor_refused(tmp_path, text):
    paths = evidence(tmp_path, text, [("Device", 20, 20, 50, 15)])
    with pytest.raises(BlivetObserverRefusal):
        verify_editor(*paths)
