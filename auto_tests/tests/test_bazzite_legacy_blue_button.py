"""Safe shape and OCR rejection cases for Bazzite legacy blue Continue button."""

import io
import sys
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_legacy_blue_button import ButtonRefusal, locate_continue  # noqa: E402

BANNER = "BAZZITE 42 INSTALLATION\nWELCOME TO BAZZITE 42.\n"


def synthetic_screenshot(*, fill=(35, 121, 226), offset=0):
    image = Image.new("RGB", (1280, 800), (245, 244, 243))
    draw = ImageDraw.Draw(image)
    draw.rectangle((1177 + offset, 754, 1273 + offset, 786), fill=fill)
    draw.text((1190 + offset, 765), "Continue", fill="white")
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


def test_known_blue_button_is_coordinate_only_not_install_authority():
    result = locate_continue(synthetic_screenshot(), BANNER, ocr_engine=lambda _bytes: "Continue")
    assert result["blueContinueTextVerified"] is True
    assert result["blueContinueGeometryVerified"] is True
    assert result["coordinate"] == {"x": 1225, "y": 770}
    for key in (
        "actualAnacondaBinaryVerified",
        "blivetGuiVerified",
        "isoProvenanceSignatureVerified",
        "installationAuthorized",
        "partitionWriteAuthorized",
        "windowsEspWriteAuthorized",
        "secureBootEnrollmentAuthorized",
    ):
        assert result[key] is False


@pytest.mark.parametrize(
    "image,ocr",
    [
        (b"not-an-image", BANNER),
        (synthetic_screenshot(fill=(255, 0, 0)), BANNER),
        (synthetic_screenshot(offset=-40), BANNER),
        (synthetic_screenshot(), "Bazzite 45 installation"),
    ],
)
def test_unknown_screen_and_geometry_refused(image, ocr):
    with pytest.raises(ButtonRefusal):
        locate_continue(image, ocr, ocr_engine=lambda _bytes: "Continue")


@pytest.mark.parametrize("label", ["", "Quit", "Continu", "Continue Quit"])
def test_other_buttons_refused(label):
    with pytest.raises(ButtonRefusal, match="not Continue"):
        locate_continue(synthetic_screenshot(), BANNER, ocr_engine=lambda _bytes: label)


def test_bounded_input_refuses_oversized_png():
    with pytest.raises(ButtonRefusal):
        locate_continue(b"a" * (5 * 1024 * 1024 + 1), BANNER)
