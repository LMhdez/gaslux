"""Negative contracts for selecting the legacy diskless storage destination tile."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_legacy_destination_gate import DestinationRefusal, locate_destination  # noqa: E402

OCR = (
    "INSTALLATION SUMMARY,\n"
    "BAZZITE 42 INSTALLATION\n"
    "Installation Destination\n"
    "No disks selected\n"
    "No network devices available\n"
    "Begin Installation\n"
)
HEADER = "level\tconf\tleft\ttop\twidth\theight\ttext\n"
TILE = (
    "5\t96\t674\t322\t81\t12\tInstallation\n"
    "5\t92\t759\t322\t83\t12\tDestination\n"
)


def probe(ocr=OCR, tsv=HEADER + TILE, width=1280, height=800):
    return locate_destination(ocr, tsv, width, height)


def test_unique_diskless_destination_is_only_a_coordinate():
    result = probe()
    assert result["coordinate"] == {"x": 758, "y": 328}
    assert result["noDisksSelectedTextVerified"] is True
    assert result["destinationTargetUniquelyObserved"] is True
    for key in (
        "installerBinaryIdentityVerified",
        "blivetGuiVerified",
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
        OCR.replace("No disks selected", "One disk selected"),
        OCR.replace("No network devices available", ""),
        OCR.replace("Begin Installation", ""),
        OCR.replace("INSTALLATION SUMMARY,", ""),
        OCR.replace("Installation Destination", "Installation Storage"),
    ],
)
def test_missing_identity_or_diskless_markers_refuses(ocr):
    with pytest.raises(DestinationRefusal, match="Missing diskless"):
        probe(ocr=ocr)


@pytest.mark.parametrize(
    "tsv",
    [
        HEADER,
        HEADER + TILE + TILE,
        HEADER + TILE.replace("674\t322", "1074\t322"),
        HEADER + TILE.replace("759\t322", "900\t322"),
        HEADER + TILE.replace("5\t92\t759", "5\t40\t759"),
    ],
)
def test_bad_target_geometry_refused(tsv):
    with pytest.raises(DestinationRefusal):
        probe(tsv=tsv)


def test_wrong_screen_size_refused():
    with pytest.raises(DestinationRefusal):
        probe(width=1024, height=768)


def test_bash_safe_cli_with_valid_temporary_png(tmp_path):
    from PIL import Image

    im = Image.new("RGB", (1280, 800), "white")
    picture = tmp_path / "summary.png"
    ocr = tmp_path / "summary.ocr"
    tsv = tmp_path / "summary.tsv"
    coords = tmp_path / "coordinates.txt"
    im.save(picture)
    ocr.write_text(OCR, encoding="utf-8")
    tsv.write_text(HEADER + TILE, encoding="utf-8")
    p = subprocess.run(
        [
            sys.executable,
            str(ROOT / "auto_tests/bazzite_legacy_destination_gate.py"),
            "--png",
            str(picture),
            "--ocr",
            str(ocr),
            "--tsv",
            str(tsv),
            "--coords",
            str(coords),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert p.returncode == 0, p.stderr
    assert coords.read_text(encoding="ascii") == "758 328\n"
