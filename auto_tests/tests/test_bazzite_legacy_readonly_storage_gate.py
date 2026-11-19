"""Native legacy Bazzite storage UI: read-only GPT lab observation contracts."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_legacy_readonly_storage_gate import (  # noqa: E402
    StorageRefusal,
    locate_destination,
    observe_destination,
)

SUMMARY = (
    "INSTALLATION SUMMARY\nBAZZITE 42 INSTALLATION\n"
    "Installation Destination\nNo disks selected\nBegin Installation"
)
HEADER = "level\tconf\tleft\ttop\twidth\theight\ttext\n"
WORDS = "5\t96\t674\t322\t81\t12\tInstallation\n5\t92\t759\t322\t83\t12\tDestination\n"
STORAGE = (
    "INSTALLATION DESTINATION BAZZITE 42 INSTALLATION\n"
    "Device Selection\nLocal Standard Disks\nStorage Configuration\n"
    "Automatic Custom Advanced Custom (Blivet-GUI)\n"
    "0 disks selected; 0 B capacity"
)


def test_summary_tile_is_just_a_coordinate():
    result = locate_destination(SUMMARY, HEADER + WORDS, 1280, 800)
    assert result["coordinate"] == {"x": 758, "y": 328}
    assert result["targetUniquelyObserved"] is True
    assert result["installationAuthorized"] is False
    assert result["windowsEspWriteAuthorized"] is False


@pytest.mark.parametrize(
    "ocr",
    [
        SUMMARY.replace("BAZZITE 42", "BAZZITE 45"),
        SUMMARY.replace("Installation Destination", "Install Drive"),
        SUMMARY.replace("INSTALLATION SUMMARY", "OTHER SCREEN"),
        SUMMARY.replace("Begin Installation", "Begin Now"),
    ],
)
def test_refuse_incorrect_legacy_summary(ocr):
    with pytest.raises(StorageRefusal):
        locate_destination(ocr, HEADER + WORDS, 1280, 800)


@pytest.mark.parametrize(
    "words",
    [
        "",
        WORDS + WORDS,
        WORDS.replace("674\t322", "900\t322"),
        WORDS.replace("759\t322", "1000\t322"),
    ],
)
def test_refuse_ambiguous_or_shifted_controls(words):
    with pytest.raises(StorageRefusal):
        locate_destination(SUMMARY, HEADER + words, 1280, 800)


def test_refuse_unexpected_geometry():
    with pytest.raises(StorageRefusal):
        locate_destination(SUMMARY, HEADER + WORDS, 1024, 768)


def test_native_storage_page_is_not_install_proof():
    result = observe_destination(STORAGE)
    assert result["nativeStoragePageObserved"] is True
    assert result["advancedCustomBlivetOptionTextObserved"] is True
    assert result["zeroDisksTextObserved"] is True
    assert result["blivetGuiExecutableVerified"] is False
    assert result["guestDiskReadOnlyFlagVerified"] is False
    assert result["diskPartitioningAttempted"] is False
    assert result["installationAuthorized"] is False
    assert result["beginInstallationActivated"] is False


def test_visible_disk_does_not_authorize_install():
    result = observe_destination(
        STORAGE.replace("0 disks selected; 0 B capacity", "1 disk selected; 64 GiB capacity")
    )
    assert result["nativeStoragePageObserved"] is True
    assert result["zeroDisksTextObserved"] is False
    assert result["installationAuthorized"] is False
    assert result["partitionWriteAuthorized"] is False


@pytest.mark.parametrize(
    "page",
    [
        STORAGE.replace("BAZZITE 42", "BAZZITE 45"),
        STORAGE.replace("Storage Configuration", "UNKNOWN OPTIONS"),
        STORAGE.replace("Device Selection", "UNKNOWN DEVICE"),
    ],
)
def test_unknown_page_refused(page):
    with pytest.raises(StorageRefusal):
        observe_destination(page)
