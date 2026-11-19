"""Check historical and newer Bazzite gates without granting disk writes."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_legacy_gpt_storage_navigation import (  # noqa: E402
    StorageNavigationRefusal,
    locate_storage_tile,
)
from bazzite_legacy_readonly_storage_gate import (  # noqa: E402
    StorageRefusal,
    locate_destination,
    observe_destination,
)

SUMMARY = (
    "INSTALLATION SUMMARY\nBAZZITE 42 INSTALLATION\n"
    "Installation Destination\nBegin Installation\n"
    "Automatic partitioning selected\nNo network devices available"
)
HEADER = "level\tconf\tleft\ttop\twidth\theight\ttext\n"
WORDS = "5\t96\t674\t322\t81\t12\tInstallation\n5\t92\t759\t322\t83\t12\tDestination\n"
TSV = HEADER + WORDS


def test_legacy_and_gpt_tile_coordinates_agree_without_write_permission():
    old = locate_destination(SUMMARY, TSV, 1280, 800)
    new = locate_storage_tile(SUMMARY, TSV, 1280, 800)
    assert old["coordinate"] == new["coordinate"] == {"x": 758, "y": 328}
    for result in (old, new):
        assert result["installationAuthorized"] is False
        assert result["partitionWriteAuthorized"] is False
        assert result["windowsEspWriteAuthorized"] is False
    assert new["isoProvenanceSignatureVerified"] is False
    assert new["diskIdentityIndependentlyVerified"] is False


@pytest.mark.parametrize("width,height", [(True, 800), (1280, True), (1024, 768)])
def test_both_gates_refuse_bad_frame_geometry(width, height):
    with pytest.raises(StorageRefusal):
        locate_destination(SUMMARY, TSV, width, height)
    with pytest.raises(StorageNavigationRefusal):
        locate_storage_tile(SUMMARY, TSV, width, height)


def test_visible_blivet_text_is_not_binary_or_disk_identity_proof():
    storage = (
        "INSTALLATION DESTINATION BAZZITE 42 INSTALLATION\n"
        "Device Selection\nStorage Configuration\n"
        "Automatic Custom Advanced Custom (Blivet-GUI)\n"
        "1 disk selected; 64 GiB capacity"
    )
    report = observe_destination(storage)
    assert report["advancedCustomBlivetOptionTextObserved"] is True
    assert report["blivetGuiExecutableVerified"] is False
    assert report["guestDiskReadOnlyFlagVerified"] is False
    assert report["installationAuthorized"] is False
    assert report["partitionWriteAuthorized"] is False
    assert report["windowsEspWriteAuthorized"] is False
