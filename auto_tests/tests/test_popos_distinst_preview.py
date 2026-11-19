"""Pop native preflight must never format the shared Windows ESP."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
from gaslux_popos_distinst_preview import (  # noqa: E402
    TARGET,
    PopDistinstPlanRefusal,
    preview_native_distinst,
)


@pytest.fixture
def candidate():
    return {
        "runId": "lab-pop-verified-20261116",
        "operation": "preview-only",
        "guestOnly": True,
        "firmwareLayout": "uefi/gpt",
        "targetDiskPath": TARGET,
        "rootPartitionNumber": 3,
        "espPartitionNumber": 1,
        "rootTransactionOwned": True,
        "windowsEspPreserved": True,
        "secureBoot": "disabled",
        "isoSha256": "a" * 64,
        "distinstSha256": "b" * 64,
        "windowsBootProofSha256": "c" * 64,
    }


def test_uefi_gpt_reuses_esp_without_formatting(candidate):
    outcome = preview_native_distinst(candidate)
    argv = outcome["args"]
    assert outcome["installationAuthorized"] is False
    assert outcome["requiresIndependentDiskProof"] is True
    assert outcome["requiresVmWriteIsolation"] is True
    assert outcome["requiresFirstBootAndWindowsRecovery"] is True
    assert outcome["bootloader"] == "systemd-boot"
    assert f"{TARGET}:1:reuse:mount=/boot/efi" in argv
    assert f"{TARGET}:3:ext4:mount=/" in argv
    assert not any(":fat32:mount=/boot/efi" in token for token in argv)
    for forbidden in ("--new-table", "--new", "--delete", "--move", "--modify-boot"):
        assert forbidden not in argv
    assert "--no-efi-vars" in argv


@pytest.mark.parametrize(
    "mutations",
    [
        {"guestOnly": False},
        {"operation": "install"},
        {"firmwareLayout": "bios/mbr"},
        {"targetDiskPath": "/dev/sda"},
        {"targetDiskPath": "/dev/disk/by-id/virtio-UNKNOWN"},
        {"rootPartitionNumber": 1},
        {"rootPartitionNumber": 1.0},
        {"rootPartitionNumber": 0},
        {"rootPartitionNumber": 129},
        {"espPartitionNumber": 3},
        {"espPartitionNumber": True},
        {"rootTransactionOwned": False},
        {"windowsEspPreserved": False},
        {"secureBoot": "enabled"},
        {"secureBoot": "unknown"},
        {"isoSha256": "0" * 63},
        {"distinstSha256": "0" * 63},
        {"windowsBootProofSha256": "0" * 63},
        {"runId": "guest"},
        {"runId": ""},
    ],
)
def test_unsafe_target_contracts_refused(candidate, mutations):
    candidate.update(mutations)
    with pytest.raises(PopDistinstPlanRefusal):
        preview_native_distinst(candidate)


def test_extra_or_missing_fields_refused(candidate):
    candidate["unsupported"] = True
    with pytest.raises(PopDistinstPlanRefusal):
        preview_native_distinst(candidate)
    del candidate["unsupported"]
    del candidate["windowsBootProofSha256"]
    with pytest.raises(PopDistinstPlanRefusal):
        preview_native_distinst(candidate)


def test_no_process_or_disk_writers_in_preview_module():
    path = ROOT / "auto_tests/tools/gaslux_popos_distinst_preview.py"
    source = path.read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "os.exec" not in source
    assert "partition.format_with(" in source  # explicit upstream semantic warning
