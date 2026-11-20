"""Fail-closed adapter contract tests; Safety dependency remains external to #266."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_q4os_safety_adapter import refuse_calamares, to_safety_snapshot  # noqa: E402


def sample():
    guid = "12345678-1234-1234-1234-123456789abc"
    q4os = {
        "layout": "uefi/gpt", "diskGuid": guid, "diskSizeBytes": 67108864,
        "logicalSectorBytes": 512, "observedStateSha256": "a" * 64,
        "partitions": [
            {"index": 1, "type": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
             "guid": "87654321-4321-4321-4321-cba987654321", "first": 2048,
             "last": 4095, "attributes": 0},
        ],
    }
    snapshot = to_safety_snapshot(q4os)
    plan = {
        "backend": "q4os-native", "firmwareLayout": "uefi/gpt",
        "diskGuid": guid, "observedStateSha256": "a" * 64, "transactionId": "lab-1",
        "proposedRootStartLba": 8192, "proposedRootEndLba": 16383,
        "windowsEspFallbackWriteBlocked": True, "efiDebianHookWriteBlocked": True,
        "installationAuthorized": False, "calamaresJobsAuthorized": False,
        "diskWritesAuthorized": False, "windowsEspWritesAuthorized": False,
        "rollbackVerified": False,
    }
    tx = {"id": "lab-1", "diskGuid": guid, "observedStateSha256": "a" * 64}
    writes = [{
        "operation": "create-root-ext4",
        "partGuid": "11111111-2222-3333-4444-555555555555",
        "ownerTransactionId": "lab-1", "startBytes": 8192 * 512,
        "sizeBytes": (16383 - 8192 + 1) * 512,
    }]
    calamares = {
        "nativeCalamaresConfigVerified": True,
        "upstreamInstallsEfiFallback": True,
        "fallbackWritePreventedAndVerified": False,
    }
    def comparator(expected, observed):
        if expected != observed:
            raise ValueError("identity or geometry changed")
    return dict(q4os=q4os, expected=snapshot, safety_observed=snapshot,
                safety_compare=comparator, plan=plan, transaction=tx,
                write_set=writes, calamares=calamares)


def test_projection_preserves_safety_contract_geometry():
    case = sample()
    part = to_safety_snapshot(case["q4os"])["partitions"][0]
    assert part["offsetBytes"] == 2048 * 512
    assert part["sizeBytes"] == 2048 * 512
    assert part["partGuid"] == case["q4os"]["partitions"][0]["guid"]


def test_verified_mock_still_refuses_fallback():
    result = refuse_calamares(**sample())
    assert result["decision"] == "refuse"
    assert result["diskWritesAuthorized"] is False
    assert result["writerPresent"] is False
    assert any("fallback" in r for r in result["reasons"])


@pytest.mark.parametrize("change", [
    lambda x: x.update(safety_compare=None),
    lambda x: x.update(expected=None),
    lambda x: x["safety_observed"].update(partitionTableId="gpt:foreign"),
    lambda x: x["plan"].update(diskWritesAuthorized=True),
    lambda x: x["transaction"].update(id="foreign"),
    lambda x: x["write_set"][0].update(partGuid=x["q4os"]["partitions"][0]["guid"]),
    lambda x: x["write_set"][0].update(operation="write-esp-fallback"),
    lambda x: x["write_set"][0].update(startBytes=0),
    lambda x: x["calamares"].update(nativeCalamaresConfigVerified=False),
    lambda x: x.update(write_set=[]),
])
def test_adversarial_mismatch_always_refuses(change):
    case = sample()
    change(case)
    result = refuse_calamares(**case)
    assert result["decision"] == "refuse"
    assert result["diskWritesAuthorized"] is False
    assert result["installationAuthorized"] is False
    assert result["reasons"][0].startswith("fail-closed:")


def test_even_claimed_fallback_suppression_cannot_authorize():
    case = sample()
    case["calamares"]["fallbackWritePreventedAndVerified"] = True
    result = refuse_calamares(**case)
    assert result["decision"] == "refuse"
    assert result["calamaresJobsAuthorized"] is False
    assert any("not authenticated" in r for r in result["reasons"])


def test_mbr_not_accepted_as_valid_safety_snapshot():
    case = sample()
    case["q4os"]["layout"] = "bios/mbr"
    assert refuse_calamares(**case)["decision"] == "refuse"
    with pytest.raises(ValueError):
        to_safety_snapshot(case["q4os"])
