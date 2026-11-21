"""Contract regression against separately pinned Safety #265/#267 source; no writer."""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))
from gaslux_q4os_safety_adapter import refuse_calamares, to_safety_snapshot  # noqa: E402


def _safety():
    source = os.environ.get("GASLUX_Q4OS_PINNED_SAFETY_SOURCE_DIR")
    if not source or not Path(source).is_dir():
        pytest.fail("Pinned real Safety #265/#267 source is required")
    sys.path.insert(0, source)
    from libertix_disk_identity_gate import assert_snapshot_matches
    from libertix_prewrite_no_writer import (
        PrewriteDenied,
        authenticated_record,
        canonical,
        decide_no_writer,
    )

    return (
        assert_snapshot_matches,
        PrewriteDenied,
        authenticated_record,
        canonical,
        decide_no_writer,
    )


def _fixture():
    disk_guid = "12345678-1234-1234-1234-123456789abc"
    esp_guid = "87654321-4321-4321-4321-cba987654321"
    q4os = {
        "layout": "uefi/gpt",
        "diskGuid": disk_guid,
        "diskSizeBytes": 64 * 1024 * 1024,
        "logicalSectorBytes": 512,
        "observedStateSha256": "c" * 64,
        "partitions": [
            {
                "index": 1,
                "type": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                "guid": esp_guid,
                "first": 2048,
                "last": 4095,
                "attributes": 0,
            }
        ],
    }
    snapshot = to_safety_snapshot(q4os)
    transaction_id = "a" * 32
    vm_id = "q4os-pinned-safety-vm-lab-only"
    safety_plan = {
        "planId": transaction_id,
        "firmware": "uefi",
        "disk": {
            key: snapshot[key]
            for key in ("partitionStyle", "partitionTableId", "sizeBytes", "logicalSectorSizeBytes")
        },
    }
    start, size = 16 * 1024 * 1024, 4 * 1024 * 1024
    plan = {
        "backend": "q4os-native",
        "firmwareLayout": "uefi/gpt",
        "diskGuid": disk_guid,
        "observedStateSha256": "c" * 64,
        "transactionId": transaction_id,
        "proposedRootStartLba": start // 512,
        "proposedRootEndLba": (start + size) // 512 - 1,
        "installationAuthorized": False,
        "calamaresJobsAuthorized": False,
        "diskWritesAuthorized": False,
        "windowsEspWritesAuthorized": False,
        "rollbackVerified": False,
        "windowsEspFallbackWriteBlocked": True,
        "efiDebianHookWriteBlocked": True,
    }
    case = {
        "q4os": q4os,
        "expected": snapshot,
        "safety_observed": snapshot,
        "plan": plan,
        "transaction": {
            "id": transaction_id,
            "diskGuid": disk_guid,
            "observedStateSha256": "c" * 64,
        },
        "write_set": [
            {
                "operation": "create-root-ext4",
                "partGuid": "11111111-2222-3333-4444-555555555555",
                "ownerTransactionId": transaction_id,
                "startBytes": start,
                "sizeBytes": size,
            }
        ],
        "calamares": {
            "nativeCalamaresConfigVerified": True,
            "upstreamInstallsEfiFallback": True,
            "fallbackWritePreventedAndVerified": False,
        },
    }
    return case, safety_plan, transaction_id, vm_id, start, size


def _run_safety(*, corrupt_mac=False):
    compare, denied, authenticated, canonical, decide = _safety()
    case, safety_plan, txid, vm_id, start, size = _fixture()
    plan_bytes = canonical(safety_plan)
    plan_sha = hashlib.sha256(plan_bytes).hexdigest()
    nonce = secrets.token_hex(32)
    host_key, guest_key = secrets.token_bytes(32), secrets.token_bytes(32)

    def record(source, key):
        return authenticated(
            {
                "source": source,
                "transactionId": txid,
                "planSha256": plan_sha,
                "vmId": vm_id,
                "nonce": nonce,
                "snapshot": case["expected"],
            },
            key,
        )

    host = record("host", host_key)
    if corrupt_mac:
        host["mac"] = "0" * 64
    report = decide(
        plan=safety_plan,
        plan_bytes=plan_bytes,
        transaction_id=txid,
        vm_id=vm_id,
        host_evidence=host,
        guest_evidence=record("guest", guest_key),
        immediate_evidence=record("guest-immediate", guest_key),
        host_key=host_key,
        guest_key=guest_key,
        fresh_nonce=nonce,
        owned_regions=[
            {
                "offsetBytes": start,
                "sizeBytes": size,
                "ownerTransactionId": txid,
            }
        ],
        write_set=[{"offsetBytes": start, "sizeBytes": size, "operation": "allocate-free-space"}],
    )
    case["transaction"]["safetyPlanSha256"] = plan_sha
    case["transaction"]["vmId"] = vm_id
    case["safety_compare"] = compare
    case["safety_attestation"] = report
    return case, denied


def test_actual_safety_no_writer_does_not_authorize_calamares():
    case, _ = _run_safety()
    assert case["safety_attestation"]["decision"] == "ACCEPT_NO_WRITER"
    decision = refuse_calamares(**case)
    assert decision["decision"] == "refuse"
    assert decision["writerPresent"] is False
    assert decision["installationAuthorized"] is False
    assert any("ACCEPT_NO_WRITER never authorizes" in r for r in decision["reasons"])


def test_actual_safety_rejects_forged_mac():
    with pytest.raises(ValueError, match="evidence MAC mismatch"):
        _run_safety(corrupt_mac=True)


def test_actual_safety_detects_q4os_geometry_drift():
    case, _ = _run_safety()
    case["q4os"]["partitions"][0]["last"] += 1
    decision = refuse_calamares(**case)
    assert decision["decision"] == "refuse"
    assert any("geometry changed" in r for r in decision["reasons"])


def test_actual_safety_transaction_or_vm_drift_refused():
    case, _ = _run_safety()
    case["transaction"]["vmId"] = "different-guest"
    decision = refuse_calamares(**case)
    assert decision["diskWritesAuthorized"] is False
    assert any("Safety no-writer transaction" in r for r in decision["reasons"])
