"""Adversarial origin-contract tests; all provenance and byte hashes are FIXTURES.

No device, QEMU, Windows or observer producer is contacted by these tests.
The Ed25519 protocol is exercised only via the unchanged Observer verifier.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import runpy
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
from libertix_disk_identity_gate import DiskIdentityError  # noqa: E402
from libertix_gpt_provenance import (  # noqa: E402
    ProvenanceAuthority,
    ProvenanceRefused,
    assess_gpt_provenance_v1,
    require_externally_attested_measurement,
)
from libertix_safety_observer_adapter import (  # noqa: E402
    consume_observer_state_no_writer,
)

TEST_HELP = runpy.run_path(str(ROOT / "auto_tests/tests/test_safety_observer_adapter.py"))
example = TEST_HELP["example"]
fresh_signed_case = TEST_HELP["fresh_signed_case"]


def diagnostic_fixture():
    args, _, _ = example()
    verified = consume_observer_state_no_writer(**args)
    pins = args["pins"]
    now = args["now"]
    authority = ProvenanceAuthority(
        issuer_id="synthetic-lab-controller",
        observer_id="synthetic-observer-01",
        collector_id=pins.collector_id,
        controller_id=pins.controller_id,
        policy_id="synthetic-lab-only",
        policy_sha256="b" * 64,
        signing_key_id=pins.observer_key_id,
        administrative_domain="same-gh-runner",
        qemu_executable_sha256="d" * 64,
        device_id="virtio-pci:0000:00:05.0",
        overlay_path="/test/controlled/overlay.qcow2",
        overlay_device_id="tmpfs:42",
        overlay_inode=1002,
        parent_device_id="tmpfs:42",
        parent_inode=1001,
    )
    sector_claims = {
        "primaryHeaderLba": 1,
        "backupHeaderLba":
            pins.virtual_size_bytes // args["host_gpt"]["logicalSectorSizeBytes"] - 1,
        "primaryHeaderCrc32": 12345678,
        "backupHeaderCrc32": 87654321,
        "primaryArrayCrc32": 55443322,
        "backupArrayCrc32": 55443322,
        "primaryHeaderSha256": "1" * 64,
        "backupHeaderSha256": "2" * 64,
        "primaryArraySha256": "3" * 64,
        "backupArraySha256": "4" * 64,
    }
    measurements = []
    for index, (source, method) in enumerate((
        ("host", "host-readonly-pread"),
        ("guest", "guest-virtio-readonly-sector"),
        ("immediate", "immediate-readonly-pread"),
    )):
        measurements.append({
            "source": source, "assurance": "SIGNED", "readMethod": method,
            "observerId": authority.observer_id,
            "collectorId": authority.collector_id,
            "observedAt": (now - timedelta(seconds=3-index)).isoformat(),
            "qemuPid": pins.qemu_pid, "qemuStartTicks": pins.qemu_start_ticks,
            "deviceId": authority.device_id, "virtualSerial": pins.virtual_serial,
            "gpt": deepcopy(args[source + "_gpt"]),
            "gptSectors": deepcopy(sector_claims),
            "originProof": {"kind": "none", "evidenceSha256": None,
                            "issuerId": authority.issuer_id},
        })
    statement = {
        "contractVersion": 1, "kind": "safety-gpt-provenance",
        "classification": "NOT_INDEPENDENT",
        "purpose": "read-only-diagnostic", "writeAuthorized": False,
        "transactionId": pins.transaction_id, "vmUuid": pins.vm_uuid,
        "requestId": pins.request_id, "nonce": pins.nonce,
        "sequence": pins.sequence,
        "observerResultSha256": verified["observer_result_sha256"],
        "issuer": {
            "issuerId": authority.issuer_id, "observerId": authority.observer_id,
            "collectorId": authority.collector_id, "controllerId": authority.controller_id,
            "policyId": authority.policy_id, "policySha256": authority.policy_sha256,
            "signingKeyId": authority.signing_key_id,
            "administrativeDomain": authority.administrative_domain,
        },
        "qemu": {
            "pid": pins.qemu_pid, "startTicks": pins.qemu_start_ticks,
            "executableSha256": authority.qemu_executable_sha256,
            "deviceId": authority.device_id, "virtualSerial": pins.virtual_serial,
            "virtualSizeBytes": pins.virtual_size_bytes,
            "logicalSectorSizeBytes": args["host_gpt"]["logicalSectorSizeBytes"],
        },
        "backingChain": [
            {
                "role": "overlay", "path": authority.overlay_path,
                "format": "qcow2", "sha256": pins.overlay_sha256,
                "virtualSizeBytes": pins.virtual_size_bytes,
                "backingFilename": pins.backing_filename, "backingFormat": "raw",
                "deviceId": authority.overlay_device_id, "inode": authority.overlay_inode,
            },
            {
                "role": "parent", "path": pins.backing_filename,
                "format": "raw", "sha256": pins.backing_sha256,
                "virtualSizeBytes": pins.virtual_size_bytes,
                "backingFilename": None, "backingFormat": None,
                "deviceId": authority.parent_device_id, "inode": authority.parent_inode,
            },
        ],
        "measurements": measurements,
    }
    params = {
        "statement": statement, "pins": pins, "authority": authority,
        "expected_observer_result_sha256": verified["observer_result_sha256"],
        "host_gpt": args["host_gpt"], "guest_gpt": args["guest_gpt"],
        "immediate_gpt": args["immediate_gpt"], "now": now,
    }
    return params


def test_signed_claims_are_diagnostic_and_not_a_measurement_receipt():
    assessment = assess_gpt_provenance_v1(**diagnostic_fixture())
    assert assessment.classification == "NOT_INDEPENDENT"
    assert assessment.result == "DIAGNOSTIC_ONLY"
    assert assessment.origin_independently_attested is False
    assert assessment.bytes_revalidated_from_raw_sectors is False
    assert assessment.signed_statement_is_measurement_proof is False
    assert assessment.production_write_authorized is False
    with pytest.raises(ProvenanceRefused, match="No external GPT measurement attestor"):
        require_externally_attested_measurement(assessment)


def test_same_runner_local_trace_is_still_diagnostic_and_unattested():
    params = diagnostic_fixture()
    for row in params["statement"]["measurements"]:
        row["assurance"] = "LOCALLY_MEASURED"
        row["originProof"]["kind"] = "local-read-trace"
        row["originProof"]["evidenceSha256"] = "5" * 64
    assessment = assess_gpt_provenance_v1(**params)
    assert assessment.classification == "NOT_INDEPENDENT"
    assert assessment.origin_independently_attested is False
    assert assessment.production_write_authorized is False


@pytest.mark.parametrize("fault", [
    "signed_invented_disk", "unknown_origin", "same_runner_claims_independent",
    "missing_collection_proof", "key_origin_unpinned", "vm_replaced",
    "pid_reused", "start_ticks", "backing_replaced", "backing_inode",
    "partuuid", "primary_backup_crc", "guest_sector_hash",
    "nonce", "transaction", "request_id", "sequence", "old_observation",
    "future_observation", "false_externally_attested", "external_proof_claim",
    "writer_escalation", "new_field", "absent_guest", "observer_key_substitution",
    "stale_observer_result", "sector_size", "backup_header_lba",
])
def test_fail_closed_on_untrusted_gpt_origin_claims(fault):
    params = diagnostic_fixture()
    statement = params["statement"]
    pins = params["pins"]
    authority = params["authority"]
    records = statement["measurements"]
    if fault == "signed_invented_disk":
        records[1]["gpt"]["partitionTableId"] = (
            "gpt:00000000-0000-0000-0000-000000000001"
        )
    elif fault == "unknown_origin":
        records[0]["readMethod"] = "unknown-shell-command"
    elif fault == "same_runner_claims_independent":
        statement["classification"] = "INDEPENDENT"
    elif fault == "missing_collection_proof":
        records[1]["assurance"] = "LOCALLY_MEASURED"
    elif fault == "key_origin_unpinned":
        statement["issuer"]["policySha256"] = "0" * 64
    elif fault == "vm_replaced":
        statement["vmUuid"] = "99999999-9999-4999-8999-999999999999"
    elif fault == "pid_reused":
        statement["qemu"]["pid"] += 1
    elif fault == "start_ticks":
        records[0]["qemuStartTicks"] += 1
    elif fault == "backing_replaced":
        statement["backingChain"][1]["sha256"] = "0" * 64
    elif fault == "backing_inode":
        statement["backingChain"][1]["inode"] += 1
    elif fault == "partuuid":
        records[1]["gpt"]["partitions"][0]["partGuid"] = (
            "00000000-0000-0000-0000-000000000001"
        )
    elif fault == "primary_backup_crc":
        records[0]["gptSectors"]["backupArrayCrc32"] += 1
    elif fault == "guest_sector_hash":
        records[1]["gptSectors"]["primaryHeaderSha256"] = "0" * 64
    elif fault == "nonce":
        statement["nonce"] = "Z" * 43
    elif fault == "transaction":
        statement["transactionId"] = "99999999-9999-4999-8999-999999999999"
    elif fault == "request_id":
        statement["requestId"] = "99999999-9999-4999-8999-999999999999"
    elif fault == "sequence":
        statement["sequence"] += 1
    elif fault == "old_observation":
        records[0]["observedAt"] = (params["now"] - timedelta(minutes=2)).isoformat()
    elif fault == "future_observation":
        records[2]["observedAt"] = (params["now"] + timedelta(minutes=2)).isoformat()
    elif fault == "false_externally_attested":
        records[1]["assurance"] = "EXTERNALLY_ATTESTED"
    elif fault == "external_proof_claim":
        records[1]["originProof"]["kind"] = "external-attestation-claim"
        records[1]["originProof"]["evidenceSha256"] = "f" * 64
    elif fault == "writer_escalation":
        statement["writeAuthorized"] = True
    elif fault == "new_field":
        statement["authorization"] = "ACCEPT_WRITE"
    elif fault == "absent_guest":
        statement["measurements"].pop(1)
    elif fault == "observer_key_substitution":
        statement["issuer"]["signingKeyId"] = "unknown-key"
    elif fault == "stale_observer_result":
        params["expected_observer_result_sha256"] = "0" * 64
    elif fault == "sector_size":
        statement["qemu"]["logicalSectorSizeBytes"] = 4096
    elif fault == "backup_header_lba":
        records[0]["gptSectors"]["backupHeaderLba"] += 1
    with pytest.raises(DiskIdentityError):
        assess_gpt_provenance_v1(**params)


def test_validly_signed_observer_gpt_fabrication_fails_against_host_measurement():
    args = fresh_signed_case(
        lambda response: response["result"]["snapshot"]["safety"]["gpt"].__setitem__(
            "partitionTableId", "gpt:00000000-0000-0000-0000-000000000001"
        )
    )
    # Observer's Ed25519 signature is mathematically valid for this fabricated
    # snapshot. Safety still detects the wrong GPT identity.
    with pytest.raises(DiskIdentityError, match="disk identity"):
        consume_observer_state_no_writer(**args)


def test_valid_observer_response_cannot_replay_as_new_measurement():
    args, _, _ = example()
    first = consume_observer_state_no_writer(**args)
    assert first["decision"] == "ACCEPT_NO_WRITER"
    from auto_tests.installer_observer.remote_verifier import VerificationRefused
    with pytest.raises(VerificationRefused, match="Nonce or request ID"):
        consume_observer_state_no_writer(**args)
