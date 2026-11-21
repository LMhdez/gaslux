"""Safety GPT provenance v1 diagnostic validator; never an attestation authority.

Schema validation rejects unknown/incomplete claimed provenance. Matching signed
declarations, GPT inventories and backing hashes still cannot certify that a
real observer measured sectors. No TPM, Ed25519, replay or writer code here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from libertix_disk_identity_gate import DiskIdentityError, assert_snapshot_matches
from libertix_safety_observer_adapter import SafetyObserverPins

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] /
     "schemas/safety-gpt-provenance-v1.schema.json").read_text(encoding="utf-8")
)
Draft202012Validator.check_schema(_SCHEMA)
_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=FormatChecker())
_MAX_BYTES = 64 * 1024
_FRESHNESS = timedelta(seconds=30)


class ProvenanceRefused(DiskIdentityError):
    """Incomplete, mismatched or unjustifiably elevated GPT origin claim."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ProvenanceRefused(message)


@dataclass(frozen=True)
class ProvenanceAuthority:
    """Identity/reference values MUST come from outside the producer/runner.

    Matching these IDs proves equality to pins, not that an external entity
    authenticated those pins or attested the attached QEMU device.
    """
    issuer_id: str
    observer_id: str
    collector_id: str
    controller_id: str
    policy_id: str
    policy_sha256: str
    signing_key_id: str
    administrative_domain: str
    qemu_executable_sha256: str
    device_id: str
    overlay_path: str
    overlay_device_id: str
    overlay_inode: int
    parent_device_id: str
    parent_inode: int


@dataclass(frozen=True)
class ProvenanceAssessment:
    classification: str = "NOT_INDEPENDENT"
    result: str = "DIAGNOSTIC_ONLY"
    provenance_statement_valid: bool = True
    gpt_inventories_match: bool = True
    origin_independently_attested: bool = False
    bytes_revalidated_from_raw_sectors: bool = False
    signed_statement_is_measurement_proof: bool = False
    production_write_authorized: bool = False


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(parsed.tzinfo is not None and parsed.utcoffset() is not None,
                "GPT measurement timestamp lacks timezone")
        return parsed.astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise ProvenanceRefused("GPT measurement timestamp is invalid") from exc


def assess_gpt_provenance_v1(
    statement: dict[str, Any],
    *,
    pins: SafetyObserverPins,
    authority: ProvenanceAuthority,
    expected_observer_result_sha256: str,
    host_gpt: dict[str, Any],
    guest_gpt: dict[str, Any],
    immediate_gpt: dict[str, Any],
    now: datetime,
) -> ProvenanceAssessment:
    """Validate a future producer's v1 origin statement for DIAGNOSTICS ONLY.

    A signed v1 response is verified separately by RemoteResponseVerifier.
    The statement is not itself a remote-v1 signature or TPM attestation.
    The expected digest must come from previously verified Observer state.
    """
    require(type(statement) is dict
            and type(pins) is SafetyObserverPins
            and type(authority) is ProvenanceAuthority,
            "missing externally supplied provenance expectations")
    try:
        raw = json.dumps(statement, ensure_ascii=True, allow_nan=False).encode("utf-8")
        require(len(raw) <= _MAX_BYTES, "oversized GPT provenance statement")
        _VALIDATOR.validate(statement)
    except (TypeError, ValueError, ValidationError, OverflowError, RecursionError) as exc:
        if isinstance(exc, ProvenanceRefused):
            raise
        raise ProvenanceRefused("GPT provenance schema invalid") from exc

    require(statement["classification"] == "NOT_INDEPENDENT"
            and statement["purpose"] == "read-only-diagnostic"
            and statement["writeAuthorized"] is False,
            "invalid diagnostic trust boundary")
    require(
        statement["transactionId"] == pins.transaction_id
        and statement["vmUuid"] == pins.vm_uuid
        and statement["requestId"] == pins.request_id
        and statement["nonce"] == pins.nonce
        and statement["sequence"] == pins.sequence
        and statement["observerResultSha256"] == expected_observer_result_sha256,
        "GPT observation belongs to another signed Observer session",
    )
    issuer = statement["issuer"]
    require(
        issuer == {
            "issuerId": authority.issuer_id,
            "observerId": authority.observer_id,
            "collectorId": authority.collector_id,
            "controllerId": authority.controller_id,
            "policyId": authority.policy_id,
            "policySha256": authority.policy_sha256,
            "signingKeyId": authority.signing_key_id,
            "administrativeDomain": authority.administrative_domain,
        }
        and issuer["controllerId"] == pins.controller_id
        and issuer["collectorId"] == pins.collector_id
        and issuer["signingKeyId"] == pins.observer_key_id,
        "GPT provenance issuer identity or external policy differs",
    )

    qemu = statement["qemu"]
    require(qemu == {
        "pid": pins.qemu_pid,
        "startTicks": pins.qemu_start_ticks,
        "executableSha256": authority.qemu_executable_sha256,
        "deviceId": authority.device_id,
        "virtualSerial": pins.virtual_serial,
        "virtualSizeBytes": pins.virtual_size_bytes,
        "logicalSectorSizeBytes": host_gpt["logicalSectorSizeBytes"],
    }, "QEMU process/device/sector geometry differs from pinned provenance")
    chain = statement["backingChain"]
    require(
        chain[0] == {
            "role": "overlay", "path": authority.overlay_path, "format": "qcow2",
            "sha256": pins.overlay_sha256, "virtualSizeBytes": pins.virtual_size_bytes,
            "backingFilename": pins.backing_filename, "backingFormat": "raw",
            "deviceId": authority.overlay_device_id, "inode": authority.overlay_inode,
        }
        and chain[1] == {
            "role": "parent", "path": pins.backing_filename, "format": "raw",
            "sha256": pins.backing_sha256, "virtualSizeBytes": pins.virtual_size_bytes,
            "backingFilename": None, "backingFormat": None,
            "deviceId": authority.parent_device_id, "inode": authority.parent_inode,
        },
        "unexpected backing chain or unpinned QCOW2 inode",
    )

    require(isinstance(now, datetime) and now.tzinfo is not None
            and now.utcoffset() is not None, "independent current time required")
    current = now.astimezone(UTC)
    inventories = {"host": host_gpt, "guest": guest_gpt,
                   "immediate": immediate_gpt}
    require([x["source"] for x in statement["measurements"]]
            == ["host", "guest", "immediate"],
            "missing, reordered or duplicated GPT observers")
    source_method = {
        "host": "host-readonly-pread",
        "guest": "guest-virtio-readonly-sector",
        "immediate": "immediate-readonly-pread",
    }
    timestamps = []
    fingerprints = []
    for measurement in statement["measurements"]:
        source = measurement["source"]
        require(measurement["readMethod"] == source_method[source],
                "GPT read method conflicts with declared source")
        require(
            measurement["observerId"] == authority.observer_id
            and measurement["collectorId"] == authority.collector_id
            and measurement["qemuPid"] == pins.qemu_pid
            and measurement["qemuStartTicks"] == pins.qemu_start_ticks
            and measurement["deviceId"] == authority.device_id
            and measurement["virtualSerial"] == pins.virtual_serial,
            "GPT collector, QEMU instance or block device substituted",
        )
        # Neither the signed controller nor its runner is permitted to certify
        # EXTERNALLY_ATTESTED. No trusted external origin verifier exists here.
        require(measurement["assurance"] != "EXTERNALLY_ATTESTED"
                and measurement["originProof"]["kind"] != "external-attestation-claim",
                "unsupported or forged independent GPT attestation")
        proof = measurement["originProof"]
        require(proof["issuerId"] == authority.issuer_id,
                "GPT read proof issuer is not pinned")
        if measurement["assurance"] == "LOCALLY_MEASURED":
            require(proof["kind"] == "local-read-trace"
                    and proof["evidenceSha256"] is not None,
                    "local measurement claim lacks a trace")
        else:
            require(proof["kind"] == "none" and proof["evidenceSha256"] is None,
                    "a signed or declared snapshot cannot assert measurement proof")
        assert_snapshot_matches(inventories[source], measurement["gpt"])
        require(measurement["gpt"]["partitionTableId"] == pins.disk_id
                and measurement["gpt"]["sizeBytes"] == pins.virtual_size_bytes,
                "GPT identity diverges from externally pinned Safety inventory")
        sector = measurement["gptSectors"]
        require(sector["backupHeaderLba"]
                == pins.virtual_size_bytes // host_gpt["logicalSectorSizeBytes"] - 1,
                "backup GPT header LBA incompatible with disk size")
        require(sector["primaryArrayCrc32"] == sector["backupArrayCrc32"],
                "primary and backup GPT partition-array CRC claims contradict")
        fingerprints.append(tuple(sector[k] for k in (
            "primaryHeaderCrc32", "backupHeaderCrc32",
            "primaryArrayCrc32", "backupArrayCrc32",
            "primaryHeaderSha256", "backupHeaderSha256",
            "primaryArraySha256", "backupArraySha256",
        )))
        timestamp = _time(measurement["observedAt"])
        require(current - _FRESHNESS <= timestamp <= current + timedelta(seconds=5),
                "stale or future GPT observation")
        timestamps.append(timestamp)
    require(timestamps == sorted(timestamps), "GPT observations out of sequence")
    require(fingerprints[0] == fingerprints[1] == fingerprints[2],
            "host/guest/immediate GPT sector CRC or hashes disagree")
    assert_snapshot_matches(host_gpt, guest_gpt)
    assert_snapshot_matches(host_gpt, immediate_gpt)
    return ProvenanceAssessment()


def require_externally_attested_measurement(_: ProvenanceAssessment) -> None:
    """Always deny trusted-origin elevation until an external verifier exists."""
    raise ProvenanceRefused(
        "No external GPT measurement attestor is implemented; read-only diagnostics only"
    )
