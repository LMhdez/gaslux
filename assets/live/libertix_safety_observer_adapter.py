"""Experimental Safety consumer for the Observer v1 signed read-only protocol.

No cryptography, canonicalization or replay implementation here: ALWAYS call
the actual pinned Observer RemoteResponseVerifier, with its external TrustStore
and ReplayGuard.  The returned decision is NEVER a write authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
import uuid
from typing import Any

from libertix_disk_identity_gate import DiskIdentityError, assert_snapshot_matches
from libertix_prewrite_no_writer import decide_no_writer


class SafetyObserverRefused(DiskIdentityError):
    """Signed evidence is insufficient for even a laboratory no-writer decision."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SafetyObserverRefused(reason)


@dataclass(frozen=True)
class SafetyObserverPins:
    """All values must be supplied OUTSIDE the Observer response and runner."""
    transaction_id: str
    vm_uuid: str
    request_id: str
    session_id: str
    nonce: str
    sequence: int
    observer_key_id: str
    controller_id: str
    collector_id: str
    qemu_pid: int
    qemu_start_ticks: int
    plan_sha256: str
    backing_filename: str
    backing_sha256: str
    overlay_sha256: str
    virtual_serial: str
    disk_id: str
    virtual_size_bytes: int

    def __post_init__(self) -> None:
        import uuid
        for name in ("transaction_id", "vm_uuid", "request_id", "session_id"):
            value = getattr(self, name)
            require(type(value) is str, "invalid pinned UUID")
            try:
                require(str(uuid.UUID(value)) == value, "noncanonical pinned UUID")
            except ValueError as exc:
                raise SafetyObserverRefused("invalid pinned UUID") from exc
        for name in ("plan_sha256", "backing_sha256", "overlay_sha256"):
            value = getattr(self, name)
            require(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None,
                    "invalid pinned digest")
        for name in ("observer_key_id", "controller_id", "collector_id",
                     "backing_filename", "virtual_serial", "disk_id"):
            value = getattr(self, name)
            require(type(value) is str and 0 < len(value) <= 1024,
                    "incomplete independent pin")
        require(self.disk_id.startswith("gpt:") and len(self.disk_id) == 40,
                "invalid pinned GPT identity")
        require(type(self.nonce) is str and len(self.nonce) == 43,
                "missing coordinator-owned challenge")
        require(type(self.sequence) is int and 1 <= self.sequence <= 4096,
                "state.read requires an existing sequenced session")
        require(type(self.qemu_pid) is int and self.qemu_pid > 1
                and type(self.qemu_start_ticks) is int and self.qemu_start_ticks > 0,
                "missing externally observed QEMU process identity")
        require(type(self.virtual_size_bytes) is int and self.virtual_size_bytes > 0,
                "invalid virtual disk size")


@dataclass(frozen=True)
class SafetyGateEvidence:
    """Externally supplied LABORATORY HMAC observations and declared free-space.

    Existing decide_no_writer validates the HMACs and transaction ownership
    assertions. These values DO NOT certify an independent physical observer.
    """
    host_record: dict
    guest_record: dict
    immediate_record: dict
    host_key: bytes
    guest_key: bytes
    owned_regions: list[dict]
    write_set: list[dict]


def consume_observer_state_no_writer(
    *,
    verifier: Any,
    request: bytes,
    response: bytes,
    pins: SafetyObserverPins,
    plan_bytes: bytes,
    host_gpt: dict,
    guest_gpt: dict,
    immediate_gpt: dict,
    gate_evidence: SafetyGateEvidence,
    now: datetime,
    deadline: datetime,
) -> dict:
    """Invoke the REAL Observer verifier, then bind signed state to Safety GPT.

    The three GPT measurements must come from a separate authorized Safety
    lab.  The adapter cannot attest their collection process.  In-memory
    replay guard and pinned observer artefacts are not production trust.
    """
    try:
        from auto_tests.installer_observer.remote_verifier import (
            RemoteResponseVerifier, TrustStore,
        )
    except ImportError as exc:
        raise SafetyObserverRefused("Observer verifier dependency unavailable") from exc

    require(type(verifier) is RemoteResponseVerifier
            and type(verifier.trust_store) is TrustStore
            and verifier.replay_guard is not None
            and verifier.require_guest_attestation is True,
            "the pinned Observer verifier and replay guard are mandatory")
    require(type(pins) is SafetyObserverPins, "external Safety pins missing")
    require(type(plan_bytes) is bytes and
            hashlib.sha256(plan_bytes).hexdigest() == pins.plan_sha256,
            "plan bytes differ from the externally pinned SHA-256")
    require(type(request) is bytes and type(response) is bytes,
            "immutable raw request and response bytes required")

    # Observer handles schemas, Ed25519/RFC8785 signatures, dates, identity
    # pins, sequence and atomic replay. We do NOT reproduce any of those.
    verified = verifier.verify(request, response, deadline=deadline, now=now)
    require(verified.controller_signature_verified is True
            and verified.controller_artifact_hash_matches_pin is True
            and verified.collector_artifact_hash_matches_pin is True
            and verified.status == "ok"
            and verified.operation == "state.read",
            "Observer did not verify a successful signed state.read response")

    req, rsp = json.loads(request), json.loads(response)
    require(
        req.get("operation") == "state.read"
        and req.get("transaction_id") == pins.transaction_id
        and req.get("request_id") == pins.request_id
        and req.get("session_id") == pins.session_id
        and req.get("nonce") == pins.nonce
        and req.get("sequence") == pins.sequence
        and verified.transaction_id == pins.transaction_id
        and verified.request_id == pins.request_id,
        "Observer request is not bound to the externally authorized transaction",
    )
    trusted = verifier.trust_store.controllers.get(pins.observer_key_id)
    require(
        trusted is not None
        and len(verifier.trust_store.controllers) == 1
        and trusted.key_id == pins.observer_key_id
        and trusted.controller_id == pins.controller_id
        and trusted.collector_id == pins.collector_id
        and trusted.vm_uuid == pins.vm_uuid,
        "Observer identities are not independently pinned",
    )
    guest = rsp["guest"]
    qemu = guest["qemu_process"]
    require(
        rsp["controller"]["key_id"] == pins.observer_key_id
        and rsp["controller"]["controller_id"] == pins.controller_id
        and rsp["collector"]["collector_id"] == pins.collector_id
        and guest["vm_uuid"] == pins.vm_uuid
        and qemu["pid"] == pins.qemu_pid
        and qemu["start_ticks"] == pins.qemu_start_ticks,
        "Observer VM, controller, collector or QEMU process mismatches pins",
    )
    snapshot = verified.result
    require(snapshot.get("kind") == "state"
            and type(snapshot.get("snapshot")) is dict
            and set(snapshot["snapshot"]) == {"safety"},
            "signed Observer state lacks a dedicated Safety evidence envelope")
    safety = snapshot["snapshot"]["safety"]
    require(type(safety) is dict
            and set(safety) == {"trust_boundary", "gpt", "qcow2", "mode"}
            and safety["trust_boundary"] == "NOT_INDEPENDENT"
            and safety["mode"] == "read-only",
            "Observer attempted to claim independence or an unauthorized mode")
    qcow = safety["qcow2"]
    require(type(qcow) is dict
            and set(qcow) == {
                "format", "backingFormat", "backingFilename", "backingSha256",
                "overlaySha256", "virtualSerial", "virtualSizeBytes"
            }
            and qcow["format"] == "qcow2"
            and qcow["backingFormat"] == "raw"
            and qcow["backingFilename"] == pins.backing_filename
            and qcow["backingSha256"] == pins.backing_sha256
            and qcow["overlaySha256"] == pins.overlay_sha256
            and qcow["virtualSerial"] == pins.virtual_serial
            and qcow["virtualSizeBytes"] == pins.virtual_size_bytes,
            "QCOW2 backing, format, serial or geometry differs from external pins")
    assert_snapshot_matches(host_gpt, guest_gpt)
    assert_snapshot_matches(host_gpt, immediate_gpt)
    assert_snapshot_matches(host_gpt, safety["gpt"])
    require(
        host_gpt["partitionTableId"] == pins.disk_id
        and host_gpt["sizeBytes"] == pins.virtual_size_bytes,
        "GPT disk or virtual geometry differs from approved Safety inventory",
    )
    require(type(gate_evidence) is SafetyGateEvidence,
            "authenticated Safety gate evidence is mandatory")
    # The observer UUID must map to the SAME 128-bit Safety transaction, not to
    # a regenerated or caller-selected unrelated string.
    safety_transaction_id = uuid.UUID(pins.transaction_id).hex
    try:
        plan = json.loads(plan_bytes)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SafetyObserverRefused("Safety plan is not canonical JSON") from exc
    expected_disk = {key: host_gpt[key] for key in (
        "partitionStyle", "partitionTableId", "sizeBytes",
        "logicalSectorSizeBytes",
    )}
    require(
        type(plan) is dict
        and plan.get("planId") == safety_transaction_id
        and plan.get("firmware") == "uefi"
        and plan.get("disk") == expected_disk,
        "observer transaction or GPT differs from the Safety plan",
    )
    gate_result = decide_no_writer(
        plan=plan, plan_bytes=plan_bytes,
        transaction_id=safety_transaction_id, vm_id=pins.vm_uuid,
        fresh_nonce=pins.nonce,
        host_evidence=gate_evidence.host_record,
        guest_evidence=gate_evidence.guest_record,
        immediate_evidence=gate_evidence.immediate_record,
        host_key=gate_evidence.host_key,
        guest_key=gate_evidence.guest_key,
        owned_regions=gate_evidence.owned_regions,
        write_set=gate_evidence.write_set,
    )
    require(gate_result["decision"] == "ACCEPT_NO_WRITER"
            and gate_result["transactionId"] == safety_transaction_id
            and gate_result["planSha256"] == pins.plan_sha256,
            "Safety gate did not authorize a laboratory no-writer comparison")
    # HMAC-valid snapshots must also be the ACTUAL snapshots supplied to this
    # consumer, not a different but internally self-consistent fake disk.
    for record, observed in (
        (gate_evidence.host_record, host_gpt),
        (gate_evidence.guest_record, guest_gpt),
        (gate_evidence.immediate_record, immediate_gpt),
    ):
        assert_snapshot_matches(observed, record["payload"]["snapshot"])
    return {
        "decision": gate_result["decision"],
        "trust_boundary": "NOT_INDEPENDENT",
        "observer_message_signature_verified": True,
        "guest_attestation_verified_locally": verified.guest_attestation_verified_locally,
        "plan_signature_verified": False,
        "production_write_authorized": False,
        "writer_called": False,
        "transaction_id": pins.transaction_id,
        "vm_uuid": pins.vm_uuid,
        "request_id": pins.request_id,
        "observer_result_sha256": verified.result_sha256,
        "plan_sha256": pins.plan_sha256,
    }
