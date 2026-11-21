"""Safety/Observer integration contracts using the exact Observer signed-test helpers.

Observer is pinned by GitHub Actions and provides Ed25519, RFC8785 and replay.
These are synthetic, independently asserted *inputs*, not a real remote sensor.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import json
import os
import runpy
import secrets
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
from libertix_disk_identity_gate import DiskIdentityError  # noqa: E402
from libertix_safety_observer_adapter import (  # noqa: E402
    SafetyGateEvidence, SafetyObserverPins, SafetyObserverRefused,
    consume_observer_state_no_writer,
)

OBSERVER_ROOT = Path(os.environ["GASLUX_OBSERVER_ROOT"]).resolve(strict=True)
assert (OBSERVER_ROOT / "auto_tests/installer_observer/remote_verifier.py").is_file()
HELP = runpy.run_path(str(OBSERVER_ROOT / "auto_tests/tests/test_observer_remote_verifier.py"))
GUARD = runpy.run_path(str(ROOT / "auto_tests/tests/test_prewrite_no_writer.py"))
DISK = GUARD["DISK"]

from auto_tests.installer_observer.remote_verifier import (  # noqa: E402
    InMemoryReplayGuard, RemoteResponseVerifier, VerificationRefused,
)


def example():
    private, store = HELP["trusted_material"]()
    verifier = RemoteResponseVerifier(store, InMemoryReplayGuard())
    now = HELP["NOW"]
    identify = HELP["make_request"]()
    verifier.verify(
        json.dumps(identify).encode(),
        json.dumps(HELP["make_response"](private, identify)).encode(),
        now=now, deadline=now + timedelta(seconds=4),
    )
    request = HELP["make_request"](
        "state.read", sequence=1, nonce=HELP["nonce_for"](1)
    )
    safety = {
        "trust_boundary": "NOT_INDEPENDENT",
        "mode": "read-only",
        "gpt": deepcopy(DISK),
        "qcow2": {
            "format": "qcow2",
            "backingFormat": "raw",
            "backingFilename": "/test/controlled/parent.raw",
            "backingSha256": "a" * 64,
            "overlaySha256": "b" * 64,
            "virtualSerial": "SAFETY-TEST-001",
            "virtualSizeBytes": DISK["sizeBytes"],
        },
    }
    def change(response):
        response["result"]["snapshot"] = {"safety": safety}
        response["result_sha256"] = HELP["sha"](HELP["rfc8785"].dumps(response["result"]))
    response = HELP["make_response"](private, request, mutate=change)
    pins = SafetyObserverPins(
        transaction_id=HELP["TRANSACTION_ID"],
        vm_uuid=HELP["VM_UUID"],
        request_id=request["request_id"],
        session_id=request["session_id"],
        nonce=request["nonce"],
        sequence=request["sequence"],
        observer_key_id=HELP["KEY_ID"],
        controller_id="test-controller",
        collector_id="test-collector",
        qemu_pid=4102,
        qemu_start_ticks=99001,
        plan_sha256="c" * 64,
        backing_filename="/test/controlled/parent.raw",
        backing_sha256="a" * 64,
        overlay_sha256="b" * 64,
        virtual_serial="SAFETY-TEST-001",
        disk_id=DISK["partitionTableId"],
        virtual_size_bytes=DISK["sizeBytes"],
    )
    guard = GUARD["guard"]
    safety_transaction = uuid.UUID(pins.transaction_id).hex
    plan = {
        "planId": safety_transaction,
        "firmware": "uefi",
        "disk": {key: DISK[key] for key in (
            "partitionStyle", "partitionTableId",
            "sizeBytes", "logicalSectorSizeBytes",
        )},
    }
    plan_bytes = guard.canonical(plan)
    from hashlib import sha256
    plan_sha256 = sha256(plan_bytes).hexdigest()
    pins = replace(pins, plan_sha256=plan_sha256)
    host_key, guest_key = secrets.token_bytes(32), secrets.token_bytes(32)
    def signed_snapshot(source, key):
        return guard.authenticated_record({
            "source": source, "transactionId": safety_transaction,
            "vmId": pins.vm_uuid, "planSha256": plan_sha256,
            "nonce": pins.nonce, "snapshot": deepcopy(DISK),
        }, key)
    gate_evidence = SafetyGateEvidence(
        host_record=signed_snapshot("host", host_key),
        guest_record=signed_snapshot("guest", guest_key),
        immediate_record=signed_snapshot("guest-immediate", guest_key),
        host_key=host_key, guest_key=guest_key,
        owned_regions=[{
            "offsetBytes": 8388608, "sizeBytes": 1048576,
            "ownerTransactionId": safety_transaction,
        }],
        write_set=[{
            "offsetBytes": 8388608, "sizeBytes": 1048576,
            "operation": "allocate-free-space",
        }],
    )
    args = {
        "verifier": verifier,
        "request": json.dumps(request).encode(),
        "response": json.dumps(response).encode(),
        "pins": pins,
        "plan_bytes": plan_bytes,
        "gate_evidence": gate_evidence,
        "host_gpt": deepcopy(DISK),
        "guest_gpt": deepcopy(DISK),
        "immediate_gpt": deepcopy(DISK),
        "now": now,
        "deadline": now + timedelta(seconds=4),
    }
    return args, private, request


def fresh_signed_case(edit):
    args, private, request = example()
    response = json.loads(args["response"])
    edit(response)
    response["result_sha256"] = HELP["sha"](HELP["rfc8785"].dumps(response["result"]))
    unsigned = dict(response)
    unsigned.pop("signature")
    signature = private.sign(HELP["rfc8785"].dumps(unsigned))
    import base64
    response["signature"]["value"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    args["response"] = json.dumps(response).encode()
    return args


def test_signed_observer_state_is_only_a_lab_no_writer_decision():
    args, _, _ = example()
    result = consume_observer_state_no_writer(**args)
    assert result["decision"] == "ACCEPT_NO_WRITER"
    assert result["trust_boundary"] == "NOT_INDEPENDENT"
    assert result["observer_message_signature_verified"] is True
    assert result["guest_attestation_verified_locally"] is False
    assert result["plan_signature_verified"] is False
    assert result["production_write_authorized"] is False
    assert result["writer_called"] is False
    assert not hasattr(__import__("libertix_safety_observer_adapter"), "authorize_write")


@pytest.mark.parametrize("fault", [
    "invalid_signature", "key_unknown", "vm_pin", "transaction_pin",
    "request_id_pin", "sequence_pin", "nonce_pin", "controller_pin",
    "collector_pin", "qemu_pid_pin", "qemu_start_pin", "plan_sha",
    "backing_sha", "overlay_sha", "virtual_serial", "disk_pin",
    "host_guest_guid", "partuuid", "immediate_offset",
    "snapshot_absent", "false_independence", "write_mode",
    "writer_request", "missing_observer", "fake_verifier",
    "gate_hmac", "gate_owner", "gate_write_set", "gate_disk",
])
def test_untrusted_or_divergent_evidence_fails_closed(fault):
    args, _, _ = example()
    pins = args["pins"]
    if fault == "invalid_signature":
        response = json.loads(args["response"])
        response["signature"]["value"] = "A" * 86
        args["response"] = json.dumps(response).encode()
    elif fault == "key_unknown":
        response = json.loads(args["response"])
        response["signature"]["key_id"] = "untrusted"
        args["response"] = json.dumps(response).encode()
    elif fault == "vm_pin":
        args["pins"] = replace(pins, vm_uuid="77777777-7777-4777-8777-777777777777")
    elif fault == "transaction_pin":
        args["pins"] = replace(pins, transaction_id="77777777-7777-4777-8777-777777777777")
    elif fault == "request_id_pin":
        args["pins"] = replace(pins, request_id="77777777-7777-4777-8777-777777777777")
    elif fault == "sequence_pin":
        args["pins"] = replace(pins, sequence=2)
    elif fault == "nonce_pin":
        args["pins"] = replace(pins, nonce=HELP["nonce_for"](4))
    elif fault == "controller_pin":
        args["pins"] = replace(pins, controller_id="other-controller")
    elif fault == "collector_pin":
        args["pins"] = replace(pins, collector_id="other-collector")
    elif fault == "qemu_pid_pin":
        args["pins"] = replace(pins, qemu_pid=4103)
    elif fault == "qemu_start_pin":
        args["pins"] = replace(pins, qemu_start_ticks=99002)
    elif fault == "plan_sha":
        args["plan_bytes"] = b"tampered plan"
    elif fault == "backing_sha":
        args["pins"] = replace(pins, backing_sha256="0" * 64)
    elif fault == "overlay_sha":
        args["pins"] = replace(pins, overlay_sha256="0" * 64)
    elif fault == "virtual_serial":
        args["pins"] = replace(pins, virtual_serial="different-disk")
    elif fault == "disk_pin":
        args["pins"] = replace(pins, disk_id="gpt:00000000-0000-0000-0000-000000000001")
    elif fault == "host_guest_guid":
        args["guest_gpt"]["partitionTableId"] = "gpt:00000000-0000-0000-0000-000000000001"
    elif fault == "partuuid":
        args["guest_gpt"]["partitions"][0]["partGuid"] = (
            "00000000-0000-0000-0000-000000000001"
        )
    elif fault == "immediate_offset":
        args["immediate_gpt"]["partitions"][0]["offsetBytes"] += 512
    elif fault == "snapshot_absent":
        args = fresh_signed_case(
            lambda response: response["result"]["snapshot"].pop("safety")
        )
    elif fault == "false_independence":
        args = fresh_signed_case(
            lambda response: response["result"]["snapshot"]["safety"].__setitem__(
                "trust_boundary", "INDEPENDENT"
            )
        )
    elif fault == "write_mode":
        args = fresh_signed_case(
            lambda response: response["result"]["snapshot"]["safety"].__setitem__(
                "mode", "write"
            )
        )
    elif fault == "writer_request":
        args = fresh_signed_case(
            lambda response: response["result"]["snapshot"]["safety"].__setitem__(
                "ACCEPT_WRITE", True
            )
        )
    elif fault == "missing_observer":
        args["response"] = b""
    elif fault == "gate_hmac":
        record = deepcopy(args["gate_evidence"].guest_record)
        record["mac"] = "0" * 64
        args["gate_evidence"] = replace(args["gate_evidence"], guest_record=record)
    elif fault == "gate_owner":
        owned = deepcopy(args["gate_evidence"].owned_regions)
        owned[0]["ownerTransactionId"] = "f" * 32
        args["gate_evidence"] = replace(args["gate_evidence"], owned_regions=owned)
    elif fault == "gate_write_set":
        write_set = deepcopy(args["gate_evidence"].write_set)
        write_set[0]["offsetBytes"] = 10485760
        args["gate_evidence"] = replace(args["gate_evidence"], write_set=write_set)
    elif fault == "gate_disk":
        record = deepcopy(args["gate_evidence"].guest_record)
        record["payload"]["snapshot"]["partitionTableId"] = (
            "gpt:00000000-0000-0000-0000-000000000001"
        )
        record = GUARD["guard"].authenticated_record(
            record["payload"], args["gate_evidence"].guest_key
        )
        args["gate_evidence"] = replace(args["gate_evidence"], guest_record=record)
    elif fault == "fake_verifier":
        class Fake:
            trust_store = args["verifier"].trust_store
            replay_guard = args["verifier"].replay_guard
            require_guest_attestation = True
            def verify(self, *a, **kw):
                raise AssertionError("untrusted fake verifier must not be called")
        args["verifier"] = Fake()
    with pytest.raises((DiskIdentityError, VerificationRefused)):
        consume_observer_state_no_writer(**args)


def test_nonce_and_request_replay_refused_by_original_observer_verifier():
    args, _, _ = example()
    consume_observer_state_no_writer(**args)
    with pytest.raises(VerificationRefused, match="Nonce or request ID"):
        consume_observer_state_no_writer(**args)


@pytest.mark.parametrize("fault", ["time_old", "request_mismatch", "sequence_invalid", "result_sha"])
def test_verifier_rejects_signed_protocol_faults(fault):
    args, private, req = example()
    if fault == "time_old":
        args = fresh_signed_case(lambda r: (
            r.__setitem__("issued_at", (HELP["NOW"]-timedelta(minutes=1)).isoformat()),
            r.__setitem__("expires_at", (HELP["NOW"]-timedelta(seconds=2)).isoformat()),
        ))
    elif fault == "request_mismatch":
        args = fresh_signed_case(lambda r: r.__setitem__(
            "request_id", "99999999-9999-4999-8999-999999999999"
        ))
    elif fault == "sequence_invalid":
        args = fresh_signed_case(lambda r: r.__setitem__("sequence", 8))
    else:
        r = json.loads(args["response"])
        r["result_sha256"] = "f" * 64
        unsigned = dict(r)
        unsigned.pop("signature")
        import base64
        r["signature"]["value"] = base64.urlsafe_b64encode(
            private.sign(HELP["rfc8785"].dumps(unsigned))
        ).decode().rstrip("=")
        args["response"] = json.dumps(r).encode()
    with pytest.raises((VerificationRefused, SafetyObserverRefused)):
        consume_observer_state_no_writer(**args)
