"""Experimental, no-writer GPT identity gate. It NEVER grants production write permission.

Trust boundary: the caller MUST independently authenticate the existing plan, VM
identity, evidence keys, origins and the evidence capture process. HMAC proves
possession of a key, not truthful hardware observations. No writer is exposed.
"""
import hashlib
import hmac
import json
import re

from libertix_disk_identity_gate import DiskIdentityError, assert_snapshot_matches


class PrewriteDenied(DiskIdentityError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def authenticated_record(payload, key):
    """Laboratory helper; keys must be provisioned out-of-band, never in a plan."""
    if type(key) is not bytes or len(key) < 32:
        raise PrewriteDenied("missing strong key")
    return {"payload": payload, "mac": hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()}


def _verified(record, key, source, transaction, plan_hash, vm, nonce):
    if type(key) is not bytes or len(key) < 32 or type(record) is not dict or set(record) != {"payload", "mac"}:
        raise PrewriteDenied("missing authenticated evidence")
    payload, mac = record["payload"], record["mac"]
    if type(payload) is not dict or set(payload) != {
        "source", "transactionId", "planSha256", "vmId", "nonce", "snapshot"
    } or type(mac) is not str or not re.fullmatch("[0-9a-f]{64}", mac):
        raise PrewriteDenied("incomplete authenticated evidence")
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        raise PrewriteDenied("evidence MAC mismatch")
    if (payload["source"], payload["transactionId"], payload["planSha256"],
            payload["vmId"], payload["nonce"]) != (source, transaction, plan_hash, vm, nonce):
        raise PrewriteDenied("wrong evidence origin, plan, transaction, VM or challenge")
    return payload["snapshot"]


def decide_no_writer(*, plan, plan_bytes, transaction_id, vm_id,
                     host_evidence, guest_evidence, immediate_evidence,
                     host_key, guest_key, fresh_nonce, owned_regions, write_set):
    """Compare independently authenticated snapshots; return only ACCEPT_NO_WRITER.

    The caller is responsible for trusted plan signature verification and re-probing
    physical identity. This experimental function MUST NOT be attached to a writer.
    """
    if (type(plan) is not dict or type(plan_bytes) is not bytes or
            canonical(plan) != plan_bytes or
            not isinstance(transaction_id, str) or
            not re.fullmatch("[0-9a-f]{32}", transaction_id) or
            plan.get("planId") != transaction_id or
            plan.get("firmware") != "uefi" or
            type(vm_id) is not str or len(vm_id) < 16 or
            type(fresh_nonce) is not str or len(fresh_nonce) < 32):
        raise PrewriteDenied("unauthenticated or invalid plan, transaction, VM or challenge")
    disk = plan.get("disk")
    if type(disk) is not dict or disk.get("partitionStyle") != "GPT":
        raise PrewriteDenied("GPT only")
    plan_hash = hashlib.sha256(plan_bytes).hexdigest()
    def verify(record, key, source):
        return _verified(record, key, source, transaction_id, plan_hash, vm_id, fresh_nonce)
    host = verify(host_evidence, host_key, "host")
    guest = verify(guest_evidence, guest_key, "guest")
    immediate = verify(immediate_evidence, guest_key, "guest-immediate")
    assert_snapshot_matches(host, guest)
    assert_snapshot_matches(host, immediate)
    for key in ("partitionTableId", "sizeBytes", "logicalSectorSizeBytes"):
        if disk.get(key) != host[key]:
            raise PrewriteDenied("plan disk identity differs from authenticated evidence")
    if type(owned_regions) is not list or not owned_regions or type(write_set) is not list or not write_set:
        raise PrewriteDenied("missing owned regions or write-set")
    sector, capacity = host["logicalSectorSizeBytes"], host["sizeBytes"]
    occupied = [(p["offsetBytes"], p["offsetBytes"] + p["sizeBytes"])
                for p in host["partitions"]]

    def region(value, owner):
        fields = {"offsetBytes", "sizeBytes", "ownerTransactionId"} if owner else {
            "offsetBytes", "sizeBytes", "operation"
        }
        if type(value) is not dict or set(value) != fields:
            raise PrewriteDenied("incomplete write extent")
        start, length = value["offsetBytes"], value["sizeBytes"]
        if (type(start) is not int or type(length) is not int or length <= 0 or
                start % sector or length % sector or
                start < max(34 * sector, 1024 * 1024) or
                start + length > capacity - 34 * sector):
            raise PrewriteDenied("write extent outside permitted free space")
        if owner and value["ownerTransactionId"] != transaction_id:
            raise PrewriteDenied("foreign ownership")
        if not owner and value["operation"] != "allocate-free-space":
            raise PrewriteDenied("unsupported writer operation")
        if any(start < b and start + length > a for a, b in occupied):
            raise PrewriteDenied("overlap with existing partition")
        return start, start + length

    owners = [region(x, True) for x in owned_regions]
    writes = sorted(region(x, False) for x in write_set)
    if len(set(owners)) != len(owners) or len(set(writes)) != len(writes):
        raise PrewriteDenied("duplicate write extents")
    for index, (start, end) in enumerate(writes):
        if index and start < writes[index - 1][1]:
            raise PrewriteDenied("overlapping write extents")
        if sum(a <= start and end <= b for a, b in owners) != 1:
            raise PrewriteDenied("write extent lacks exclusive transaction ownership")
    return {"decision": "ACCEPT_NO_WRITER", "transactionId": transaction_id,
            "planSha256": plan_hash, "vmId": vm_id, "writeCount": len(writes)}
