#!/usr/bin/env python3
"""Fail-closed reader of the genuine Win10/Pop QEMU laboratory evidence.

The Pop lab emits a *read-only guest witness*, not a Safety host/guest
transaction attestation. This boundary must remain an explicit DENY.
No writer, HMAC material, privileged command, or disk access is exposed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from libertix_prewrite_no_writer import PrewriteDenied

FILES = (
    "win10-pop-live-gpt.json",
    "win10-pop-native-child-checkpoint.json",
)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def _load_verified(root: Path, name: str) -> dict:
    path = root / name
    signature = root / (name + ".sha256")
    for item in (path, signature):
        if item.is_symlink():
            raise PrewriteDenied("symlink evidence path")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(item, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 65536:
                raise PrewriteDenied("unsafe evidence file")
            data = os.read(fd, info.st_size)
            if len(data) != info.st_size:
                raise PrewriteDenied("short evidence read")
        finally:
            os.close(fd)
        if item == path:
            payload = data
        else:
            digest_text = data.decode("ascii")
    expected = hashlib.sha256(payload).hexdigest() + "  " + name + "\n"
    if digest_text != expected:
        raise PrewriteDenied("evidence file digest mismatch")
    value = json.loads(payload)
    if type(value) is not dict:
        raise PrewriteDenied("evidence is not a JSON object")
    return value


def observe_readonly_lab(root: Path) -> dict:
    """Read the exact produced evidence. A .sha256 sidecar is NOT authenticity."""
    if root.is_symlink() or not root.is_dir():
        raise PrewriteDenied("unsafe evidence root")
    guest = _load_verified(root, FILES[0])
    child = _load_verified(root, FILES[1])
    measured = guest.get("guestGpt")
    if (type(measured) is not dict or
            measured.get("primaryAndBackupGptCrcVerified") is not True or
            measured.get("diskWritePerformed") is not False or
            measured.get("distinstExecutionAuthorized") is not False or
            type(measured.get("diskGuid")) is not str or
            GUID.fullmatch(measured["diskGuid"]) is None or
            guest.get("nativeInstallationExecuted") is not False):
        raise PrewriteDenied("guest read-only witness absent or invalid")
    if not (
        child.get("childCreatedThenDiscardedWithoutWrite") is True and
        child.get("distinstExecutionAuthorized") is False and
        child.get("authenticatedNativeInstallHandoffVerified") is False and
        child.get("productionInstallationAuthorized") is False
    ):
        raise PrewriteDenied("nested QCOW2 child lifecycle unproven")
    base_hash = child.get("snapshotOfGenuineWindowsParentSha256")
    stage_hash = child.get("snapshotOfSixGptWindowsStageSha256")
    if not (type(base_hash) is str and HEX64.fullmatch(base_hash) and
            type(stage_hash) is str and HEX64.fullmatch(stage_hash)):
        raise PrewriteDenied("backing hash witness incomplete")
    return {
        "guestDiskGuid": measured["diskGuid"],
        "primaryAndBackupGptCrcVerified": True,
        "guestDiskWritePerformed": False,
        "windowsParentSha256": base_hash,
        "stagedParentSha256": stage_hash,
        "nestedChildDiscarded": True,
        "genuineGuestObservationClaimed": True,
        "hostGuestAuthenticatedBySafety": False,
    }


def assess_for_safety(record: dict, *, transaction_id: str | None,
                      vm_id: str | None, expected_guest_guid: str | None,
                      nonce: str | None) -> dict:
    """Return a machine-readable DENY even when guest witness appears sound.

    A host measurement, live recheck, independently authenticated VM/plan
    and nonce registry are absent; a self-reported QEMU witness cannot
    substitute for them. Deliberately no path to ACCEPT_NO_WRITER.
    """
    reason = "missing independently authenticated host/guest/plan/transaction binding"
    if not transaction_id or not re.fullmatch(r"[0-9a-f]{32}", transaction_id):
        reason = "transaction missing or invalid"
    elif not vm_id or len(vm_id) < 16:
        reason = "VM identity missing or invalid"
    elif not nonce or len(nonce) < 32:
        reason = "freshness challenge missing or invalid"
    elif not expected_guest_guid or record["guestDiskGuid"] != expected_guest_guid:
        reason = "guest disk GUID mismatch"
    return {"decision": "DENY_NO_WRITER", "reason": reason,
            "guestDiskGuid": record["guestDiskGuid"],
            "hostGuestAuthenticatedBySafety": False, "writerCalled": False}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        observed = observe_readonly_lab(args.evidence)
        result = assess_for_safety(
            observed, transaction_id=None, vm_id=None,
            expected_guest_guid=observed["guestDiskGuid"], nonce=None,
        )
        report = {"readOnlyLabObservation": observed, "safetyGate": result,
                  "status": "REFUSED_UNAUTHENTICATED_PROVENANCE"}
        print(json.dumps(report, sort_keys=True))
        if result["decision"] != "DENY_NO_WRITER":
            raise PrewriteDenied("unexpected authorization")
    except Exception as error:
        report = {"status": "REFUSED_MISSING_OR_INVALID_EVIDENCE",
                  "reason": type(error).__name__, "writerCalled": False}
        print(json.dumps(report, sort_keys=True))
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
