#!/usr/bin/env python3
"""Pop-only interface to Safety PR #265's GPT snapshot contract; no writer.

PR #265 exports a READ-ONLY regular-image identity and equality check, not
authenticated Windows/QEMU/Linux evidence. Never represent a supplied JSON,
claimed signature, or this adapter as authorization to start distinst.
"""
from __future__ import annotations

import hashlib
import json
import re

from windows_x64_installed_gpt_ro_audit import require
from windows10_popos_native_write_set import expected_pop_operations, _digest
from windows10_popos_gpt_mirror_gate import SECTOR, TOTAL_BYTES

HASH = re.compile(r"[0-9a-f]{64}\Z")
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SAFETY_FIELDS = {"partitionStyle", "partitionTableId", "sizeBytes",
                 "logicalSectorSizeBytes", "partitions"}
PART_FIELDS = {"number", "typeGuid", "partGuid", "offsetBytes",
               "sizeBytes", "attributes"}


def safety_snapshot_from_existing_gpt(after: dict) -> dict:
    """Adapt verified Pop six-GPT rows to Safety #265 field names, no GPT parser."""
    require(type(after) is dict and after.get("primaryAndBackupCrcVerified") is True,
            "Pop GPT mirror evidence absent")
    rows = after["windowsPartitions"] + [after["popEsp"], after["linuxRoot"]]
    require(len(rows) == 6 and [p["number"] for p in rows] == list(range(1, 7)),
            "Pop/Windows GPT partition inventory incomplete")
    require(type(after.get("diskGuid")) is str
            and GUID.fullmatch(after["diskGuid"]) is not None,
            "invalid existing Windows disk GUID")
    output = []
    for p in rows:
        require(type(p) is dict and type(p.get("startLba")) is int
                and type(p.get("endLba")) is int
                and 0 < p["startLba"] <= p["endLba"]
                and (p["endLba"] + 1) * SECTOR <= TOTAL_BYTES
                and all(type(p.get(k)) is str and GUID.fullmatch(p[k])
                        for k in ("guid", "type"))
                and type(p.get("attrs")) is int and p["attrs"] >= 0,
                "untrusted six-GPT partition identity")
        output.append({
            "number": p["number"],
            "typeGuid": p["type"],
            "partGuid": p["guid"],
            "offsetBytes": p["startLba"] * SECTOR,
            "sizeBytes": (p["endLba"] - p["startLba"] + 1) * SECTOR,
            "attributes": p["attrs"],
        })
    return {
        "partitionStyle": "GPT",
        "partitionTableId": "gpt:" + after["diskGuid"],
        "sizeBytes": TOTAL_BYTES,
        "logicalSectorSizeBytes": SECTOR,
        "partitions": output,
    }


def compare_safety_snapshot(expected: dict, observed: dict) -> bool:
    """Mirror PR #265's *comparison shape* for local contracts, NOT trust.

    The Safety implementation itself is not imported into the experimental
    branch; this function never claims its validator or provenance was run.
    A future contract version must consume Safety's signed/verified result.
    """
    for snap in (expected, observed):
        require(type(snap) is dict and set(snap) == SAFETY_FIELDS
                and snap["partitionStyle"] == "GPT"
                and type(snap["partitionTableId"]) is str
                and snap["partitionTableId"].startswith("gpt:")
                and GUID.fullmatch(snap["partitionTableId"][4:]) is not None
                and type(snap["sizeBytes"]) is int
                and snap["sizeBytes"] == TOTAL_BYTES
                and type(snap["logicalSectorSizeBytes"]) is int
                and snap["logicalSectorSizeBytes"] == SECTOR
                and type(snap["partitions"]) is list
                and len(snap["partitions"]) == 6,
                "Safety #265 snapshot contract absent or unsupported")
        for i, p in enumerate(snap["partitions"], 1):
            require(type(p) is dict and set(p) == PART_FIELDS
                    and type(p["number"]) is int and p["number"] == i
                    and type(p["offsetBytes"]) is int
                    and type(p["sizeBytes"]) is int
                    and type(p["attributes"]) is int and p["attributes"] >= 0
                    and p["offsetBytes"] > 0 and p["sizeBytes"] > 0
                    and p["offsetBytes"] % SECTOR == 0
                    and p["sizeBytes"] % SECTOR == 0
                    and p["offsetBytes"] + p["sizeBytes"] <= TOTAL_BYTES
                    and all(type(p[k]) is str and GUID.fullmatch(p[k])
                            for k in ("partGuid", "typeGuid")),
                    "Safety #265 exact partition identity malformed")
    require(expected == observed, "Safety identity/geometry drift")
    return True


def assess_pop_safety_handoff(proposal: dict, safety: dict | None) -> dict:
    """Only assess completeness; NEVER return an executable authorization.

    Authenticity MUST be established by a future Safety gate, not a JSON
    boolean or proof string supplied by an installer/guest.
    """
    require(type(proposal) is dict and
            proposal.get("scenario") == "genuine-win10-pop-native-claimed-write-set"
            and proposal.get("distinstExecutionAuthorized") is False
            and proposal.get("productionInstallationAuthorized") is False,
            "missing fail-closed Pop write-set")
    require(type(safety) is dict, "Safety authenticated attestation absent")
    expected = {
        "schemaVersion", "transactionId", "diskSnapshot", "writeSetSha256",
        "provenance", "issuedAtUtc", "expiresAtUtc", "authenticator",
    }
    require(set(safety) == expected,
            "Safety #265 does not provide complete authenticated write attestation")
    require(safety["transactionId"] == proposal["transactionId"],
            "Safety handoff belongs to different transaction")
    require(safety["writeSetSha256"] == _digest(proposal),
            "Safety write-set digest differs from exact Pop proposal")
    require(type(safety["provenance"]) is dict
            and type(safety["authenticator"]) is dict
            and safety["provenance"].get("producer") == "GASLUX-SAFETY"
            and safety["provenance"].get("independentHostMeasurement") is True
            and safety["provenance"].get("independentGuestMeasurement") is True
            and safety["provenance"].get("physicalGuestBindingVerified") is True,
            "untrusted Safety provenance / host-guest binding")
    # Important: no generic signature verification is available at #265.
    # Refuse even well-formed self-asserted 'verified' flags, timestamps, and
    # digest; supplying an arbitrary certificate or public key cannot unlock.
    require(False,
            "Safety #265 lacks independently authenticated host/guest attestation")
    raise AssertionError("unreachable")


def classify_distinst_trace(proposal: dict, events: list[dict]) -> dict:
    """Fail-closed offline observer for independently collected events.

    UNKNOWN event kinds and missing range/file provenance are not mapped to
    an allowed filesystem operation. An internally emitted distinst log is
    insufficient to attest actual block writes.
    """
    require(type(proposal) is dict
            and proposal.get("distinstExecutionAuthorized") is False
            and type(events) is list,
            "native write-set/trace absent")
    owned = proposal.get("ownedOperations")
    require(type(owned) is list and len(owned) == 6,
            "native plan missing owned operations")
    allowed = {(p["partitionIndex"], p["partuuid"], p["operation"],
                p["offsetBytes"], p["lengthBytes"], p["filesystem"], p["mount"])
               for p in owned}
    require(len(events) > 0, "empty trace cannot attest installed write-set")
    for item in events:
        require(type(item) is dict and set(item) == {
            "diskGuid", "partitionIndex", "partuuid", "operation",
            "offsetBytes", "lengthBytes", "filesystem", "mount",
            "measurement", "source",
        }, "incomplete or unknown distinst write event")
        require(item["diskGuid"] == proposal["disk"]["guid"]
                and item["measurement"] == "block-write"
                and item["source"] == "independent-qemu-observer"
                and (item["partitionIndex"], item["partuuid"],
                     item["operation"], item["offsetBytes"],
                     item["lengthBytes"], item["filesystem"],
                     item["mount"]) in allowed,
                "unowned or unauthenticated distinst operation")
    return {"eventsSyntacticallyWithinProposal": True,
            "allWritesObserved": False,
            "safetyAttestationAuthenticated": False,
            "distinstExecutionAuthorized": False}
