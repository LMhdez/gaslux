#!/usr/bin/env python3
"""Non-executable, fail-closed Windows/CachyOS partition transaction proposal.

This module is purely functional: no disk access, subprocess, bootloader or
filesystem mutation. A proposal is NOT permission to write to a disk.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


class ProposalRejected(ValueError):
    """Input is not a trustworthy read-only transaction proposal."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ProposalRejected(reason)


def canonical_sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def propose(report: Mapping[str, Any], transaction: Mapping[str, Any]) -> dict[str, Any]:
    """Build a simulation only, binding exact evidence and immutable intent.

    Never returns a command, device path, write token, or permission to mutate.
    The real writer must independently revalidate disk bytes, state, recovery,
    encryption and boot integrity; none of those conditions is established here.
    """
    require(isinstance(report, dict) and isinstance(transaction, dict),
            "report and transaction must be objects")
    require(set(transaction) == {"transactionId", "expectedDiskGuidSha256",
                                 "expectedGptAuditWindowsSha256", "expectedFirstLba",
                                 "expectedLastLba"},
            "unknown/missing transaction properties")
    require(re.fullmatch(r"[0-9a-f]{32}", transaction["transactionId"])
            if isinstance(transaction["transactionId"], str) else False,
            "malformed transaction identity")
    for field in ("expectedDiskGuidSha256", "expectedGptAuditWindowsSha256"):
        require(canonical_sha(transaction[field]), "malformed evidence digest")
    for field in ("expectedFirstLba", "expectedLastLba"):
        require(type(transaction[field]) is int and transaction[field] >= 0,
                "invalid integer LBA")

    require(report.get("candidateWindowsGptPrimaryAndBackupConsistent") is True,
            "GPT consistency is unproven")
    for field in ("storageWritesAuthorized", "releaseEligible", "sameDiskDualBootVerified"):
        require(report.get(field) is False, "untrusted report authority flag")
    require(report.get("sectorBytes") == 512 and
            report.get("virtualDiskBytes") == 128 * 1024**3,
            "unexpected virtual disk geometry")
    require(canonical_sha(report.get("diskGuidSha256")) and
            canonical_sha(report.get("gptAuditWindowsSha256")),
            "missing or invalid GPT evidence identity")
    require(report["diskGuidSha256"] == transaction["expectedDiskGuidSha256"] and
            report["gptAuditWindowsSha256"] ==
            transaction["expectedGptAuditWindowsSha256"],
            "stale or foreign GPT evidence")

    partitions = report.get("windowsPartitions")
    require(isinstance(partitions, list) and len(partitions) == 4,
            "unexpected Windows partition inventory")
    require(all(isinstance(p, dict) and type(p.get("firstLba")) is int and
                type(p.get("lastLba")) is int and p["firstLba"] <= p["lastLba"]
                for p in partitions), "malformed Windows geometry")
    require(all(partitions[i]["lastLba"] < partitions[i+1]["firstLba"]
                for i in range(3)), "overlapping or unordered Windows partitions")

    extent = report.get("observedPostWindowsFreeExtent")
    require(isinstance(extent, dict), "missing post-Windows observation")
    require(extent.get("readOnlyObservation") is True and
            extent.get("partitionCreated") is False and
            extent.get("linuxWriteAuthorized") is False and
            extent.get("recoveryAndOwnershipProofRequired") is True,
            "extent is not a protected read-only observation")
    start, end = extent.get("firstLba"), extent.get("lastLba")
    require(type(start) is int and type(end) is int and 0 < start <= end,
            "invalid observed LBA extent")
    require(start == transaction["expectedFirstLba"] and
            end == transaction["expectedLastLba"], "stale extent")
    require(extent.get("alignmentBytes") == 1024 * 1024 and
            start % 2048 == 0 and (end + 1) % 2048 == 0,
            "unaligned extent")
    require(start > partitions[-1]["lastLba"] and
            end <= report["virtualDiskBytes"] // 512 - 34 and
            extent.get("lengthBytes") == (end - start + 1) * 512 and
            extent["lengthBytes"] >= 40 * 1024**3,
            "extent overlaps Windows, GPT backup or lacks required capacity")
    require(report.get("protectiveMbrCanonical") is True and
            report.get("protectiveMbrOversizedWindowsLabException") is False,
            "noncanonical protective MBR cannot be used to propose mutation")

    identity = {
        "transactionId": transaction["transactionId"],
        "diskGuidSha256": report["diskGuidSha256"],
        "gptAuditWindowsSha256": report["gptAuditWindowsSha256"],
        "firstLba": start,
        "lastLba": end,
        "sectorBytes": 512,
    }
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True,
                                        separators=(",", ":")).encode()).hexdigest()
    return {
        "proposalSchema": "gaslux-cachyos-simulated-partition-v1",
        "identity": identity,
        "proposalSha256": digest,
        "simulationOnly": True,
        "storageWritesAuthorized": False,
        "partitionCreated": False,
        "recoveryPrepared": False,
        "recoveryVerified": False,
        "windowsBootAfterLinuxVerified": False,
        "sameDiskDualBootVerified": False,
        "releaseEligible": False,
    }
