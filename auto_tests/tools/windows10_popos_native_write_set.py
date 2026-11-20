#!/usr/bin/env python3
"""Fail-closed, INERT Pop/System76 six-GPT write-set proposal for VM laboratory.

This is NOT a disk writer or an authorization to run distinst. It consumes the
existing reconciled Windows/Pop identity contract; it never invents a second
disk identity. A signed-shaped plan and host flags are claims, not a trust
anchor. In particular, upstream distinst's disk.commit() cannot yet be
confined to Pop partition byte ranges. No commands are emitted or executed.
"""
from __future__ import annotations

import hashlib
import json
import re

from windows10_popos_native_readonly_handoff_candidate import preview_native_handoff
from windows10_popos_gpt_mirror_gate import SECTOR, TOTAL_BYTES
from windows_x64_installed_gpt_ro_audit import require

SHA = re.compile(r"[a-f0-9]{64}\Z")
TX = re.compile(
    r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z"
)
OWNED_INDEXES = (5, 6)
WINDOWS_INDEXES = (1, 2, 3, 4)
LAB_CHILD = "gaslux-pop-native-install.qcow2"
LAB_STAGE = "gaslux-pop-stage.qcow2"
LAB_BASE = "only-disposable-windows-target.qcow2"


def _digest(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _resource(row: dict, *, operation: str, filesystem: str | None,
              mount: str | None) -> dict:
    start, end = row["startLba"], row["endLba"]
    require(type(start) is int and type(end) is int and
            0 < start <= end and (end + 1) * SECTOR <= TOTAL_BYTES,
            "invalid proposed Pop resource geometry")
    return {
        "operation": operation,
        "partitionIndex": row["number"],
        "partuuid": row["guid"],
        "offsetBytes": start * SECTOR,
        "lengthBytes": (end - start + 1) * SECTOR,
        "filesystem": filesystem,
        "mount": mount,
    }


def expected_pop_operations(after: dict) -> list[dict]:
    """Declarative upper-bound, never native executable distinst argv."""
    esp, root = after["popEsp"], after["linuxRoot"]
    return [
        _resource(esp, operation="format", filesystem="fat32", mount=None),
        _resource(root, operation="format", filesystem="ext4", mount=None),
        _resource(root, operation="mount", filesystem="ext4", mount="/"),
        _resource(esp, operation="mount", filesystem="fat32", mount="/boot/efi"),
        _resource(root, operation="install-root", filesystem="ext4", mount="/"),
        _resource(esp, operation="install-systemd-boot",
                  filesystem="fat32", mount="/boot/efi"),
    ]


def propose_native_write_set(
    before: dict, after: dict, plan: dict, media: dict, guest: dict,
    transaction: dict, checkpoint: dict, requested_operations: list[dict],
) -> dict:
    """Check exact six-GPT identity, authenticated-shaped transaction claims.

    The returned proposal always refuses native execution. Only a future
    separate, independently trusted verifier can authorize actual writes.
    """
    candidate = preview_native_handoff(before, after, plan, media, guest)
    require(type(transaction) is dict
            and set(transaction) == {
                "transactionId", "handoffSha256", "handoffSignatureVerified",
                "identityGatePassed", "recoveryCheckpointPrepared",
            }
            and type(transaction["transactionId"]) is str
            and TX.fullmatch(transaction["transactionId"]) is not None
            and transaction["handoffSignatureVerified"] is True
            and transaction["identityGatePassed"] is True
            and transaction["recoveryCheckpointPrepared"] is True,
            "missing authenticated-shaped transaction and prewrite recovery claims")
    expected_digest = _digest({
        "before": before, "after": after, "plan": plan,
        "media": media, "guest": guest, "checkpoint": checkpoint,
        "transactionId": transaction["transactionId"],
    })
    require(transaction["handoffSha256"] == expected_digest,
            "transaction handoff does not bind exact Windows/Pop plan")
    require(type(checkpoint) is dict and
            checkpoint.get("schemaVersion") == 1 and
            checkpoint.get("scenario") == "genuine_win10_pop_owned_native_child_checkpoint"
            and checkpoint.get("writerMayUseOnlyPrivateNativeChild") is True
            and checkpoint.get("distinstExecutionAuthorized") is False
            and checkpoint.get("authenticatedNativeInstallHandoffVerified") is False
            and checkpoint.get("productionInstallationAuthorized") is False
            and checkpoint.get("rollbackVerified") is False
            and all(type(checkpoint.get(field)) is str
                    and SHA.fullmatch(checkpoint[field]) is not None
                    for field in ("snapshotOfGenuineWindowsParentSha256",
                                  "snapshotOfSixGptWindowsStageSha256")),
            "absent or contradictory independently measured QCOW2 checkpoint")
    require(type(requested_operations) is list
            and requested_operations == expected_pop_operations(after),
            "incomplete, foreign or reordered native System76 write-set")
    protected = [
        _resource(row, operation="exclude", filesystem=None, mount=None)
        for row in after["windowsPartitions"]
    ]
    require([x["partitionIndex"] for x in protected] == list(WINDOWS_INDEXES),
            "Windows GPT exclusion list incomplete")
    owned = expected_pop_operations(after)
    require([x["partitionIndex"] for x in owned] == [5, 6, 6, 5, 6, 5],
            "Pop write-set partition selection incomplete")
    for op in owned:
        a, b = op["offsetBytes"], op["offsetBytes"] + op["lengthBytes"]
        require(all(b <= w["offsetBytes"] or
                    a >= w["offsetBytes"] + w["lengthBytes"]
                    for w in protected),
                "Pop write-set overlaps Windows partitions")
    # NOTE: upstream distinst's partition step iterates physical disks and
    # calls disk.commit(). Its sector-level effects on GPT/PMBR/partition
    # metadata must be independently confined before executing any writer.
    return {
        "schemaVersion": 1,
        "scenario": "genuine-win10-pop-native-claimed-write-set",
        "transactionId": transaction["transactionId"],
        "handoffSha256": expected_digest,
        "identitySource": "existing-windows10-popos-six-gpt-reconcile",
        "disk": {
            "guid": before["diskGuid"],
            "virtioSerial": candidate["diskSerial"],
            "sizeBytes": TOTAL_BYTES,
            "logicalSectorBytes": SECTOR,
        },
        "ownedOperations": owned,
        "protectedWindowsResources": protected,
        "forbiddenEfiPaths": ["EFI/Microsoft", "EFI/Boot/bootmgfw.efi"],
        "forbiddenOperations": [
            "disk-commit", "rewrite-gpt", "rewrite-mbr", "change-partition-table",
            "format-windows", "write-windows-esp", "write-windows-ntfs",
            "write-windows-recovery", "write-efi-nvram", "change-bootorder",
            "change-bootnext", "replace-windows-boot-manager",
        ],
        "bootloader": {"name": "systemd-boot", "partitionIndex": 5,
                       "efiVariablesWritable": False, "windowsEspWritable": False},
        "backingParentsSha256": {
            "base": checkpoint["snapshotOfGenuineWindowsParentSha256"],
            "stage": checkpoint["snapshotOfSixGptWindowsStageSha256"],
        },
        "signedHandoffAuthorityEstablished": False,
        "diskCommitSideEffectsConfined": False,
        "durableNativeWriteRollbackVerified": False,
        "distinstExecutionAuthorized": False,
        "productionInstallationAuthorized": False,
        "blocker": "native distinst disk.commit() may rewrite GPT outside Pop #5/#6",
    }


def check_observed_write_events(proposal: dict, events: list[dict]) -> dict:
    """Offline trace checker; a valid trace never authorizes a future writer."""
    require(type(proposal) is dict
            and proposal.get("distinstExecutionAuthorized") is False
            and type(events) is list and len(events) > 0,
            "missing inert write-set or observed write event list")
    expected = proposal["ownedOperations"]
    require(events == expected, "native write trace contains unauthorized operations")
    return {
        "observedEventsMatchProposal": True,
        "distinstExecutionAuthorized": False,
        "productionInstallationAuthorized": False,
    }
