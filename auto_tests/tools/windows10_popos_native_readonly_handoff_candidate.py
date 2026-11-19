#!/usr/bin/env python3
"""Read-only System76 native-install HANDOFF CANDIDATE for the Win10 six-GPT lab.

This module does NOT execute distinst, issue shell commands, inspect disks,
verify external signatures, format partitions or authorize an installation.
It only validates the *shape* of previously measured evidence and emits an
inert candidate partition selection. A future authenticated live handoff MUST
re-measure every source from the actual guest before writes are considered.
"""
from __future__ import annotations

import re

from windows10_popos_independent_esp_root_stage import reconcile_owned_pair
from windows_x64_installed_gpt_ro_audit import require

LAB_VIRTIO_SERIAL = "GASLUX_POP_WIN10_COW"
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _valid_hash(value: object) -> bool:
    return (
        type(value) is str
        and HEX_SHA256.fullmatch(value) is not None
        and any(char != "0" for char in value)
    )


def _expected_partitions(after: dict) -> list[dict]:
    """Literal full GPT identity, not /dev/sda or enumeration order."""
    rows = after["windowsPartitions"] + [after["popEsp"], after["linuxRoot"]]
    require(len(rows) == 6, "incomplete Windows+Pop GPT roles")
    return [
        {
            "index": row["number"],
            "guid": row["guid"],
            "typeGuid": row["type"],
            "firstLba": row["startLba"],
            "lastLba": row["endLba"],
        }
        for row in rows
    ]


def preview_native_handoff(
    before: dict, after: dict, plan: dict,
    media: dict, live_guest: dict,
) -> dict:
    """Refuse ambiguous ownership; return NO executable/authorized operation.

    A JSON-shaped plan is not a cryptographic signature. The flags in
    media/live_guest are evidence *claims* used for contract checking, not
    authoritative proof of a signed handoff or genuine firmware state.
    """
    require(
        type(before) is dict and type(after) is dict and type(plan) is dict
        and type(media) is dict and type(live_guest) is dict,
        "invalid native handoff evidence document",
    )
    reconcile_owned_pair(before, after, plan)
    require(
        plan.get("firmware") == "uefi"
        and plan.get("partitionStyle") == "gpt"
        and plan.get("windowsEspToRemainUntouched") is True
        and plan.get("windowsBootManagerToRemainUntouched") is True
        and plan.get("productionInstallationAuthorized") is False
        and plan.get("sameDiskDualBootVerified") is False
        and len(plan.get("partitions", [])) == 2,
        "unsafe System76 shared-disk plan policy",
    )
    require(
        media.get("upstreamId") == "pop"
        and media.get("version") == "24.04"
        and media.get("variant") == "intel"
        and media.get("officialIsoSignedMetadataVerified") is True
        and _valid_hash(media.get("isoSha256"))
        and _valid_hash(media.get("distinstSha256"))
        and media["isoSha256"] != media["distinstSha256"],
        "untrusted native Pop media or System76 agent identity",
    )
    require(
        live_guest.get("hostedDisposableVm") is True
        and live_guest.get("qcow2ChildOnly") is True
        and live_guest.get("windowsBackingWritable") is False
        and live_guest.get("firmware") == "uefi"
        and live_guest.get("partitionStyle") == "gpt"
        and live_guest.get("secureBootEnabled") is False
        and live_guest.get("diskSerial") == LAB_VIRTIO_SERIAL
        and live_guest.get("diskGuid") == before["diskGuid"]
        and live_guest.get("partitionEntries") == _expected_partitions(after)
        and live_guest.get("popEspFilesystem") is None
        and live_guest.get("popRootFilesystem") is None
        and live_guest.get("windowsEspMounted") is False
        and live_guest.get("windowsNtfsMounted") is False
        and live_guest.get("networkAttached") is False
        and live_guest.get("efiVariablesWritable") is False,
        "VM, disk provenance, secure boot or unformatted partition proof missing",
    )
    esp, root = plan["partitions"]
    require(
        esp["index"] == 5 and root["index"] == 6
        and esp["uniqueGuid"] == after["popEsp"]["guid"]
        and root["uniqueGuid"] == after["linuxRoot"]["guid"]
        and esp["formatRequested"] is False
        and root["formatRequested"] is False,
        "native System76 selector does not refer to exactly owned partitions",
    )
    # NO executable argv or trusted shell command: the native writer is not
    # authorized until a cryptographically authenticated handoff and rollback
    # checkpoint have been implemented and tested in an isolated guest.
    return {
        "schemaVersion": 1,
        "scenario": "windows10_pop24_native_system76_handoff_candidate",
        "nativeBackend": "system76",
        "upstreamBootloaderUefi": "systemd-boot",
        "diskSerial": LAB_VIRTIO_SERIAL,
        "diskGuid": before["diskGuid"],
        "protectedWindowsPartitionIndexes": [1, 2, 3, 4],
        "ownedEsp": {
            "partitionIndex": 5,
            "partitionGuid": esp["uniqueGuid"],
            "mode": "reuse",
            "mount": "/boot/efi",
            "formatAllowed": False,
        },
        "ownedRoot": {
            "partitionIndex": 6,
            "partitionGuid": root["uniqueGuid"],
            "intendedFilesystem": "ext4",
            "mount": "/",
            "formatAllowed": False,
        },
        "nativeAgentSha256": media["distinstSha256"],
        "isoSha256": media["isoSha256"],
        "authenticatedWindowsToLiveHandoffVerified": False,
        "durableRecoveryCheckpointVerified": False,
        "efiNvrAMWriteAuthorized": False,
        "distinstExecutionAuthorized": False,
        "productionInstallationAuthorized": False,
        "popInstalled": False,
        "sameDiskDualBootVerified": False,
        "stable": False,
    }
