#!/usr/bin/env python3
"""Read-only Pop!_OS UEFI plan for TWO owned partitions after genuine Windows 10.

No GPT, MBR, ESP, filesystem or firmware write occurs in this module.
The caller must separately authenticate the Windows client and both GPT mirrors.
This is a hosted-QEMU feasibility proposal, never production authorization.
"""
from __future__ import annotations

import uuid

from windows10_popos_same_disk_overlay_stage import (
    GIB, MIB, SECTOR, WINDOWS_TYPES, candidate_plan,
)
from windows10_popos_gpt_mirror_gate import (
    ESP, LINUX_TYPE, ROOT_LABEL, TOTAL_BYTES, DiskAuditError, require,
)

POP_ESP_SIZE = GIB
POP_ROOT_SIZE = 24 * GIB
POP_ESP_NAME = "GASLUX-LAB-POP-ESP"
POP_ROOT_NAME = ROOT_LABEL
ALIGN_SECTORS = MIB // SECTOR


def propose_owned_esp_root(
    windows: dict, gpt: dict, esp_guid: uuid.UUID, root_guid: uuid.UUID,
) -> dict:
    """Derive a *non-executable* plan only from verified Windows/GPT evidence."""
    original = candidate_plan(windows)
    require(
        type(gpt) is dict
        and gpt.get("primaryAndBackupCrcVerified") is True
        and gpt.get("productionInstallationAuthorized") is False
        and gpt.get("linuxRoot") is None
        and type(gpt.get("windowsPartitions")) is list
        and len(gpt["windowsPartitions"]) == 4
        and gpt.get("mbrSha256") is not None,
        "genuine Windows original GPT mirrors not independently verified",
    )
    for n, (source, recorded) in enumerate(
        zip(windows["partitions"], gpt["windowsPartitions"]), 1
    ):
        require(
            recorded.get("number") == n
            and recorded.get("type") == WINDOWS_TYPES[n-1]
            and source.get("offsetBytes") == recorded.get("startLba", -1) * SECTOR
            and source.get("sizeBytes")
            == (recorded.get("endLba", -1) - recorded.get("startLba", 0) + 1) * SECTOR
            and (source.get("partitionGuid") is None
                 or source["partitionGuid"].lower() == recorded.get("guid")),
            "Windows libguestfs partition identity disagrees with GPT mirrors",
        )
    require(
        type(esp_guid) is uuid.UUID and type(root_guid) is uuid.UUID
        and esp_guid.int != 0 and root_guid.int != 0 and esp_guid != root_guid,
        "distinct explicit transaction-owned partition GUIDs required",
    )
    require(
        str(esp_guid) not in {p["guid"] for p in gpt["windowsPartitions"]}
        and str(root_guid) not in {p["guid"] for p in gpt["windowsPartitions"]},
        "owned Pop partition GUID collides with Windows GPT",
    )
    esp_start = original["startSector"]
    esp_end = esp_start + POP_ESP_SIZE // SECTOR - 1
    root_start = ((esp_end + 1 + ALIGN_SECTORS - 1) // ALIGN_SECTORS) * ALIGN_SECTORS
    root_end = root_start + POP_ROOT_SIZE // SECTOR - 1
    require(
        esp_start % ALIGN_SECTORS == 0 and root_start % ALIGN_SECTORS == 0
        and esp_end < root_start
        and root_end + 2 * ALIGN_SECTORS < TOTAL_BYTES // SECTOR - 33
        and root_end <= gpt["lastUsableLba"]
        and esp_start > gpt["windowsPartitions"][-1]["endLba"]
        and original["sizeBytes"] == POP_ROOT_SIZE,
        "insufficient strictly unallocated Windows GPT tail for separate Pop ESP/root",
    )
    return {
        "schemaVersion": 1,
        "scenario": "windows10_readonly_independent_pop_esp_root_proposal",
        "firmware": "uefi",
        "partitionStyle": "gpt",
        "windowsDiskGuid": gpt["diskGuid"],
        "windowsProtectiveMbrSha256": gpt["mbrSha256"],
        "windowsPrimaryAndBackupGptCrcVerified": True,
        "partitions": [
            {
                "index": 5,
                "typeGuid": ESP,
                "uniqueGuid": str(esp_guid),
                "name": POP_ESP_NAME,
                "startSector": esp_start,
                "endSector": esp_end,
                "sizeBytes": POP_ESP_SIZE,
                "formatRequested": False,
            },
            {
                "index": 6,
                "typeGuid": LINUX_TYPE,
                "uniqueGuid": str(root_guid),
                "name": POP_ROOT_NAME,
                "startSector": root_start,
                "endSector": root_end,
                "sizeBytes": POP_ROOT_SIZE,
                "formatRequested": False,
            },
        ],
        "windowsEspToRemainUntouched": True,
        "windowsBootManagerToRemainUntouched": True,
        "secureBootVerified": False,
        "signedHandoffVerified": False,
        "linuxSystemInstalled": False,
        "sameDiskDualBootVerified": False,
        "productionInstallationAuthorized": False,
        "stable": False,
    }
