#!/usr/bin/env python3
"""Fail-closed, READ-ONLY candidate for Archiso on a Windows-backed fifth GPT.

This gate is documentary, not an authenticated guest disk identity.
It MUST NOT authorize pacstrap, mkfs, ESP/BCD writes or any physical disk I/O.
The existing blank-disk QEMU installer is incompatible with shared Windows GPT.
"""
from __future__ import annotations

import re
from uuid import UUID

from windows_cachyos_qcow2_gpt_readonly import VIRTUAL_BYTES, SECTOR, TYPES
from windows_cachyos_overlay_gpt_stage import LINUX_TYPE, LINUX_SIZE_BYTES

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_OWNER = re.compile(r"[A-Za-z0-9_-]{12,100}\Z")


class SharedDiskGateError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SharedDiskGateError(message)


def guid(value: object, message: str) -> str:
    require(type(value) is str, message)
    try:
        normalized = str(UUID(value))
    except (ValueError, AttributeError) as exc:
        raise SharedDiskGateError(message) from exc
    require(normalized == value.lower() and UUID(value).int != 0, message)
    return normalized


def candidate(geometry: dict, checkpoint: dict, stage: dict,
              third: dict, ext4: dict, fourth: dict,
              *, transaction: str, iso_sha256: str) -> dict:
    """Validate staged evidence without granting live Archiso disk mutation."""
    require(type(transaction) is str and _OWNER.fullmatch(transaction) is not None,
            "missing validated transaction id")
    require(type(iso_sha256) is str and _SHA.fullmatch(iso_sha256) is not None,
            "missing SHA-256 pin for official CachyOS Archiso")
    require(all(type(v) is dict for v in
                (geometry, checkpoint, stage, third, ext4, fourth)),
            "missing same-run Windows/COW evidence objects")

    require(
        geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True
        and geometry.get("virtualDiskBytes") == VIRTUAL_BYTES
        and geometry.get("sectorBytes") == SECTOR
        and geometry.get("storageWritesAuthorized") is False
        and geometry.get("releaseEligible") is False
        and type(geometry.get("diskGuidSha256")) is str
        and _SHA.fullmatch(geometry["diskGuidSha256"]) is not None,
        "not the expected intact Windows 10 GPT geometry",
    )
    parts = geometry.get("windowsPartitions")
    require(type(parts) is list and len(parts) == 4,
            "Windows ESP/MSR/NTFS/WinRE partition count changed")
    previous_end = -1
    for i, item in enumerate(parts):
        require(
            type(item) is dict
            and item.get("index") == i + 1
            and type(item.get("firstLba")) is int
            and type(item.get("lastLba")) is int
            and item.get("type") == TYPES[i]
            and item["firstLba"] > previous_end
            and item["lastLba"] >= item["firstLba"]
            and item.get("lengthBytes") ==
                (item["lastLba"] - item["firstLba"] + 1) * SECTOR,
            "Windows partition GUID, sequence or geometry mismatch",
        )
        previous_end = item["lastLba"]

    require(
        checkpoint.get("candidateWindowsCowCheckpointPrepared") is True
        and checkpoint.get("trialOverlayInitiallyMatchesWindows") is True
        and checkpoint.get("windowsBaselineUnchangedDuringCheckpoint") is True
        and checkpoint.get("snapshotIndependentlyRestorable") is False
        and checkpoint.get("storageWritesAuthorized") is False
        and checkpoint.get("releaseEligible") is False,
        "missing protected Windows backing/COW checkpoint",
    )
    root = stage.get("linuxRoot")
    require(
        type(root) is dict
        and stage.get("overlayGptLinuxRootEntryPrepared") is True
        and stage.get("onlyDisposableOverlayModified") is True
        and stage.get("windowsPartitionEntriesUnchanged") is True
        and stage.get("bothGptMirrorsAfterStageVerified") is True
        and stage.get("windowsBackingQcow2Unchanged") is True
        and stage.get("windowsUefiVariablesUnchanged") is True
        and stage.get("linuxRootFilesystemFormatted") is False
        and stage.get("cachyosInstalled") is False
        and stage.get("storageWritesAuthorized") is False
        and stage.get("releaseEligible") is False,
        "missing fifth GPT-only stage identity",
    )
    require(
        root.get("index") == 5
        and root.get("typeGuid") == LINUX_TYPE
        and root.get("lengthBytes") == LINUX_SIZE_BYTES
        and type(root.get("firstLba")) is int
        and type(root.get("lastLba")) is int
        and root["firstLba"] % (1024 * 1024 // SECTOR) == 0
        and root["firstLba"] > previous_end
        and root["lastLba"] - root["firstLba"] + 1 == LINUX_SIZE_BYTES // SECTOR
        and type(root.get("remainingUnallocatedAfterLinuxBytes")) is int
        and root["remainingUnallocatedAfterLinuxBytes"] >= 16 * 1024**3
        and root["lastLba"] < VIRTUAL_BYTES // SECTOR - 33,
        "fifth partition outside the exact owned 24-GiB extent",
    )
    root_guid = guid(root.get("uniqueGuid"), "missing fifth GPT PARTUUID")
    require(
        third.get("windowsBootAfterOverlayMutationVerified") is True
        and third.get("guestBcdWinreEspAfterOverlayVerified") is True
        and third.get("windowsGuestShutdownAfterOverlayVerified") is True
        and third.get("fifthGptUnchangedAfterGuestBoot") is True
        and third.get("windowsBackingUnchangedAfterGuestBoot") is True
        and third.get("originalUefiVarsUnchangedAfterGuestBoot") is True
        and third.get("sameDiskDualBootVerified") is False
        and third.get("releaseEligible") is False,
        "third native Windows GPT/BCD/WinRE boot not attested",
    )
    filesystem = ext4.get("rootFilesystem")
    require(
        type(filesystem) is dict
        and ext4.get("linuxRoot") == root
        and ext4.get("onlyOwnedOverlayFifthPartitionFormatted") is True
        and ext4.get("linuxRootFilesystemFormatted") is True
        and ext4.get("windowsBackingQcow2UnchangedAfterExt4") is True
        and ext4.get("windowsOriginalUefiUnchangedAfterExt4") is True
        and ext4.get("cachyosInstalled") is False
        and ext4.get("windowsRecoveryAfterLinuxVerified") is False
        and ext4.get("storageWritesAuthorized") is False
        and ext4.get("releaseEligible") is False
        and filesystem.get("filesystemType") == "ext4"
        and filesystem.get("allFourWindowsPartitionSha256Unchanged") is True
        and filesystem.get("gptMirrorsByteIdenticalAfterExt4") is True,
        "fifth ext4 stage or protected Windows evidence missing",
    )
    windows_hashes = filesystem.get("windowsFourPartitionSha256")
    require(
        type(windows_hashes) is list and len(windows_hashes) == 4
        and all(type(h) is str and _SHA.fullmatch(h) for h in windows_hashes),
        "missing all four full Windows partition hashes",
    )
    root_uuid = guid(filesystem.get("filesystemUuid"),
                     "invalid fifth ext4 filesystem UUID")
    require(
        fourth.get("windowsBootAfterExt4Verified") is True
        and fourth.get("windowsBcdWinreEspAfterExt4Verified") is True
        and fourth.get("fourthGuestCleanShutdownVerified") is True
        and fourth.get("fifthExt4UuidSurvivedWindowsBoot") is True
        and fourth.get("windowsGptUnchangedAfterExt4Boot") is True
        and fourth.get("windowsBackingUnchangedAfterExt4Boot") is True
        and fourth.get("originalWindowsUefiUnchangedAfterExt4Boot") is True
        and fourth.get("cachyosInstalled") is False
        and fourth.get("windowsRecoveryAfterLinuxVerified") is False
        and fourth.get("storageWritesAuthorized") is False
        and fourth.get("releaseEligible") is False,
        "real fourth Windows boot after ext4 did not pass",
    )
    # Documentary handoff only. A separately authenticated Archiso guest must
    # prove this partition's physical GPT and filesystem identity in situ,
    # with protected Windows hashes and a durable recovery plan, BEFORE pacstrap.
    return {
        "schemaVersion": 1,
        "transaction": transaction,
        "archisoSha256": iso_sha256,
        "windowsDiskGuidSha256": geometry["diskGuidSha256"],
        "windowsPartitionCount": 4,
        "windowsPartitionSha256": windows_hashes,
        "rootPartitionIndex": 5,
        "rootPartitionGuid": root_guid,
        "rootFilesystemUuid": root_uuid,
        "rootLengthBytes": LINUX_SIZE_BYTES,
        "candidateWindowsFirstBootAndFourthBootVerified": True,
        "candidatePreparedFromSameRunWindowsCOW": True,
        "archisoGuestDiskIdentityVerified": False,
        "handoffAuthenticated": False,
        "archisoWriteAuthorized": False,
        "pacstrapExecuted": False,
        "cachyosInstalled": False,
        "linuxFirstBootVerified": False,
        "windowsRecoveryAfterLinuxVerified": False,
        "rollbackProven": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library-only preflight; no host devices or live installer")
