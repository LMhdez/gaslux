#!/usr/bin/env python3
"""Strict read-only ESP measurement from a *pinned RAW regular-file FD*.

This is deliberately not a QCOW2, host-device, VM or historical attestor.
Only disposable synthetic 128-GiB sparse RAW fixtures are accepted.
A caller's matching transaction/GPT claims are NOT signed provenance.

For production-grade QCOW2 provenance, independently tie a QMP block graph,
QEMU process generation and open FDs to a frozen, authenticated checkpoint.
Do not pass a QCOW2 container FD to os.pread as if it were a guest disk.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import uuid
from typing import Any

import cachyos_bcd_fat32_offline as fat
import windows_cachyos_qcow2_gpt_readonly as gpt

_TX = re.compile(r"^[0-9a-f]{32}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_KEYS = frozenset(("dev", "ino", "nlink", "size", "mtimeNs", "ctimeNs"))
_EXPECTED = frozenset((
    "scope", "transactionId", "checkpointSha256", "sectorBytes",
    "diskBytes", "diskGuid", "espPartuuid", "espStartLba", "espEndLba",
    "espSha256", "gptWindowsSha256", "sourceIdentity",
))
_QEMU = frozenset((
    "scope", "transactionId", "checkpointSha256", "traceSha256",
    "blkPointer", "qemuProcesses", "processAtEnd", "openFdAtStart",
    "openFdAtEnd", "selectedDiskIdentity", "backingSha256Before",
    "backingSha256After", "qmpNodeNames",
))
_PROC = frozenset(("pid", "startTicks", "uid", "executableSha256"))
ESP_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


class EspProvenanceError(ValueError):
    """A provenance precondition failed; do not use its output."""


def require(ok: bool, explanation: str) -> None:
    if not ok:
        raise EspProvenanceError(explanation)


def _sha(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _guid(value: object) -> str:
    require(type(value) is str, "invalid GUID/PARTUUID type")
    try:
        identifier = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise EspProvenanceError("invalid GUID/PARTUUID") from error
    require(identifier.int != 0 and str(identifier) == value,
            "invalid or noncanonical GUID/PARTUUID")
    return value


def _identity(st: os.stat_result) -> dict[str, int]:
    return {
        "dev": st.st_dev, "ino": st.st_ino, "nlink": st.st_nlink,
        "size": st.st_size, "mtimeNs": st.st_mtime_ns,
        "ctimeNs": st.st_ctime_ns,
    }


def _valid_identity(identity: object) -> bool:
    return (
        type(identity) is dict
        and set(identity) == _SOURCE_KEYS
        and all(type(x) is int and x >= 0 for x in identity.values())
        and identity["dev"] > 0
        and identity["ino"] > 0
        and identity["nlink"] == 1
        and identity["size"] == gpt.VIRTUAL_BYTES
    )


def _check_open_descriptor(fd: int, path: Path, pinned: dict) -> dict:
    require(type(fd) is int and fd >= 0 and isinstance(path, Path)
            and path.is_absolute(), "FD/path shape invalid")
    try:
        mode = fcntl.fcntl(fd, fcntl.F_GETFL)
        desc = os.fstat(fd)
        pathname = path.lstat()
    except OSError as exc:
        raise EspProvenanceError("open descriptor identity unavailable") from exc
    require(mode & os.O_ACCMODE == os.O_RDONLY,
            "descriptor is not read-only")
    require(stat.S_ISREG(desc.st_mode) and stat.S_ISREG(pathname.st_mode)
            and not path.is_symlink()
            and desc.st_uid == os.getuid()
            and pathname.st_uid == os.getuid()
            and stat.S_IMODE(desc.st_mode) == 0o400
            and desc.st_nlink == pathname.st_nlink == 1,
            "path identity, link, owner or permissions invalid")
    require(_valid_identity(pinned), "untrusted pinned FD identity")
    current = _identity(desc)
    require(current == pinned and _identity(pathname) == pinned,
            "open descriptor/path identity mismatch")
    return current


def _validate_windows_gpt_windows(
    front: bytes, back: bytes, expected: dict,
) -> dict[str, str | int]:
    """Reuse the audited lab GPT CRC readers; enforce ESP identity/geometry.

    Fixed 128 GiB/512-byte experimental lab only; no generic GPT parser.
    """
    require(len(front) == len(back) == gpt.WINDOW_BYTES,
            "incomplete primary/backup GPT windows")
    require(front[510:512] == b"\x55\xaa" and front[450] == 0xee
            and front[446] == 0 and all(
                not any(front[446 + i * 16:446 + (i + 1) * 16])
                for i in range(1, 4)
            ), "invalid protective MBR")
    mbr_first, mbr_count = struct.unpack_from("<II", front, 454)
    require(mbr_first == 1 and mbr_count in (
        gpt.VIRTUAL_BYTES // 512 - 1, 0xffffffff
    ), "invalid protective MBR size")
    total = gpt.VIRTUAL_BYTES // 512
    try:
        primary = gpt.header_at(front, 512, 1, total - 1, total)
        backup = gpt.header_at(
            back, gpt.WINDOW_BYTES - 512, total - 1, 1, total
        )
        first = gpt.part_array(primary, front, back, total)
        second = gpt.part_array(backup, front, back, total)
    except (gpt.GeometryError, ValueError, struct.error) as exc:
        raise EspProvenanceError("GPT header/entry CRC or geometry invalid") from exc
    require(first == second and primary[56:72] == backup[56:72]
            and primary[40:56] == backup[40:56]
            and primary[80:92] == backup[80:92]
            and struct.unpack_from("<Q", primary, 72)[0] == 2
            and struct.unpack_from("<Q", backup, 72)[0] == total - 33,
            "GPT primary/backup mirror differs")
    actual_disk_guid = str(uuid.UUID(bytes_le=primary[56:72]))
    require(actual_disk_guid == expected["diskGuid"],
            "GPT disk GUID differs from pinned expectation")
    require(hashlib.sha256(front + back).hexdigest()
            == expected["gptWindowsSha256"], "GPT window hashes diverge")
    first_usable, last_usable = struct.unpack_from("<QQ", primary, 40)
    seen: set[str] = set()
    spans: list[tuple[int, int]] = []
    active = 0
    esp_partuuid = ""
    for i in range(128):
        rec = first[i * 128:(i + 1) * 128]
        if not any(rec[:16]):
            require(not any(rec), "invalid unused GPT entry")
            continue
        require(i < 5, "extra non-Gaslux GPT partition detected")
        guid = str(uuid.UUID(bytes_le=rec[16:32]))
        partition_type = str(uuid.UUID(bytes_le=rec[:16]))
        first_lba, last_lba = struct.unpack_from("<QQ", rec, 32)
        require(guid not in seen and first_usable <= first_lba <= last_lba
                <= last_usable, "PARTUUID duplicate or GPT partition out of bounds")
        seen.add(guid)
        spans.append((first_lba, last_lba + 1))
        active += 1
        if i == 0:
            require(partition_type == ESP_GUID,
                    "GPT partition #1 is not a Microsoft ESP")
            require(first_lba == expected["espStartLba"]
                    and last_lba == expected["espEndLba"],
                    "GPT ESP partition geometry differs")
            esp_partuuid = guid
        if 1 <= i < 4:
            require(partition_type == gpt.TYPES[i],
                    "Windows GPT partition type changed")
        if i == 4:
            require(partition_type ==
                    "0fc63daf-8483-4772-8e79-3d69d8477de4",
                    "unowned Linux partition type")
    spans.sort()
    require(active in (4, 5)
            and all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))
            and esp_partuuid == expected["espPartuuid"],
            "ESP PARTUUID or GPT partition extent/ownership mismatch")
    return {
        "diskGuid": actual_disk_guid,
        "espPartuuid": esp_partuuid,
        "partitionCount": active,
    }


def measure_esp_from_pinned_raw_fd(
    fd: int, path: Path, expected: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Measure synthetic RAW ESP from caller's already-open O_RDONLY FD.

    Checks describe consistency of *claims* with bytes. A path, open FD and
    caller-supplied checkpoint are not an independently signed VM attestation.
    Never call this method on host block devices, QCOW2 or Windows media.
    """
    require(type(expected) is dict and set(expected) == _EXPECTED
            and expected["scope"] == "DISPOSABLE_SYNTHETIC_RAW_ONLY"
            and type(expected["transactionId"]) is str
            and _TX.fullmatch(expected["transactionId"]) is not None
            and _sha(expected["checkpointSha256"])
            and _sha(expected["espSha256"])
            and _sha(expected["gptWindowsSha256"])
            and type(expected["sectorBytes"]) is int
            and expected["sectorBytes"] == 512
            and type(expected["diskBytes"]) is int
            and expected["diskBytes"] == gpt.VIRTUAL_BYTES
            and all(type(expected[x]) is int and expected[x] >= 0
                    for x in ("espStartLba", "espEndLba"))
            and expected["espStartLba"] <= expected["espEndLba"],
            "unsafe synthetic-only source claim, transaction or geometry")
    _guid(expected["diskGuid"])
    _guid(expected["espPartuuid"])
    before = _check_open_descriptor(fd, path, expected["sourceIdentity"])
    offset = expected["espStartLba"] * 512
    length = (expected["espEndLba"] + 1) * 512 - offset
    require(512 * 80 <= length <= fat.MAX_ESP_BYTES
            and offset > 0 and offset + length <= gpt.VIRTUAL_BYTES,
            "ESP physical range outside fixed synthetic disk")
    try:
        front = os.pread(fd, gpt.WINDOW_BYTES, 0)
        back = os.pread(
            fd, gpt.WINDOW_BYTES, gpt.VIRTUAL_BYTES - gpt.WINDOW_BYTES
        )
        require(front[:4] != b"QFI\xfb",
                "QCOW2 format requires pinned QEMU virtual-block reader")
        gpt_identity = _validate_windows_gpt_windows(front, back, expected)
        volume = os.pread(fd, length, offset)
        require(len(volume) == length, "incomplete ESP capture")
        esp_digest = hashlib.sha256(volume).hexdigest()
        require(esp_digest == expected["espSha256"],
                "ESP capture hash diverges from pinned expectation")
        mapped = fat.map_bcd_fat32(
            volume, esp_start_lba=expected["espStartLba"],
            esp_end_lba=expected["espEndLba"], disk_bytes=gpt.VIRTUAL_BYTES,
        )
        # A second byte-exact read, not only a marker, detects common
        # in-place changes. Snapshot isolation is still NOT independently
        # proven and an adversarial write+restore race can evade readback.
        volume_after = os.pread(fd, length, offset)
        front_after = os.pread(fd, gpt.WINDOW_BYTES, 0)
        back_after = os.pread(
            fd, gpt.WINDOW_BYTES, gpt.VIRTUAL_BYTES - gpt.WINDOW_BYTES
        )
        require(volume_after == volume and front_after == front
                and back_after == back, "ESP/GPT bytes changed during measurement")
        _check_open_descriptor(fd, path, before)
    except (OSError, fat.Fat32MapError, gpt.GeometryError) as exc:
        raise EspProvenanceError(
            "read-only ESP/GPT measurement failed or structurally invalid"
        ) from exc
    report = {
        "status": "SYNTHETIC_RAW_FD_MEASURED_DENY_ONLY",
        "transactionId": expected["transactionId"],
        "checkpointSha256": expected["checkpointSha256"],
        "diskGuid": gpt_identity["diskGuid"],
        "espPartuuid": gpt_identity["espPartuuid"],
        "partitionCount": gpt_identity["partitionCount"],
        "diskBytes": gpt.VIRTUAL_BYTES,
        "sectorBytes": 512,
        "espStartLba": expected["espStartLba"],
        "espEndLba": expected["espEndLba"],
        "espOffsetBytes": offset,
        "espLengthBytes": length,
        "espSha256": esp_digest,
        "gptWindowsSha256": expected["gptWindowsSha256"],
        "sourceDescriptorIdentity": before,
        "twoPassEspBytesEqual": True,
        "primaryBackupGptConsistent": True,
        "historicalEspProvenanceAuthenticated": False,
        "qemuBlkNodeToDiskAuthenticated": False,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
        "releaseEligible": False,
    }
    return report, mapped


def _process(record: object) -> bool:
    return type(record) is dict and set(record) == _PROC and all(
        type(record[x]) is int and record[x] >= (2 if x == "pid" else 0)
        for x in ("pid", "startTicks", "uid")
    ) and record["startTicks"] > 0 and _sha(record["executableSha256"])


def evaluate_untrusted_qemu_claim(parsed: dict, claim: dict) -> dict:
    """Refuse inconsistent source claims; never authenticate trace blk IDs.

    No QMP node name, PID, /proc pathname or blk hex string alone is a
    cryptographic/FD-proven QEMU→Windows disk→trace pointer association.
    """
    require(type(parsed) is dict and
            parsed.get("sourceHasDiskIdentityAttestation") is False
            and parsed.get("processAttributionProven") is False
            and type(parsed.get("records")) is list
            and len(parsed["records"]) > 0
            and type(parsed.get("blkPointers")) is dict
            and _sha(parsed.get("traceSha256")),
            "QEMU trace missing provenance or truncated")
    require(type(claim) is dict and set(claim) == _QEMU
            and claim["scope"] == "HOST_OBSERVATION_UNVERIFIED"
            and type(claim["transactionId"]) is str
            and _TX.fullmatch(claim["transactionId"]) is not None
            and _sha(claim["checkpointSha256"])
            and claim["traceSha256"] == parsed["traceSha256"]
            and type(claim["blkPointer"]) is str
            and claim["blkPointer"] in parsed["blkPointers"],
            "QEMU trace claim missing or unbound to a parsed trace")
    require(type(claim["qemuProcesses"]) is list
            and len(claim["qemuProcesses"]) == 1
            and _process(claim["qemuProcesses"][0])
            and _process(claim["processAtEnd"])
            and claim["qemuProcesses"][0] == claim["processAtEnd"],
            "QEMU process/PID generation ambiguous or changed")
    for name in ("openFdAtStart", "openFdAtEnd",
                 "selectedDiskIdentity"):
        require(_valid_identity(claim[name]),
                "selected QEMU disk FD identity invalid")
    require(claim["openFdAtStart"] == claim["openFdAtEnd"]
            == claim["selectedDiskIdentity"],
            "selected QEMU descriptor identity changed or wrong disk")
    require(_sha(claim["backingSha256Before"])
            and claim["backingSha256Before"] ==
            claim["backingSha256After"],
            "QEMU backing hash changed or unproven")
    require(type(claim["qmpNodeNames"]) is list
            and len(claim["qmpNodeNames"]) == 1
            and type(claim["qmpNodeNames"][0]) is str
            and re.fullmatch(r"[A-Za-z0-9_-]{1,64}",
                             claim["qmpNodeNames"][0]) is not None,
            "QEMU QMP node graph ambiguous or unbounded")
    return {
        "status": "QEMU_PROCESS_FD_CONSISTENT_BLK_POINTER_UNBOUND",
        "transactionId": claim["transactionId"],
        "checkpointSha256": claim["checkpointSha256"],
        "traceSha256": parsed["traceSha256"],
        "qmpNodeNameCount": 1,
        "processGenerationClaimConsistent": True,
        "fdIdentityClaimConsistent": True,
        "backingClaimConsistent": True,
        "qmpNodeToProcFdAuthenticated": False,
        "qemuBlkNodeToDiskAuthenticated": False,
        "processAttributionProven": False,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
        "releaseEligible": False,
        "remainingBoundary": "QMP_NODE_TO_OPEN_FD_AND_TRACE_BLK_POINTER_UNPROVEN",
    }
