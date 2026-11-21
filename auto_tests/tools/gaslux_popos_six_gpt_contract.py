#!/usr/bin/env python3
"""INERT six-GPT System76 reuse write-set; no installer and no Windows image.

All regions are synthetic. Reuse the proven Pop QCOW2/gate helpers. GPT is
decoded by sfdisk and checked by sgdisk, never by another Python GPT parser.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from gaslux_popos_reuse_snapshot_gate import Refusal, WRITE, UNSAFE, need

SECTOR = 512
SIZE = 32 * 1024**3
COUNT = SIZE // SECTOR
SERIAL = "GASLUXPOPSIXGPT"
DISK_GUID = "81ab6d0e-0f88-4923-a24b-8748f15890e1"
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
MSR_TYPE = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
DATA_TYPE = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
RECOVERY_TYPE = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
ROOT_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
ISO_SHA256 = "a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c"
DISTINST_SHA256 = "8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5"
SYSTEM76_GPG_FPR = "63C46DF0140D738961429F4E204DD8AEC33A7AFF"
SCENARIO = "pop-synthetic-six-gpt-preflight-only-v1"
CONSENT = "I_ACCEPT_DISPOSABLE_SIX_GPT_PREFLIGHT_ONLY"
HASH = re.compile(r"[0-9a-f]{64}\Z")
GUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


@dataclass(frozen=True)
class Partition:
    index: int
    role: str
    start: int
    count: int
    type_guid: str
    partuuid: str
    owned: bool

    @property
    def end(self) -> int:
        return self.start + self.count - 1

    def as_dict(self) -> dict:
        return {
            "number": self.index, "role": self.role, "startLba": self.start,
            "endLba": self.end, "offsetBytes": self.start * SECTOR,
            "lengthBytes": self.count * SECTOR, "typeGuid": self.type_guid,
            "partuuid": self.partuuid, "ownedByPopTransaction": self.owned,
        }


def part(number: int, role: str, start: int, mib: int,
         type_guid: str, owned: bool) -> Partition:
    return Partition(
        number, role, start, mib * 2048, type_guid,
        f"c900f2a6-6f9b-4aa9-9af0-bd5d824417{number:02d}", owned,
    )


PARTS = (
    part(1, "simulated-protected-esp", 2048, 260, ESP_TYPE, False),
    part(2, "simulated-protected-msr", 534528, 16, MSR_TYPE, False),
    part(3, "simulated-protected-data", 567296, 512, DATA_TYPE, False),
    part(4, "simulated-protected-recovery", 1615872, 768, RECOVERY_TYPE, False),
    part(5, "owned-pop-esp", 3188736, 1024, ESP_TYPE, True),
    part(6, "owned-pop-ext4-root", 5285888, 28672, ROOT_TYPE, True),
)
PROTECTED = PARTS[:4]
OWNED = PARTS[4:]
# PMBR + both GPT tables and unallocated sectors are always excluded.
UNALLOCATED_CANARIES = (64, 1024, 64006144, COUNT - 64)
PROTECTED_ESP_FILE = "::/EFI/Microsoft/GASLUX-SIMULATED-PROTECTED-CANARY.txt"
BOOLEANS = {
    "distinstExecutionAuthorized": False,
    "productionInstallationAuthorized": False,
    "windowsWriterAuthorized": False,
    "sameDiskDualBootVerified": False,
    "windowsInPlaceRollbackProven": False,
    "releaseEligible": False,
    "stable": False,
}


def validate_geometry() -> None:
    need(len(PARTS) == 6
         and [p.index for p in PARTS] == list(range(1, 7))
         and [p.owned for p in PARTS] == [False]*4 + [True]*2,
         "REFUSE_IDENTITY_MISMATCH: six-GPT contract missing")
    need(PARTS[0].start >= 2048 and PARTS[-1].end < COUNT - 33,
         "REFUSE_IDENTITY_MISMATCH: GPT reserved sectors overlapped")
    for previous, current in zip(PARTS, PARTS[1:]):
        need(previous.end < current.start and current.start % 2048 == 0,
             "REFUSE_IDENTITY_MISMATCH: partition overlap/misalignment")
    need(PARTS[5].count * SECTOR >= 28 * 1024**3,
         "REFUSE_IDENTITY_MISMATCH: root not sized for proven full install")
    for sector in UNALLOCATED_CANARIES:
        need(34 <= sector < COUNT - 33
             and not any(p.start <= sector <= p.end for p in PARTS),
             "REFUSE_IDENTITY_MISMATCH: unallocated canary overlaps partitions")


def canonical_digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def validate_plan(plan: dict, transaction_id: str) -> None:
    validate_geometry()
    need(type(plan) is dict and plan.get("schemaVersion") == 1
         and plan.get("scenario") == SCENARIO
         and type(transaction_id) is str
         and re.fullmatch(r"[a-f0-9-]{36}", transaction_id) is not None
         and plan.get("transactionId") == transaction_id,
         "REFUSE_IDENTITY_MISMATCH: missing/foreign transaction")
    need(plan.get("disk") == {
        "sizeBytes": SIZE, "logicalSectorBytes": SECTOR,
        "guid": DISK_GUID, "virtioSerial": SERIAL,
    } and plan.get("partitions") == [p.as_dict() for p in PARTS],
         "REFUSE_IDENTITY_MISMATCH: disk/partition identity changed")
    need(plan.get("media") == {
        "isoSha256": ISO_SHA256, "distinstSha256": DISTINST_SHA256,
        "system76GpgFingerprint": SYSTEM76_GPG_FPR,
        "isoIndependentlyAuthenticatedHere": False,
    } and plan.get("distinstReuseArgv") == [
        "--no-efi-vars", "--use", ":5:reuse:mount=/boot/efi",
        "--use", ":6:reuse:mount=/",
    ], "REFUSE_IDENTITY_MISMATCH: unsigned or foreign distinst plan")
    need(all(plan.get(k) is v for k, v in BOOLEANS.items())
         and plan.get("windowsAttached") is False
         and plan.get("physicalDisksAttached") is False
         and plan.get("onlyWritableGuestDisk") == "owned-qcow2-child"
         and plan.get("recoveryMode") == "discard-private-child-recreate",
         "REFUSE_IDENTITY_MISMATCH: illegal write/boot authority")
    need(type(plan.get("backingSha256")) is str
         and HASH.fullmatch(plan["backingSha256"]) is not None
         and type(plan.get("gpt")) is dict
         and all(HASH.fullmatch(plan["gpt"].get(k, "")) is not None
                 for k in ("pmbrAndPrimary", "secondary"))
         and type(plan.get("protectedPartitionHashes")) is dict
         and set(plan["protectedPartitionHashes"]) == {"1", "2", "3", "4"}
         and all(HASH.fullmatch(h) for h in plan["protectedPartitionHashes"].values())
         and type(plan.get("canaries")) is list and len(plan["canaries"]) == 7
         and all(type(v) is dict
                 and set(v) == {"lba", "role", "sectorSha256"}
                 and v["lba"] == sector and v["role"] == role
                 and type(v["sectorSha256"]) is str
                 and HASH.fullmatch(v["sectorSha256"]) is not None
                 for v, (sector, role) in zip(plan["canaries"], (
                     (534536, "protected-msr"), (567304, "protected-data"),
                     (1615880, "protected-recovery"), (64, "unallocated"),
                     (1024, "unallocated"), (64006144, "unallocated"),
                     (67108800, "unallocated"),
                 )))
         and type(plan.get("protectedEspFileSha256")) is str
         and HASH.fullmatch(plan["protectedEspFileSha256"]) is not None
         and type(plan.get("ovmfTemplateSha256")) is str
         and HASH.fullmatch(plan["ovmfTemplateSha256"]) is not None,
         "REFUSE_IDENTITY_MISMATCH: manifest evidence missing")
    expected = canonical_digest({k: v for k, v in plan.items() if k != "manifestSha256"})
    need(plan.get("manifestSha256") == expected,
         "REFUSE_IDENTITY_MISMATCH: replay/modified plan digest")


def classify_sector_write(start: int, count: int) -> int:
    need(type(start) is int and type(count) is int
         and start >= 0 and count > 0 and start + count <= COUNT,
         "REFUSE_OUT_OF_WRITESET: malformed sector extent")
    for p in OWNED:
        if p.start <= start and start + count - 1 <= p.end:
            return p.index
    raise Refusal("REFUSE_OUT_OF_WRITESET: GPT/protected/unallocated write")


def audit_qemu_trace(trace: str) -> dict:
    """External request locations only; never claim individual I/O completion.

    When a six-GPT QEMU is eventually approved, it must have exactly one
    writable virtio device bound to this transaction's private child.
    """
    need(type(trace) is str and 0 < len(trace) < 128_000_000,
         "OBSERVATION_INCOMPLETE: QEMU trace absent/oversized")
    writes = {5: 0, 6: 0}
    bytes_written = 0
    vars_events = 0
    for line in trace.splitlines():
        need(UNSAFE.search(line) is None,
             "REFUSE_OUT_OF_WRITESET: discard/zero/unmapped write")
        if "pflash_" in line and "system.flash" in line:
            vars_events += 1
        if "virtio_blk_handle_" in line and (
            "discard" in line or "write_zeroes" in line
        ):
            raise Refusal("REFUSE_OUT_OF_WRITESET: unapproved block command")
        if "virtio_blk_handle_write" not in line:
            continue
        match = WRITE.search(line)
        need(match is not None, "OBSERVATION_INCOMPLETE: malformed write request")
        sector, count = int(match[1]), int(match[2])
        writes[classify_sector_write(sector, count)] += 1
        bytes_written += count * SECTOR
    need(sum(writes.values()) > 0, "OBSERVATION_INCOMPLETE: no QEMU write witness")
    return {
        "observedWritesConfinedToOwnedPopPartitions": True,
        "writesByPartition": {"5": writes[5], "6": writes[6]},
        "observedBytes": bytes_written, "outOfWriteSetRequests": 0,
        "pflashEventsSeen": vars_events, "observationComplete": False,
        "guestBioCompletionVerified": False,
        "ovmfTransientWritesProvenAbsent": False,
        **BOOLEANS,
    }
