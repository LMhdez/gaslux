#!/usr/bin/env python3
"""Independent QEMU virtio-blk write-request trace contract, SYNTHETIC ONLY.

No disk writer and no authorization to run distinst on Windows. The QEMU
hypervisor, not an installer log, emits virtio_blk_handle_write requests.
Capture is not complete if other devices/writers, discards, zero-writes or
NVRAM effects are uninstrumented. Compare with raw-image changed bytes
separately: final diffs cannot see transient requests.
"""
from __future__ import annotations

import hashlib
import json
import re

from windows_x64_installed_gpt_ro_audit import require

SECTOR = 512
SERIAL = "GASLUX_POP_SYNTH"
DISK_SIZE = 8 * 1024**3
SMOKE_OFFSET = 96 * 1024 * 1024
SMOKE_LENGTH = 4096
SYNTH_GUID = "a6784e03-11a6-4544-b61c-87b66db8e117"
# Source QEMU's hw/block/trace-events:
# virtio_blk_handle_write(void *vdev, void *req, uint64_t sector, size_t nsectors)
# "vdev %p req %p sector %"PRIu64" nsectors %zu"
WRITE_EVENT = re.compile(
    r"\bvirtio_blk_handle_write\b[^\r\n]{0,250}?"
    r"\bsector (?P<sector>[0-9]+) nsectors (?P<count>[0-9]+)(?=\s|$)"
)
# These have different origin/format and cannot be ignored as successful trace.
UNKNOWN_WRITE = re.compile(
    r"\b(?:virtio_blk_handle_write|virtio_blk_handle_discard|"
    r"virtio_blk_handle_write_zeroes|blk_co_pwritev|bdrv_co_pwritev)\b"
)
HASH = re.compile(r"[a-f0-9]{64}\Z")
PFLASH_WRITE = re.compile(
    r"\bpflash_(?:data_write|data_write_block|io_write|write_block_erase|"
    r"write_block_start|write_block_flush|write_block_abort|write|write_failed)\b"
)
GUID = re.compile(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\Z")


def synthetic_plan(disk_guid: str, esp_partuuid: str, root_partuuid: str,
                   base_sha256: str, expected_child: str) -> dict:
    """Typed inert plan for completely synthetic, disposable 8-GiB disk."""
    require(GUID.fullmatch(disk_guid) is not None
            and GUID.fullmatch(esp_partuuid) is not None
            and GUID.fullmatch(root_partuuid) is not None
            and disk_guid != esp_partuuid != root_partuuid
            and type(base_sha256) is str and HASH.fullmatch(base_sha256)
            and type(expected_child) is str
            and expected_child == "gaslux-pop-synthetic-write-child.qcow2",
            "synthetic disk identity or backing checkpoint missing")
    return {
        "schemaVersion": 1, "scenario": "isolated-pop-synthetic-qemu-smoke",
        "purpose": "observe-guest-write-request-only",
        "serial": SERIAL, "diskGuid": disk_guid,
        "sizeBytes": DISK_SIZE, "logicalSectorBytes": SECTOR,
        "esp": {"partitionIndex": 1, "partuuid": esp_partuuid,
                "offsetBytes": 1024**2, "lengthBytes": 64 * 1024**2},
        "root": {"partitionIndex": 2, "partuuid": root_partuuid,
                 "offsetBytes": 128 * 1024**2, "lengthBytes": 2 * 1024**3},
        "expectedOperation": {
            "process": "python3", "operation": "guest-block-write-smoke",
            "offsetBytes": SMOKE_OFFSET, "lengthBytes": SMOKE_LENGTH,
            "intervalType": "unallocated-synthetic-only",
        },
        "baseSha256": base_sha256, "childName": expected_child,
        "windowsDiskAttached": False, "productionInstallationAuthorized": False,
        "distinstExecutionAuthorized": False, "diskWritesAuthorizedForWindows": False,
        "windowsEspWritesAuthorized": False, "rollbackAfterInstallVerified": False,
    }


def classify_trace(trace: str, plan: dict, *, reported_serial: str,
                   base_sha_after: str, nvram_sha_before: str,
                   nvram_sha_after: str, child_discarded: bool,
                   guest_probe_ok: bool, process_name: str,
                   installer_elf_sha256: str | None,
                   trace_untruncated: bool = True) -> dict:
    """Every guest request must be represented. Return no Windows authority."""
    require(type(trace) is str and 0 < len(trace) <= 4_000_000
            and type(plan) is dict and plan.get("schemaVersion") == 1
            and plan.get("scenario") == "isolated-pop-synthetic-qemu-smoke"
            and plan.get("windowsDiskAttached") is False
            and plan.get("distinstExecutionAuthorized") is False
            and plan.get("diskWritesAuthorizedForWindows") is False
            and plan.get("windowsEspWritesAuthorized") is False
            and plan.get("serial") == SERIAL
            and plan.get("sizeBytes") == DISK_SIZE
            and plan.get("logicalSectorBytes") == SECTOR
            and type(trace_untruncated) is bool and trace_untruncated
            and reported_serial == SERIAL
            and type(base_sha_after) is str
            and base_sha_after == plan.get("baseSha256")
            and type(nvram_sha_before) is str and HASH.fullmatch(nvram_sha_before)
            and type(nvram_sha_after) is str and HASH.fullmatch(nvram_sha_after)
            and child_discarded is True and guest_probe_ok is True,
            "QEMU trace/provenance/isolation or backing checkpoint unproven")
    require(plan.get("diskGuid") == SYNTH_GUID
            and plan.get("esp") == {
                "partitionIndex": 1,
                "partuuid": "ae228a25-0ecd-4f62-83b4-88dd48b88edd",
                "offsetBytes": 1024**2,
                "lengthBytes": 64 * 1024**2,
            }
            and plan.get("root") == {
                "partitionIndex": 2,
                "partuuid": "f81482ad-e0e1-491a-8ea5-9c246f82ded8",
                "offsetBytes": 128 * 1024**2,
                "lengthBytes": 2 * 1024**3,
            },
            "synthetic disk or PARTUUID drift")
    require(process_name == "python3"
            and installer_elf_sha256 is None,
            "write request has unexpected origin or untrusted installer ELF")
    expected = plan.get("expectedOperation")
    require(type(expected) is dict
            and expected == {"process": "python3",
                             "operation": "guest-block-write-smoke",
                             "offsetBytes": SMOKE_OFFSET,
                             "lengthBytes": SMOKE_LENGTH,
                             "intervalType": "unallocated-synthetic-only"},
            "unexpected or incomplete synthetic write-set")
    pflash_events = [line for line in trace.splitlines()
                     if PFLASH_WRITE.search(line)]
    vars_changed = nvram_sha_before != nvram_sha_after
    require(not vars_changed or len(pflash_events) > 0,
            "OVMF VARS changed without independent QEMU pflash write events")
    events = []
    for line in trace.splitlines():
        if not UNKNOWN_WRITE.search(line):
            continue
        match = WRITE_EVENT.search(line)
        # blk/bdrv implementation traces may be present in the same file;
        # refuse all other write classes until their node is independently
        # mapped to the synthetic device and their semantics classified.
        require(match is not None, "unattributed QEMU write/zero/discard event")
        sector, count = int(match["sector"]), int(match["count"])
        require(count > 0 and count <= 1_000_000
                and 0 <= sector <= DISK_SIZE // SECTOR
                and sector + count <= DISK_SIZE // SECTOR,
                "QEMU write out of synthetic disk bounds")
        events.append({"offsetBytes": sector * SECTOR,
                       "lengthBytes": count * SECTOR,
                       "source": "external-qemu-virtio-block-trace",
                       "operation": "guest-write-request"})
    require(len(events) >= 1 and len(events) <= 1000,
            "no real synthetic block request observed / unbounded events")
    require(all(x["offsetBytes"] == SMOKE_OFFSET
                and x["lengthBytes"] == SMOKE_LENGTH for x in events),
            "synthetic QEMU event outside precise declared write-set: " +
            repr(events[:8]))
    # The smoke is deliberately in UNALLOCATED synthetic space, not in Pop
    # partitions or the Windows six-GPT plan. It has zero authority elsewhere.
    return {
        "schemaVersion": 1,
        "scenario": "isolated-pop-synthetic-qemu-smoke",
        "events": events,
        "guestWriteRequestsObserved": True,
        "exactSyntheticSmokeEventMatched": True,
        "qemuTraceSource": "virtio_blk_handle_write",
        "baseImageSha256Unchanged": True,
        "privateChildDiscarded": True,
        "ovmfVarsChanged": vars_changed,
        "ovmfPflashWriteRequestsObserved": bool(pflash_events),
        "ovmfPflashWriteEventCount": len(pflash_events),
        "ovmfPflashWriteEvents": pflash_events[:100],
        "nvramWriteSetAttested": False,
        "installerProcessObserved": False,
        "installerWritesObserved": False,
        "transientWritesOutsideTraceProvenAbsent": False,
        "windowsWriteSetMatchProven": False,
        "distinstExecutionAuthorized": False,
        "diskWritesAuthorizedForWindows": False,
        "windowsEspWritesAuthorized": False,
        "productionInstallationAuthorized": False,
        "rollbackAfterNativeInstallVerified": False,
    }
