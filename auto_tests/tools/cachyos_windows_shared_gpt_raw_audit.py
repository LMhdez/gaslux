#!/usr/bin/env python3
"""Read-only primary+backup GPT byte check against an Ed25519-bound lab plan.

No GPT repairs, partition writes, sgdisk --clear, mkfs or bootloader changes.
A signed host-supplied GPT window hash must match the actual guest disk;
this alone does not authenticate the VM origin or authorize pacstrap.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
from pathlib import Path
import stat
import struct
import uuid

from cachyos_windows_shared_archiso_handoff import (
    SharedDiskHandoffRejected, validate_plan, require,
)
from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, SECTOR, WINDOW_BYTES, header_at, part_array,
)

GPT_ENTRY_BYTES = 128
GPT_COUNT = 128


def inspect_bound_gpt_windows(
    primary_window: bytes, backup_window: bytes, plan: dict,
) -> dict[str, bool]:
    """Verify exact GPT records and header CRCs from two bounded raw reads."""
    validate_plan(plan)
    require(isinstance(primary_window, bytes)
            and isinstance(backup_window, bytes)
            and len(primary_window) == WINDOW_BYTES
            and len(backup_window) == WINDOW_BYTES,
            "missing exact primary/backup guest disk windows")
    require(hashlib.sha256(primary_window+backup_window).hexdigest()
            == plan["gptWindowsSha256"],
            "guest GPT window bytes differ from signed transaction plan")
    require(primary_window[510:512] == b"\x55\xaa",
            "invalid protective MBR signature")
    mbr = [primary_window[446+i*16:446+(i+1)*16]
           for i in range(4)]
    total = VIRTUAL_BYTES // SECTOR
    start, span = struct.unpack_from("<II", mbr[0], 8)
    require(mbr[0][0] == 0 and mbr[0][4] == 0xEE
            and start == 1 and span in (total-1, 0xFFFFFFFF)
            and all(not any(x) for x in mbr[1:]),
            "hybrid or malformed protective MBR")
    first_header=header_at(primary_window, SECTOR, 1, total-1, total)
    last_header=header_at(backup_window, WINDOW_BYTES-SECTOR,
                          total-1, 1, total)
    require(first_header[56:72] == last_header[56:72]
            and hashlib.sha256(first_header[56:72]).hexdigest()
                == plan["diskGuidSha256"],
            "GPT disk GUID differs from signed Windows disk identity")
    require(first_header[40:56] == last_header[40:56]
            and first_header[80:92] == last_header[80:92],
            "GPT mirror headers disagree")
    require(struct.unpack_from("<Q", first_header, 72)[0] == 2
            and struct.unpack_from("<Q", last_header, 72)[0] == total-33,
            "nonstandard GPT partition-entry array position")
    first=part_array(first_header,primary_window,backup_window,total)
    last=part_array(last_header,primary_window,backup_window,total)
    require(first == last and len(first) == GPT_COUNT*GPT_ENTRY_BYTES,
            "GPT mirrors or partition array length disagree")
    for i, expected in enumerate(plan["partitions"]):
        item=first[i*GPT_ENTRY_BYTES:(i+1)*GPT_ENTRY_BYTES]
        actual_type=str(uuid.UUID(bytes_le=item[:16]))
        actual_guid=str(uuid.UUID(bytes_le=item[16:32]))
        begin,end=struct.unpack_from("<QQ",item,32)
        require(actual_type == expected["typeGuid"]
                and actual_guid == expected["uniqueGuid"]
                and begin == expected["firstLba"]
                and end == expected["lastLba"],
                "GPT entry differs from exact signed Windows/Linux partition contract")
    require(not any(first[5*GPT_ENTRY_BYTES:]),
            "unowned sixth or further GPT entry detected")
    return {
        "actualPrimaryBackupGptCrcAndWindowsPartitionsVerified": True,
        "actualGptWindowsBoundToSignedWindowSha256": True,
        "windowsDiskOriginAuthenticated": False,
        "pacstrapAuthorized": False,
        "storageWritesAuthorized": False,
        "sameDiskDualBootVerified": False,
        "releaseEligible": False,
    }


def read_guest_disk_windows_readonly(device: Path) -> tuple[bytes, bytes]:
    """Bounded O_RDONLY device reads, never a write or block-device mutation."""
    require(isinstance(device, Path) and device.is_absolute()
            and device.parent == Path("/dev")
            and re.fullmatch(r"vd[a-z]{1,2}", device.name) is not None
            and not device.is_symlink(),
            "read-only audit only accepts exact QEMU virtio guest block path")
    st = device.stat()
    require(stat.S_ISBLK(st.st_mode), "target is not a guest block device")
    fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC |
                 os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        require(os.fstat(fd).st_rdev == st.st_rdev,
                "guest block device changed before read")
        # Linux block ioctls: reject a partition, stale node, or wrong geometry
        # before either bounded GPT window read. Read-only ioctls only.
        physical_bytes = struct.unpack("=Q", fcntl.ioctl(
            fd, 0x80081272, bytes(8)))[0]  # BLKGETSIZE64, x86_64
        logical_bytes = struct.unpack("=I", fcntl.ioctl(
            fd, 0x1268, bytes(4)))[0]  # BLKSSZGET
        require(physical_bytes == VIRTUAL_BYTES and logical_bytes == SECTOR,
                "guest block device size or logical sector differs from plan")
        first=os.pread(fd, WINDOW_BYTES, 0)
        last=os.pread(fd, WINDOW_BYTES, VIRTUAL_BYTES-WINDOW_BYTES)
        require(len(first) == WINDOW_BYTES and len(last) == WINDOW_BYTES,
                "short read from guest GPT windows")
        require(os.fstat(fd).st_rdev == st.st_rdev,
                "guest disk changed during read-only GPT audit")
        return first, last
    finally:
        os.close(fd)


if __name__=="__main__":
    raise SystemExit("Read-only library only, never execute a partition operation.")
