#!/usr/bin/env python3
"""Read-only candidate GPT geometry audit of a SHUT DOWN disposable Windows QCOW2.

Independent disk-level checks of both GPT header CRCs and both partition-entry
array CRCs, without mounting a filesystem or opening a block device. Does not
prove Windows boot provenance, recovery, dual boot, or safe Linux disk writes.
"""
from __future__ import annotations

import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import uuid

SECTOR = 512
WINDOW_SECTORS = 2048
WINDOW_BYTES = WINDOW_SECTORS * SECTOR
VIRTUAL_BYTES = 128 * 1024**3
MIN_UNALLOCATED = 40 * 1024**3
TYPES = (
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",  # ESP
    "e3c9e316-0b5c-4db8-817d-f92df00215ae",  # MSR
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",  # NTFS Windows basic data
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac",  # Windows Recovery
)


class GeometryError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GeometryError(message)


def part_array(header: bytes, front: bytes, back: bytes,
               total_lbas: int) -> bytes:
    lba = struct.unpack_from("<Q", header, 72)[0]
    count, entry_size, crc = struct.unpack_from("<III", header, 80)
    require(count == 128 and entry_size == 128,
            "unrecognized Windows GPT partition-entry geometry")
    sectors = count * entry_size // SECTOR
    if 0 <= lba and lba + sectors <= WINDOW_SECTORS:
        entries = front[lba * SECTOR:(lba + sectors) * SECTOR]
    elif total_lbas - WINDOW_SECTORS <= lba and lba + sectors <= total_lbas:
        start = lba - (total_lbas - WINDOW_SECTORS)
        entries = back[start * SECTOR:(start + sectors) * SECTOR]
    else:
        raise GeometryError("GPT partition array is outside bounded disk windows")
    require(len(entries) == count * entry_size and
            binascii.crc32(entries) & 0xffffffff == crc,
            "GPT partition array CRC mismatch")
    return entries


def header_at(data: bytes, offset: int, current: int,
              backup: int, total_lbas: int) -> bytes:
    require(len(data) == WINDOW_BYTES and
            0 <= offset <= WINDOW_BYTES - SECTOR,
            "missing bounded GPT disk window")
    raw = data[offset:offset + SECTOR]
    require(raw[:8] == b"EFI PART" and
            struct.unpack_from("<I", raw, 8)[0] == 0x00010000,
            "missing/unsupported GPT header")
    size, recorded_crc, reserved = struct.unpack_from("<III", raw, 12)
    require(size == 92 and reserved == 0, "unsupported GPT header size")
    header = bytearray(raw[:size])
    header[16:20] = b"\x00" * 4
    require(binascii.crc32(header) & 0xffffffff == recorded_crc,
            "GPT header CRC mismatch")
    this_lba, backup_lba, first, last = struct.unpack_from("<QQQQ", raw, 24)
    # This laboratory uses a fixed 128-record GPT (32 sectors) on an
    # exactly 128 GiB, 512-byte-sector Windows disk. Reject truncated or
    # shifted usable ranges even if an attacker recomputes both header CRCs.
    require(this_lba == current and backup_lba == backup and
            first == 34 and last == total_lbas - 34,
            "unexpected GPT header addresses")
    require(raw[56:72] != b"\x00" * 16,
            "missing GPT disk identity")
    return raw


def inspect_gpt_windows(front: bytes, back: bytes,
                        disk_bytes: int = VIRTUAL_BYTES) -> dict[str, object]:
    """Validate Windows GPT bytes extracted from a single immutable QCOW2."""
    require(type(disk_bytes) is int and disk_bytes == VIRTUAL_BYTES,
            "unexpected Windows lab virtual disk geometry")
    require(len(front) == WINDOW_BYTES and len(back) == WINDOW_BYTES,
            "missing primary or backup GPT window")
    require(front[510:512] == b"\x55\xaa",
            "invalid protective MBR signature")
    entries_mbr = [front[446 + 16*i:446 + 16*(i+1)] for i in range(4)]
    total = disk_bytes // SECTOR
    # A mere 0xEE type byte does not establish a protective MBR. In
    # particular, a forged zero-length/shifted entry must not certify a
    # disk for subsequent Linux partition planning. This fixed-size lab
    # fits the protective MBR's 32-bit sector-count field exactly.
    protective_start, protective_span = struct.unpack_from(
        "<II", entries_mbr[0], 8,
    )
    protective_boot = entries_mbr[0][0]
    protective_type = entries_mbr[0][4]
    expected_span = min(total - 1, 0xffffffff)
    extra_slots = tuple(i + 2 for i, entry in enumerate(entries_mbr[1:])
                        if any(entry))
    require(
        protective_boot == 0
        and protective_type == 0xEE
        and protective_start == 1
        and protective_span == expected_span
        and not extra_slots,
        "hybrid or invalid protective MBR geometry: "
        f"boot={protective_boot}, type=0x{protective_type:02x}, "
        f"start_lba={protective_start}, span_lba={protective_span}, "
        f"expected_span_lba={expected_span}, "
        f"unexpected_entry_slots={extra_slots}",
    )
    primary = header_at(front, SECTOR, 1, total - 1, total)
    backup = header_at(back, WINDOW_BYTES - SECTOR, total - 1, 1, total)
    require(primary[56:72] == backup[56:72] and
            primary[40:56] == backup[40:56] and
            primary[80:92] == backup[80:92],
            "primary and backup GPT headers disagree")
    p_entries = part_array(primary, front, back, total)
    b_entries = part_array(backup, front, back, total)
    require(p_entries == b_entries, "primary and backup GPT entries disagree")
    # The first and backup partition tables must occupy the standard Windows
    # 128-entry sectors. No surprising GPT records beyond these four Windows
    # partitions are accepted.
    require(struct.unpack_from("<Q", primary, 72)[0] == 2 and
            struct.unpack_from("<Q", backup, 72)[0] == total - 33,
            "unrecognized primary or backup GPT array position")
    first_usable, last_usable = struct.unpack_from("<QQ", primary, 40)
    spans = []
    result_parts = []
    unique_partition_guids: set[bytes] = set()
    for i in range(128):
        rec = p_entries[i*128:(i+1)*128]
        if not any(rec[:16]):
            require(not any(rec), "nonempty supposedly unused GPT record")
            continue
        require(i < 4, "foreign fifth GPT partition detected")
        typ = str(uuid.UUID(bytes_le=rec[:16]))
        require(typ == TYPES[i], "unexpected Windows GPT partition type/order")
        unique_guid = rec[16:32]
        require(unique_guid != b"\x00" * 16,
                "missing unique Windows GPT partition GUID")
        require(unique_guid not in unique_partition_guids,
                "duplicate Windows GPT partition identity")
        unique_partition_guids.add(unique_guid)
        start, end = struct.unpack_from("<QQ", rec, 32)
        require(first_usable <= start <= end <= last_usable and
                start >= 2048 and start % 2048 == 0,
                "unaligned or out-of-bounds Windows GPT partition")
        part_bytes = (end - start + 1) * SECTOR
        # Broad bounds accommodate Windows Setup's sector-level rounding.
        limits = ((240, 320), (15, 18), (70000, 76000), (1400, 1700))
        lo, hi = limits[i]
        require(lo * 1024**2 <= part_bytes <= hi * 1024**2,
                "unexpected Windows GPT partition size")
        spans.append((start, end))
        result_parts.append({
            "index": i + 1, "type": typ, "partitionGuid": str(uuid.UUID(bytes_le=unique_guid)),
            "firstLba": start, "lastLba": end,
            "lengthBytes": part_bytes,
        })
    require(len(result_parts) == 4 and all(
        spans[i][1] < spans[i+1][0] for i in range(3)
    ), "missing, overlapping or reordered Windows partitions")
    free_end_bytes = (last_usable - spans[-1][1]) * SECTOR
    require(free_end_bytes >= MIN_UNALLOCATED,
            "insufficient untouched post-Windows GPT free space")
    return {
        "candidateWindowsGptPrimaryAndBackupConsistent": True,
        "virtualDiskBytes": disk_bytes,
        "sectorBytes": SECTOR,
        "windowsPartitions": result_parts,
        "unallocatedAfterWindowsBytes": free_end_bytes,
        "diskGuidSha256": hashlib.sha256(primary[56:72]).hexdigest(),
        "windowsGuestOriginAuthenticated": False,
        "windowsBootVerified": False,
        "windowsBcdWinreRestorationVerified": False,
        "sameDiskDualBootVerified": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


def bounded_qcow2_dd_command(disk: Path, dest: Path, suffix: str) -> list[str]:
    """Read a bounded window from a closed QCOW2 without modifying the source.

    QEMU img_dd initializes the output size with count * bs BEFORE applying
    skip (see qemu-img.c). Using count=2048 plus a 128-GiB tail skip creates
    a ZERO-BYTE output despite a successful exit. Use count only at the front;
    reading without count from exactly 1 MiB before EOF naturally bounds the
    tail to 1 MiB. In both cases the caller verifies output length/identity.
    """
    require(suffix in ("front", "back"), "unknown GPT window selector")
    skip = (0 if suffix == "front" else
            VIRTUAL_BYTES // SECTOR - WINDOW_SECTORS)
    cmd = ["qemu-img", "dd", "-f", "qcow2", "-O", "raw", f"bs={SECTOR}"]
    if suffix == "front":
        cmd.append(f"count={WINDOW_SECTORS}")
    cmd.extend([f"skip={skip}", f"if={disk}", f"of={dest}"])
    return cmd



def qcow2_file_identity(disk: Path) -> tuple[int, int, int, int, int, int]:
    """Track owned image identity and mutation across bounded GPT reads.

    A cleanly shut down guest must leave its QCOW2 unchanged while two
    independent GPT windows are extracted. This is a fail-closed
    inconsistency detector, NOT an authenticated immutable snapshot.
    """
    item = disk.lstat()
    require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1,
            "Windows QCOW2 ceased to be an exclusive regular file")
    return (item.st_dev, item.st_ino, item.st_nlink, item.st_size,
            item.st_mtime_ns, item.st_ctime_ns)


def require_unchanged_qcow2(
    disk: Path, baseline: tuple[int, int, int, int, int, int],
) -> None:
    require(qcow2_file_identity(disk) == baseline,
            "Windows QCOW2 identity or content changed during GPT audit")


def inspect_owned_qcow2(disk: Path) -> dict[str, object]:
    """QEMU reads only an owned QCOW2 and writes at most 2 MiB private scratch."""
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT") ==
            "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
            "authorized hosted Windows CI required")
    require(disk.name == "only-disposable-windows-target.qcow2" and
            disk.parent.parent == Path("/home/runner/work/_temp") and
            disk.parent.name.startswith("gaslux-win-x64-") and
            not disk.parent.is_symlink() and
            not disk.is_symlink() and disk.is_file() and
            stat.S_ISREG(disk.stat().st_mode) and
            disk.stat().st_uid == os.getuid() and
            disk.stat().st_nlink == 1 and
            disk.parent.stat().st_uid == os.getuid() and
            stat.S_IMODE(disk.parent.stat().st_mode) == 0o700,
            "unowned or unsafe Windows QCOW2 path")
    baseline_identity = qcow2_file_identity(disk)
    raw = subprocess.run(
        ["qemu-img", "info", "-f", "qcow2", "--output=json", str(disk)],
        check=True, capture_output=True, text=True, timeout=25,
    )
    info = json.loads(raw.stdout)
    require(info.get("format") == "qcow2" and
            info.get("virtual-size") == VIRTUAL_BYTES and
            not info.get("backing-filename") and
            not info.get("full-backing-filename") and
            not info.get("encrypted", False),
            "QCOW2 has unexpected format, size, encryption or backing chain")
    require_unchanged_qcow2(disk, baseline_identity)
    with tempfile.TemporaryDirectory(prefix="gaslux-gpt-readonly-", dir=disk.parent) as tmp:
        region = []
        for suffix in ("front", "back"):
            dest = Path(tmp) / (suffix + ".raw")
            subprocess.run(
                bounded_qcow2_dd_command(disk, dest, suffix),
                check=True, capture_output=True, timeout=60,
            )
            require_unchanged_qcow2(disk, baseline_identity)
            require(dest.is_file() and not dest.is_symlink(),
                    f"QEMU returned no regular bounded {suffix} GPT window")
            actual_bytes = dest.stat().st_size
            require(actual_bytes == WINDOW_BYTES,
                    f"QEMU returned invalid {suffix} GPT window length: "
                    f"{actual_bytes} bytes instead of {WINDOW_BYTES}")
            region.append(dest.read_bytes())
    require_unchanged_qcow2(disk, baseline_identity)
    return inspect_gpt_windows(region[0], region[1])


def correlate_host_gpt_and_guestfs(
    candidate: dict[str, object], filesystem: dict[str, object], profile: str
) -> dict[str, object]:
    """Require byte-exact agreement between two read-only QCOW2 inspections.

    This is an offline geometry consistency check, not an authorization to
    change a disk, a proof of Windows guest provenance, or a dual-boot test.
    """
    require(profile in ("win10_22h2_en_us_x64", "win11_26h2_en_us_x64"),
            "unsupported Windows host GPT profile")
    require(candidate.get("candidateWindowsGptPrimaryAndBackupConsistent") is True
            and candidate.get("sameDiskDualBootVerified") is False
            and candidate.get("storageWritesAuthorized") is False
            and candidate.get("releaseEligible") is False
            and candidate.get("windowsBootVerified") is False,
            "untrusted or overclaiming host GPT report")
    require(filesystem.get("profile") == profile
            and filesystem.get("source") ==
            "gaslux-host-libguestfs-readonly-after-verified-firstboot"
            and filesystem.get("partitionCount") == 4
            and filesystem.get("diskVirtualSizeBytes") == VIRTUAL_BYTES
            and filesystem.get("sameDiskDualBootVerified") is False
            and filesystem.get("storageWritesAuthorized") is False
            and filesystem.get("stable") is False,
            "untrusted libguestfs evidence or mismatched Windows profile")
    for key in ("espBootManagerPresent", "espBcdPresent",
                "ntfsWindowsLoaderPresent", "ntfsWindowsSystemHivePresent",
                "recoveryGptPartitionPresent"):
        require(filesystem.get(key) is True,
                "missing Windows EFI/BCD/NTFS offline verification")
    host_partitions = candidate.get("windowsPartitions")
    mounted_partitions = filesystem.get("partitions")
    require(isinstance(host_partitions, list) and len(host_partitions) == 4
            and isinstance(mounted_partitions, list)
            and len(mounted_partitions) == 4,
            "host and guestfs Windows partition lists do not match")
    for host, mounted in zip(host_partitions, mounted_partitions):
        require(isinstance(host, dict) and isinstance(mounted, dict)
                and mounted.get("number") == host.get("index")
                and mounted.get("typeGuid") == host.get("type")
                and mounted.get("partitionGuid") == host.get("partitionGuid")
                and mounted.get("offsetBytes") == host.get("firstLba") * SECTOR
                and mounted.get("sizeBytes") == host.get("lengthBytes")
                and (host.get("lastLba") - host.get("firstLba") + 1) * SECTOR
                == host.get("lengthBytes"),
                "host GPT and libguestfs partition geometry/identity disagree")
    require(type(candidate.get("unallocatedAfterWindowsBytes")) is int
            and candidate["unallocatedAfterWindowsBytes"] >= MIN_UNALLOCATED,
            "missing safe unallocated post-Windows extent")
    return dict(candidate, profile=profile,
                independentLibguestfsPartitionAgreement=True)


if __name__ == "__main__":
    raise SystemExit(
        "Library only: invoked after genuine Windows shutdown in an authorized VM")
