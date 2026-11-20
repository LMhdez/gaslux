"""Read-only Windows/Q4OS GPT preservation boundary for disposable raw VM images.

This is NOT an installer, write authorization, Windows boot verifier or trusted
handoff. A separately authenticated Windows-side baseline is mandatory before
these observations can contribute to a real installation decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import stat
import struct
import uuid
import zlib
from pathlib import Path

OFFICIAL_Q4OS_ISO_SHA256 = "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d"
ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
MSR = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
WINDOWS_DATA = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
WINRE = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"
PROTECTED = {ESP, MSR, WINDOWS_DATA, WINRE}


class Q4osWindowsBoundaryRefusal(ValueError):
    """Malformed/ambiguous target, drift, or unproven recovery boundary."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Q4osWindowsBoundaryRefusal(reason)


def _canonical(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def _read(fd: int, offset: int, length: int) -> bytes:
    data = os.pread(fd, length, offset)
    _require(len(data) == length, "Truncated raw VM disk")
    return data


def _header(fd: int, sector: int, lba: int, peer_lba: int, last: int, table_lba: int) -> dict:
    data = _read(fd, lba * sector, sector)
    _require(data[:8] == b"EFI PART", "Not a GPT header")
    _require(struct.unpack_from("<I", data, 8)[0] == 0x10000, "Unsupported GPT revision")
    size = struct.unpack_from("<I", data, 12)[0]
    _require(size == 92 and data[size:] == bytes(sector - size), "Unsupported GPT header")
    crc = struct.unpack_from("<I", data, 16)[0]
    copy = bytearray(data[:size])
    copy[16:20] = bytes(4)
    _require((zlib.crc32(copy) & 0xFFFFFFFF) == crc, "GPT header CRC mismatch")
    current, other, usable_first, usable_last = struct.unpack_from("<QQQQ", data, 24)
    _require(current == lba and other == peer_lba, "GPT header location/peer mismatch")
    table = struct.unpack_from("<Q", data, 72)[0]
    count, entry_size, entries_crc = struct.unpack_from("<III", data, 80)
    _require(count == 128 and entry_size == 128, "Unsupported GPT entry geometry")
    _require(table == table_lba, "GPT table location mismatch")
    _require(usable_first == 2 + (16384 // sector), "GPT usable start mismatch")
    _require(usable_last == last - 1 - (16384 // sector), "GPT usable end mismatch")
    disk_guid = str(uuid.UUID(bytes_le=data[56:72]))
    _require(uuid.UUID(disk_guid).int != 0, "Missing GPT disk GUID")
    return {"diskGuid": disk_guid, "entriesCrc": entries_crc, "first": usable_first, "last": usable_last}


def _partition_sha256(fd: int, first: int, last: int, sector: int) -> str:
    # Full protected-content hashes, including ESP (and therefore BCD) and WinRE.
    # Reject unsupported huge protected images rather than silently sampling them.
    total = (last - first + 1) * sector
    _require(total <= 8 * 1024**3, "Protected partition too large for full-content proof")
    digest = hashlib.sha256()
    for offset in range(0, total, 1024 * 1024):
        digest.update(_read(fd, first * sector + offset, min(1024 * 1024, total - offset)))
    return digest.hexdigest()


def _inspect(fd: int, size: int, sector: int) -> dict:
    _require(sector in (512, 4096) and size % sector == 0, "Unsupported sector geometry")
    _require(8 * 1024**2 <= size <= 2 * 1024**4, "Unsupported disk size")
    last = size // sector - 1
    table_sectors = 16384 // sector
    mbr = _read(fd, 0, 512)
    _require(mbr[:4] != b"QFI\xfb", "QCOW2 requires read-only raw conversion")
    _require(mbr[510:512] == b"\x55\xaa", "Missing protective MBR")
    first_mbr = mbr[446:462]
    _require(
        first_mbr[0] == 0 and first_mbr[4] == 0xEE
        and struct.unpack_from("<I", first_mbr, 8)[0] == 1
        and struct.unpack_from("<I", first_mbr, 12)[0] == min(last, 0xFFFFFFFF)
        and mbr[462:510] == bytes(48),
        "Hybrid/foreign/nonprotective MBR",
    )
    primary = _header(fd, sector, 1, last, last, 2)
    backup = _header(fd, sector, last, 1, last, last - table_sectors)
    _require(primary == backup, "Primary/secondary GPT identity differs")
    data_a = _read(fd, 2 * sector, 16384)
    data_b = _read(fd, (last - table_sectors) * sector, 16384)
    _require(data_a == data_b, "Primary/secondary GPT partition tables differ")
    _require((zlib.crc32(data_a) & 0xFFFFFFFF) == primary["entriesCrc"], "GPT entry CRC mismatch")
    partitions = []
    used_guids = set()
    for index in range(128):
        item = data_a[index * 128 : (index + 1) * 128]
        if item == bytes(128):
            continue
        _require(item[:16] != bytes(16), "Residual/deleted GPT entry bytes")
        type_guid = str(uuid.UUID(bytes_le=item[:16]))
        guid = str(uuid.UUID(bytes_le=item[16:32]))
        first, end, attributes = struct.unpack_from("<QQQ", item, 32)
        _require(guid not in used_guids and uuid.UUID(guid).int != 0, "Duplicate/empty PARTUUID")
        used_guids.add(guid)
        _require(primary["first"] <= first <= end <= primary["last"], "Out-of-range partition")
        try:
            name = item[56:128].decode("utf-16-le").rstrip("\0")
        except UnicodeDecodeError as exc:
            raise Q4osWindowsBoundaryRefusal("Invalid GPT partition name") from exc
        partitions.append({"index": index + 1, "type": type_guid, "guid": guid,
                           "first": first, "last": end, "attributes": attributes, "name": name})
    for a, b in zip(sorted(partitions, key=lambda p: p["first"]),
                    sorted(partitions, key=lambda p: p["first"])[1:]):
        _require(a["last"] < b["first"], "Overlapping GPT partitions")
    types = [part["type"] for part in partitions]
    _require(types.count(ESP) == 1 and WINDOWS_DATA in types and WINRE in types,
             "Unique ESP, Windows data and WinRE partitions required")
    _require(types.count(MSR) == 1, "Unique Windows reserved partition required")
    protected = {}
    for part in partitions:
        if part["type"] == ESP:
            boot = _read(fd, part["first"] * sector, sector)
            _require(boot[510:512] == b"\x55\xaa" and boot[82:90] == b"FAT32   ",
                     "Windows ESP FAT32 identity mismatch")
        if part["type"] in (WINRE, WINDOWS_DATA):
            boot = _read(fd, part["first"] * sector, sector)
            _require(boot[3:11] == b"NTFS    ", "Windows NTFS identity mismatch")
        # The Windows data volume may be terabytes: its full restoration requires
        # independently authenticated Windows VSS/BitLocker/NTFS evidence.
        if part["type"] != WINDOWS_DATA:
            protected[part["guid"]] = _partition_sha256(fd, part["first"], part["last"], sector)
    return {"layout": "uefi/gpt", "diskSizeBytes": size, "logicalSectorBytes": sector,
            "diskGuid": primary["diskGuid"], "partitions": partitions,
            "protectedPartitionSha256": protected,
            "gptPrimarySha256": hashlib.sha256(_read(fd, 0, (2 + table_sectors) * sector)).hexdigest(),
            "gptBackupSha256": hashlib.sha256(_read(fd, (last - table_sectors) * sector,
                                                      (table_sectors + 1) * sector)).hexdigest(),
            "windowsFullVolumeVerified": False, "windowsBootVerified": False,
            "winreBcdRuntimeVerified": False, "nvramVerified": False,
            "diskWritesAuthorized": False}


def inspect_private_raw_vm_disk(workspace: Path, image: Path, *, sector_bytes: int) -> dict:
    """Obtain real GPT/partition bytes, avoiding physical devices and link traversal."""
    _require(isinstance(workspace, Path) and workspace.is_absolute(), "Absolute workspace required")
    _require(isinstance(image, Path) and image == workspace / "windows-target.raw",
             "Only the named disposable raw image is accepted")
    current = workspace
    while current != current.parent:
        _require(not current.is_symlink(), "Symlinked workspace path")
        current = current.parent
    dir_fd = None
    fd = None
    try:
        _require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"),
                 "No-follow directory access unavailable")
        dir_fd = os.open(workspace, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
                         | getattr(os, "O_CLOEXEC", 0))
        directory = os.fstat(dir_fd)
        _require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.getuid()
                 and directory.st_mode & 0o077 == 0, "Private owned workspace required")
        fd = os.open(image.name, os.O_RDONLY | os.O_NOFOLLOW
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
        pre = os.fstat(fd)
        _require(stat.S_ISREG(pre.st_mode) and pre.st_uid == os.getuid()
                 and pre.st_nlink == 1, "Nonexclusive/foreign disk image")
        result = _inspect(fd, pre.st_size, sector_bytes)
        post = os.fstat(fd)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        _require(identity(pre) == identity(post), "Disk mutated during inspection")
        _require(identity(directory) == identity(os.fstat(dir_fd)),
                 "Workspace changed during inspection")
        result["vmFileDeviceId"] = pre.st_dev
        result["vmFileInode"] = pre.st_ino
        result["observedStateSha256"] = hashlib.sha256(_canonical(result)).hexdigest()
        return result
    except OSError as exc:
        raise Q4osWindowsBoundaryRefusal("Cannot safely read private raw image") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if dir_fd is not None:
            os.close(dir_fd)


def propose_read_only_native_target(*, before: dict, reread: dict, start_lba: int,
                                    end_lba: int, calamares: dict, hooks: dict,
                                    checkpoint: dict,
                                    firmware_layout: str = "uefi/gpt") -> dict:
    """Typed proposed root extent; *never* hands write authority to Calamares."""
    _require(firmware_layout == "uefi/gpt", "Other Q4OS layouts lack proven Windows recovery")
    _require(before == reread, "External disk, GPT, or Windows partition drift")
    _require(before.get("layout") == "uefi/gpt" and before.get("diskWritesAuthorized") is False,
             "Untrusted or writable disk observation")
    _require(before.get("windowsBootVerified") is False and before.get("nvramVerified") is False,
             "Unexpected elevated observation claim")
    _require(type(checkpoint) is dict and checkpoint.get("checkpointComparedToFullDisk") is True
             and checkpoint.get("observedStateSha256") == before.get("observedStateSha256")
             and checkpoint.get("checkpointRestoredAndBooted") is False,
             "No independently matched read-only checkpoint")
    sector = before["logicalSectorBytes"]
    _require(type(start_lba) is int and type(end_lba) is int and start_lba < end_lba,
             "Invalid proposed root geometry")
    _require(start_lba % (1048576 // sector) == 0, "Root must be MiB aligned")
    _require(end_lba < before["diskSizeBytes"] // sector - 1 - (16384 // sector),
             "Root overlaps backup GPT metadata")
    _require(start_lba >= 2 + (16384 // sector), "Root overlaps primary GPT metadata")
    for part in before["partitions"]:
        _require(end_lba < part["first"] or start_lba > part["last"],
                 "Proposed root overlaps Windows/OEM/existing partition")
    _require(calamares.get("distribution") == "q4os" and calamares.get("version") == "6.10-deb13u1"
             and calamares.get("nativeCalamaresConfigVerified") is True,
             "Unverified pinned native Calamares identity")
    _require(calamares.get("upstreamInstallsEfiFallback") is True,
             "Unexpected upstream EFI fallback configuration; re-audit required")
    _require(hooks.get("unownedEfiDebianWriteRiskObserved") is True
             and hooks.get("forcedGrubInstallRiskObserved") is True,
             "Unexpected Calamares hook behavior; re-audit required")
    return {
        "schemaVersion": 1, "backend": "q4os-native", "sourceKind": "native-live-calamares",
        "isoSha256": OFFICIAL_Q4OS_ISO_SHA256, "firmwareLayout": firmware_layout,
        "diskGuid": before["diskGuid"], "diskSizeBytes": before["diskSizeBytes"],
        "logicalSectorBytes": sector, "vmFileDeviceId": before["vmFileDeviceId"],
        "vmFileInode": before["vmFileInode"], "observedStateSha256": before["observedStateSha256"],
        "proposedRootStartLba": start_lba, "proposedRootEndLba": end_lba,
        "proposedRootFilesystem": "ext4", "checkpointMatchesFullDisk": True,
        "checkpointSha256": checkpoint["checkpointSha256"],
        "gptMetadataWriteRequiresSeparateAuthority": True,
        "windowsEspFallbackWriteBlocked": True, "efiDebianHookWriteBlocked": True,
        "windowsBootAndWinreRecoveryUnverified": True,
        "installationAuthorized": False, "calamaresJobsAuthorized": False,
        "diskWritesAuthorized": False, "windowsEspWritesAuthorized": False,
        "rollbackVerified": False,
    }


def verify_windows_preservation(before: dict, after: dict) -> dict:
    """Read-only partition/GPT comparison; no assertion that Windows can boot."""
    for key in ("diskGuid", "diskSizeBytes", "logicalSectorBytes"):
        _require(before.get(key) == after.get(key), "Disk identity/geometry drift: " + key)
    originals = {part["guid"]: part for part in before["partitions"]}
    current = {part["guid"]: part for part in after["partitions"]}
    _require(len(current) == len(after["partitions"]), "Duplicate current PARTUUID")
    for guid, part in originals.items():
        _require(current.get(guid) == part, "Original Windows/OEM partition altered")
        if guid in before["protectedPartitionSha256"]:
            _require(after["protectedPartitionSha256"].get(guid)
                     == before["protectedPartitionSha256"][guid],
                     "Protected partition contents changed (ESP/WinRE/OEM)")
    return {"originalPartitionMetadataPreserved": True, "protectedContentPreserved": True,
            "windowsBootVerified": False, "winreBcdRuntimeVerified": False,
            "rollbackVerified": False, "installationAuthorized": False}


def verify_read_only_checkpoint(workspace: Path, source: Path, snapshot: Path,
                                *, sector_bytes: int, expected_snapshot_sha256: str) -> dict:
    """Compare complete raw disk to a private, self-contained qcow2 with qemu-img.

    Never creates a snapshot or runs guest commands. The expected digest must be
    supplied by an independently authenticated checkpoint ledger; caller must
    also preserve a separately accessible durable recovery copy.
    """
    _require(snapshot == workspace / "checkpoints" / "recovery.qcow2",
             "Foreign checkpoint path")
    before = inspect_private_raw_vm_disk(workspace, source, sector_bytes=sector_bytes)
    folder = snapshot.parent
    _require(folder.is_dir() and not folder.is_symlink(), "Missing checkpoint folder")
    folder_meta = folder.stat()
    _require(folder_meta.st_uid == os.getuid() and folder_meta.st_mode & 0o077 == 0,
             "Checkpoint folder not private")
    _require(type(expected_snapshot_sha256) is str and len(expected_snapshot_sha256) == 64
             and all(c in "0123456789abcdef" for c in expected_snapshot_sha256),
             "Missing independent checkpoint digest")
    _require(hasattr(os, "O_NOFOLLOW"), "No-follow open unavailable")
    try:
        fd = os.open(snapshot, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise Q4osWindowsBoundaryRefusal("Cannot open owned checkpoint") from exc
    try:
        meta = os.fstat(fd)
        _require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid()
                 and meta.st_nlink == 1 and meta.st_size > 0, "Nonexclusive checkpoint file")
        hasher = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            hasher.update(block)
        _require(hasher.hexdigest() == expected_snapshot_sha256, "Checkpoint SHA-256 mismatch")
        def run(*args: str) -> str:
            try:
                completed = subprocess.run(["qemu-img", *args], capture_output=True,
                                           text=True, timeout=180, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Q4osWindowsBoundaryRefusal("QEMU checkpoint inspection unavailable") from exc
            _require(completed.returncode == 0, "QEMU checkpoint verification refused: "
                     + completed.stderr[-300:])
            return completed.stdout
        try:
            info = json.loads(run("info", "--output=json", "-f", "qcow2", str(snapshot)))
        except (ValueError, TypeError) as exc:
            raise Q4osWindowsBoundaryRefusal("Malformed QEMU snapshot metadata") from exc
        _require(info.get("format") == "qcow2"
                 and info.get("virtual-size") == before["diskSizeBytes"]
                 and "backing-filename" not in info and "full-backing-filename" not in info,
                 "Checkpoint has backing chain or wrong format/geometry")
        run("check", "-f", "qcow2", str(snapshot))
        run("compare", "-f", "raw", "-F", "qcow2", str(source), str(snapshot))
        post = os.fstat(fd)
        _require((meta.st_ino, meta.st_dev, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)
                 == (post.st_ino, post.st_dev, post.st_size, post.st_mtime_ns, post.st_ctime_ns),
                 "Checkpoint modified during verification")
    finally:
        os.close(fd)
    reread = inspect_private_raw_vm_disk(workspace, source, sector_bytes=sector_bytes)
    _require(before == reread, "Target changed during checkpoint comparison")
    return {"checkpointSha256": expected_snapshot_sha256,
            "checkpointComparedToFullDisk": True,
            "observedStateSha256": before["observedStateSha256"],
            "checkpointRestoredAndBooted": False, "durableOffHostCopyVerified": False,
            "diskWritesAuthorized": False, "rollbackVerified": False}
