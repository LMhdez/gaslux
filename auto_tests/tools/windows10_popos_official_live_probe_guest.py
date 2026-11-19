#!/usr/bin/env python3
"""Live Pop 24.04 read-only *witness* for genuine Windows 10 QCOW2.

EXPERIMENTAL, disposable QEMU ONLY. This is never an installer or an
authenticated Windows->Linux handoff. No mutating block operations exist.
A host-generated hash manifest is read from a RO, separate lab control disk;
the same owned QCOW2 was independently verified before VM boot.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import uuid
import zlib

SERIAL = "GASLUX_POP_WIN10_COW"
CONTROL = Path("/run/gaslux-pop-lab")
DISK_LINK = Path("/dev/disk/by-id/virtio-" + SERIAL)
EXPECTED_DISK_BYTES = 128 * 1024**3
WINDOW = 1024 * 1024
SECTOR = 512
GUID_ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
GUID_MSFT_BASIC = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
GUID_MSFT_MSR = "e3c9e316-0b5c-4db8-817d-f92df00215ae"
GUID_WINRE = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
GUID_LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"
EXPECTED_TYPES = [
    GUID_ESP, GUID_MSFT_MSR, GUID_MSFT_BASIC,
    GUID_WINRE, GUID_ESP, GUID_LINUX,
]


class Refusal(Exception):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise Refusal(message)


def read_manifest() -> dict:
    require(CONTROL.is_dir() and not CONTROL.is_symlink(),
            "lab-only control filesystem absent")
    mount = subprocess.run(
        ["findmnt", "-rn", "-M", str(CONTROL), "-o", "FSTYPE,OPTIONS"],
        capture_output=True, text=True, timeout=8,
    )
    require(mount.returncode == 0 and mount.stdout.startswith("vfat "),
            "lab control not separate FAT filesystem")
    require("ro" in mount.stdout.strip().split(",") and "rw" not in mount.stdout,
            "lab command medium not mounted read-only")
    manifest_file = CONTROL / "six-gpt.json"
    require(manifest_file.is_file() and not manifest_file.is_symlink()
            and manifest_file.stat().st_size < 8192,
            "unexpected live GPT control manifest")
    m = json.loads(manifest_file.read_text("utf-8"))
    require(type(m) is dict and set(m) == {
        "scenario", "diskGuid", "diskSerial", "diskSizeBytes",
        "frontMiBSha256", "backMiBSha256", "windowsFourEntriesSha256",
        "popEspGuid", "popRootGuid", "expectedSectorBytes", "ownedIndexes",
        "windowsIndexes", "productionInstallationAuthorized",
    }, "ambiguous live GPT manifest fields")
    require(
        m["scenario"] == "pop-live-genuine-windows10-pair-readonly"
        and m["diskSerial"] == SERIAL
        and m["diskSizeBytes"] == EXPECTED_DISK_BYTES
        and m["expectedSectorBytes"] == SECTOR
        and m["ownedIndexes"] == [5, 6]
        and m["windowsIndexes"] == [1, 2, 3, 4]
        and m["productionInstallationAuthorized"] is False,
        "untrusted disk layout identity or requested disk write",
    )
    for field in ("frontMiBSha256", "backMiBSha256",
                  "windowsFourEntriesSha256"):
        require(type(m[field]) is str
                and re.fullmatch("[0-9a-f]{64}", m[field]) is not None,
                "malformed GPT hash")
    for field in ("diskGuid", "popEspGuid", "popRootGuid"):
        require(type(m[field]) is str
                and str(uuid.UUID(m[field])) == m[field],
                "malformed manifest disk/partition UUID")
    return m


def require_pop_iso_live() -> None:
    require(os.geteuid() == 0
            and Path("/sys/firmware/efi/efivars").is_dir(),
            "Pop live probe requires QEMU UEFI guest root")
    detected = subprocess.run(
        ["systemd-detect-virt", "--vm"], capture_output=True, text=True, timeout=8,
    )
    require(detected.returncode == 0
            and detected.stdout.strip() in ("qemu", "kvm"),
            "not the explicitly isolated QEMU VM")
    lines = Path("/etc/os-release").read_text("utf-8").splitlines()
    fields = dict(line.split("=", 1) for line in lines if "=" in line)
    require(fields.get("ID", "").strip('"') == "pop"
            and fields.get("VERSION_ID", "").strip('"') == "24.04",
            "native live ISO is not Pop!_OS 24.04")
    for key, expected in (("SecureBoot", 0), ("SetupMode", 1)):
        path = Path("/sys/firmware/efi/efivars") / (
            key + "-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        )
        require(path.is_file() and not path.is_symlink(),
                "missing firmware mode evidence")
        raw = path.read_bytes()
        require(len(raw) == 5 and raw[4] == expected,
                "Secure Boot enabled or SetupMode ambiguous")
    require(not Path("/sys/class/net/eth0").exists(),
            "guest network interface unexpectedly configured")


def _decode_gpt(front: bytes, back: bytes, m: dict) -> list[dict]:
    total = EXPECTED_DISK_BYTES // SECTOR
    require(hashlib.sha256(front).hexdigest() == m["frontMiBSha256"]
            and hashlib.sha256(back).hexdigest() == m["backMiBSha256"],
            "live GPT bytes differ from previously measured Windows COW")
    windows_entries = front[SECTOR * 2:SECTOR * 2 + 4 * 128]
    require(hashlib.sha256(windows_entries).hexdigest()
            == m["windowsFourEntriesSha256"],
            "original four Windows GPT rows not byte-exact")
    front_gpt = front[SECTOR:SECTOR*2]
    backup_gpt = back[-SECTOR:]
    a = front[SECTOR*2:SECTOR*34]
    b = back[-SECTOR*33:-SECTOR]
    require(a == b, "primary and backup entry arrays disagree")
    require(front_gpt[:8] == b"EFI PART"
            and backup_gpt[:8] == b"EFI PART",
            "GPT signatures missing")
    guid = str(uuid.UUID(bytes_le=front_gpt[56:72]))
    require(guid == m["diskGuid"]
            and backup_gpt[56:72] == front_gpt[56:72],
            "guest disk identity not original Windows GPT")
    for header, position, alternate in (
        (front_gpt, 1, total-1),
        (backup_gpt, total-1, 1),
    ):
        size, checksum = struct.unpack_from("<II", header, 12)
        clone = bytearray(header[:size])
        clone[16:20] = b"\0"*4
        count, stride, array_crc = struct.unpack_from("<III", header, 80)
        current, other = struct.unpack_from("<QQ", header, 24)
        require(
            size == 92 and (zlib.crc32(clone) & 0xffffffff) == checksum
            and current == position and other == alternate
            and count == 128 and stride == 128
            and (zlib.crc32(a) & 0xffffffff) == array_crc,
            "live GPT CRC or mirror geometry mismatch",
        )
    require(not any(a[6*128:]), "unexpected seventh or foreign partition")
    rows = []
    seen = set()
    for i in range(6):
        raw = a[128*i:128*(i+1)]
        kind = str(uuid.UUID(bytes_le=raw[:16]))
        part = str(uuid.UUID(bytes_le=raw[16:32]))
        first, last, attrs = struct.unpack_from("<QQQ", raw, 32)
        require(kind == EXPECTED_TYPES[i]
                and first <= last and first >= 2048
                and part not in seen and attrs in (0, 0x8000000000000001),
                "live GPT unrecognized partition " + str(i+1))
        seen.add(part)
        rows.append({"index": i+1, "guid": part,
                     "firstLba": first, "lastLba": last})
    require(rows[4]["guid"] == m["popEspGuid"]
            and rows[5]["guid"] == m["popRootGuid"],
            "owned Pop partition GUID was replaced")
    return rows


def run_probe() -> None:
    require_pop_iso_live()
    m = read_manifest()
    require(DISK_LINK.is_symlink(), "approved virtio target link absent")
    disk = DISK_LINK.resolve(strict=True)
    require(disk.parent == Path("/dev")
            and re.fullmatch(r"vd[a-z]{1,2}", disk.name) is not None
            and stat.S_ISBLK(disk.stat().st_mode),
            "approved target not a QEMU whole disk")
    serial = subprocess.run(
        ["lsblk", "-dn", "-o", "SERIAL", str(disk)],
        capture_output=True, text=True, timeout=8,
    )
    require(serial.returncode == 0 and serial.stdout.strip() == SERIAL,
            "virtio disk serial mismatch")
    fd = os.open(disk, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        require(stat.S_ISBLK(os.fstat(fd).st_mode),
                "QEMU target fd is not a block device")
        size = int(Path("/sys/class/block", disk.name, "size").read_text()) * SECTOR
        require(size == EXPECTED_DISK_BYTES, "unexpected Windows disk size")
        front = os.pread(fd, WINDOW, 0)
        back = os.pread(fd, WINDOW, EXPECTED_DISK_BYTES - WINDOW)
        require(len(front) == WINDOW and len(back) == WINDOW,
                "incomplete GPT read-only windows")
        rows = _decode_gpt(front, back, m)
    finally:
        os.close(fd)
    mountinfo = Path("/proc/self/mountinfo").read_text("utf-8")
    mounted = {line.split()[2] for line in mountinfo.splitlines()
               if len(line.split()) > 2}
    disks = set()
    for child in Path("/sys/class/block").iterdir():
        if re.fullmatch(re.escape(disk.name)+r"[1-9][0-9]*", child.name):
            disks.add(child.name)
    require(disks == {f"{disk.name}{i}" for i in range(1, 7)},
            "guest Linux kernel did not recognize exactly six GPT partitions")
    for row in rows:
        name = f"{disk.name}{row['index']}"
        sysdir = Path("/sys/class/block") / name
        require(int((sysdir/"start").read_text()) == row["firstLba"]
                and int((sysdir/"size").read_text())
                == row["lastLba"] - row["firstLba"] + 1,
                "kernel partition geometry and GPT disagree")
        node = Path("/dev") / name
        require(node.exists() and stat.S_ISBLK(node.stat().st_mode),
                "Linux guest partition block node absent")
        device = node.stat().st_rdev
        require(f"{os.major(device)}:{os.minor(device)}" not in mounted,
                "Windows or Pop target partition already mounted")
        if row["index"] in (5, 6):
            probe = subprocess.run(
                ["blkid", "-p", "-s", "TYPE", "-o", "value", str(node)],
                capture_output=True, text=True, timeout=10,
            )
            require(probe.returncode == 2 and not probe.stdout,
                    "Pop-owned partition preformatted or filesystem ambiguous")
    print("GASLUX_POP_LIVE_WIN10_SIX_GPT_READONLY_VERIFIED=1", flush=True)
    print("GASLUX_POP_LIVE_WIN10_DISK_GUID=" + m["diskGuid"], flush=True)
    print("GASLUX_POP_LIVE_WIN10_POP_ESP_GUID=" + m["popEspGuid"], flush=True)
    print("GASLUX_POP_LIVE_WIN10_POP_ROOT_GUID=" + m["popRootGuid"], flush=True)
    print("GASLUX_POP_LIVE_WIN10_REAL_DUALBOOT_VERIFIED=0", flush=True)
    print("GASLUX_POP_LIVE_WIN10_DISTINST_EXECUTED=0", flush=True)


if __name__ == "__main__":
    try:
        run_probe()
    except (Refusal, OSError, ValueError, KeyError, RuntimeError) as exc:
        print("GASLUX_POP_LIVE_WIN10_PREFLIGHT_FAILURE: " + str(exc),
              file=sys.stderr, flush=True)
        sys.exit(1)
