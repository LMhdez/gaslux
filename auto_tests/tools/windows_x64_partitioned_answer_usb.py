#!/usr/bin/env python3
"""Test-only FAT32 partitioned USB answer image for disposable Windows KVM.

Never accepts /dev paths, real disks, an existing output, or a non-hosted runner.
The sole distinction from the earlier superfloppy lab is a conventional MBR
containing one FAT32 LBA partition beginning at sector 2048.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import struct
import subprocess

SECTOR = 512
IMAGE_BYTES = 64 * 1024 * 1024
FIRST_LBA = 2048
PART_LBAS = IMAGE_BYTES // SECTOR - FIRST_LBA
PART_OFFSET = FIRST_LBA * SECTOR
PART_BLOCKS_1024 = PART_LBAS * SECTOR // 1024
LABEL = b"GASLUXCI   "
CONSENT = "I_ACCEPT_GITHUB_HOSTED_DISPOSABLE_FAT32_MBR_USB_IMAGE_ONLY"


class PartitionedUsbError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise PartitionedUsbError(message)


def mbr_sector() -> bytes:
    data = bytearray(SECTOR)
    data[446:462] = (
        b"\x00\xfe\xff\xff\x0c\xfe\xff\xff"
        + struct.pack("<II", FIRST_LBA, PART_LBAS)
    )
    data[510:512] = b"\x55\xaa"
    return bytes(data)


def validate_mbr_and_bpb(mbr: bytes, fat_boot: bytes) -> None:
    require(len(mbr) == SECTOR and mbr == mbr_sector(),
            "answer USB MBR has changed or contains an extra partition")
    require(len(fat_boot) == SECTOR and fat_boot[510:512] == b"\x55\xaa"
            and fat_boot[82:90] == b"FAT32   "
            and fat_boot[71:82] == LABEL
            and struct.unpack_from("<H", fat_boot, 11)[0] == SECTOR
            and struct.unpack_from("<I", fat_boot, 28)[0] == FIRST_LBA
            and struct.unpack_from("<I", fat_boot, 32)[0] == PART_LBAS,
            "partitioned FAT32 BPB, identity or geometry differs")


def inspect_partitioned_image(image: Path) -> None:
    require(image.is_file() and not image.is_symlink()
            and stat.S_ISREG(image.stat().st_mode)
            and image.stat().st_size == IMAGE_BYTES
            and image.stat().st_uid == os.getuid()
            and image.stat().st_nlink == 1,
            "answer image is not a unique owned regular 64MiB file")
    with image.open("rb") as fp:
        mbr = fp.read(SECTOR)
        fp.seek(PART_OFFSET)
        fat_boot = fp.read(SECTOR)
    validate_mbr_and_bpb(mbr, fat_boot)


def build_partitioned_answer(image: Path, xml: Path, powershell: Path) -> None:
    workspace = image.parent
    root = Path("/home/runner/work/_temp")
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GASLUX_PARTITIONED_ANSWER_CONSENT") == CONSENT
        and image.is_absolute() and image.name == "only-disposable-answer-usb.img"
        and workspace.parent == root and workspace.name.startswith("gaslux-win-x64-")
        and workspace.is_dir() and not workspace.is_symlink()
        and workspace.resolve() == workspace
        and workspace.stat().st_uid == os.getuid()
        and stat.S_IMODE(workspace.stat().st_mode) == 0o700
        and not image.exists() and not image.is_symlink(),
        "partitioned answer image requires an unused private hosted-runner file",
    )
    for expected, target in (("Autounattend.xml", xml), ("GASLUX.PS1", powershell)):
        require(target.parent == workspace and target.name == expected
                and target.is_file() and not target.is_symlink()
                and target.stat().st_uid == os.getuid()
                and target.stat().st_nlink == 1
                and 0 < target.stat().st_size < 128 * 1024,
                "answer content is not the owned bounded source: " + expected)
    # Use O_EXCL: never replace any file even in the private scratch directory.
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(image, flags, 0o600)
    try:
        os.ftruncate(fd, IMAGE_BYTES)
        require(os.pwrite(fd, mbr_sector(), 0) == SECTOR, "short MBR write")
        os.fsync(fd)
    finally:
        os.close(fd)
    commands = (
        ["mkfs.vfat", "-F", "32", "-n", "GASLUXCI", "--offset=2048",
         "-h", str(FIRST_LBA), str(image), str(PART_BLOCKS_1024)],
        ["mcopy", "-i", str(image) + "@@1M", str(xml), "::/Autounattend.xml"],
        ["mcopy", "-i", str(image) + "@@1M", str(powershell), "::/GASLUX.PS1"],
    )
    for command in commands:
        try:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, timeout=45)
        except (OSError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired) as error:
            # Do not include any guest account, XML or other command output.
            raise PartitionedUsbError(
                "owned partitioned answer image FAT32 creation failed"
            ) from None
    inspect_partitioned_image(image)
    # mtype reads the private image, not a host block device or mounted volume.
    for source, dest in ((xml, "::/Autounattend.xml"),
                         (powershell, "::/GASLUX.PS1")):
        try:
            readback = subprocess.run(
                ["mtype", "-i", str(image) + "@@1M", dest],
                check=True, capture_output=True, timeout=20,
            ).stdout
        except (OSError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired):
            raise PartitionedUsbError(
                "cannot read back the partitioned answer image"
            ) from None
        require(readback == source.read_bytes(),
                "partitioned answer image readback disagrees with source bytes")
    inspect_partitioned_image(image)
