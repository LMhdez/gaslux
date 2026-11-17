#!/usr/bin/env python3
"""Bounded numeric-only QEMU VGA telemetry for disposable diskless WinPE.

No image ever leaves the owned private runner directory; only numeric
framebuffer statistics are returned. Not evidence of WinPE/Setup success.
"""
from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import re
import socket
import stat

from windows_x64_tcg_firstboot import LabError

MAX_SCREEN_BYTES = 16 * 1024 * 1024
HEADER = re.compile(rb"\AP6\s+([0-9]{1,5})\s+([0-9]{1,5})\s+255\s")
PRIVATE_ROOT = Path("/home/runner/work/_temp")
EXPECTED_SHOTS = frozenset(("winpe-vga-early.ppm", "winpe-vga-late.ppm"))


def require(ok: bool, message: str) -> None:
    if not ok:
        raise LabError(message)


def numeric_ppm(raw: bytes) -> dict[str, int]:
    require(0 < len(raw) <= MAX_SCREEN_BYTES, "missing/oversized QEMU framebuffer")
    match = HEADER.match(raw[:96])
    require(match is not None, "unexpected QEMU framebuffer format")
    width, height = int(match[1]), int(match[2])
    require(0 < width <= 4096 and 0 < height <= 2160,
            "unreasonable QEMU framebuffer geometry")
    data = raw[match.end():]
    require(len(data) == width * height * 3,
            "incomplete or oversized QEMU framebuffer")
    interval = max(1, width * height // 4096)
    samples = [tuple(data[i * 3:i * 3 + 3])
               for i in range(0, width * height, interval)]
    nonblack = sum(1 for r, g, b in samples if max(r, g, b) > 32)
    return {
        "width": width, "height": height,
        "sampleCount": len(samples),
        "uniqueRgbSampleCount": len(set(samples)),
        "nonBlackPercent": round(nonblack * 100 / len(samples)),
        "dominantRgbPercent": round(max(Counter(samples).values()) * 100
                                    / len(samples)),
    }


def verify_owned_paths(work: Path, monitor: Path, screenshot: Path) -> None:
    root = work.parent
    require(
        work.is_absolute() and work.is_dir() and not work.is_symlink()
        and work.name in ("fat12_floppy", "fat32_usb")
        and root.parent == PRIVATE_ROOT
        and root.name.startswith("gaslux-win-x64-")
        and root.resolve() == root and work.resolve() == work
        and root.stat().st_uid == os.getuid()
        and work.stat().st_uid == os.getuid()
        and stat.S_IMODE(root.stat().st_mode) == 0o700
        and stat.S_IMODE(work.stat().st_mode) == 0o700
        and monitor == work / "winpe-hmp.sock"
        and monitor.is_socket() and not monitor.is_symlink()
        and monitor.stat().st_uid == os.getuid()
        and screenshot.parent == work
        and screenshot.name in EXPECTED_SHOTS
        and not screenshot.exists() and not screenshot.is_symlink(),
        "refusing unowned WinPE private monitor/screendump paths",
    )


def capture_numeric_vga(work: Path, basename: str) -> dict[str, int]:
    monitor = work / "winpe-hmp.sock"
    screenshot = work / basename
    verify_owned_paths(work, monitor, screenshot)

    def to_hmp_prompt(conn: socket.socket) -> bytes:
        response = bytearray()
        while len(response) < 131072:
            chunk = conn.recv(8192)
            require(bool(chunk), "QEMU HMP closed before VGA response")
            response.extend(chunk)
            if b"(qemu) " in response:
                return bytes(response)
        raise LabError("QEMU HMP VGA response exceeds bounded limit")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5)
            conn.connect(str(monitor))
            require(b"QEMU" in to_hmp_prompt(conn),
                    "unexpected QEMU HMP monitor banner")
            conn.sendall(("screendump " + str(screenshot) + "\n").encode("ascii"))
            message = to_hmp_prompt(conn).lower()
            require(not any(error in message for error in
                            (b"error:", b"could not", b"unknown command", b"invalid")),
                    "QEMU rejected private framebuffer capture")
        require(screenshot.is_file() and not screenshot.is_symlink()
                and screenshot.stat().st_uid == os.getuid()
                and screenshot.stat().st_nlink == 1
                and stat.S_ISREG(screenshot.stat().st_mode)
                and 0 < screenshot.stat().st_size <= MAX_SCREEN_BYTES,
                "unowned or oversized screenshot")
        with screenshot.open("rb") as src:
            return numeric_ppm(src.read(MAX_SCREEN_BYTES + 1))
    finally:
        # Never log or upload raw pixels, even on a malformed PPM/error path.
        if (screenshot.is_file() and not screenshot.is_symlink()
                and screenshot.stat().st_uid == os.getuid()):
            screenshot.unlink()
