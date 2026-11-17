#!/usr/bin/env python3
"""Bounded, private VGA occupancy diagnostic for a disposable Windows QEMU.

Only numeric colour/layout statistics are logged. The raw screenshot lives
briefly in the 0700 GitHub-hosted runner workspace and is never an artifact.
It is NOT Windows Setup, WinRE, BCD or boot verification.
"""
from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import re
import socket
import stat

from windows_x64_tcg_firstboot import LabError, require_owned_hmp_socket

MAX_SCREEN_BYTES = 16 * 1024 * 1024
HEADER = re.compile(rb"\AP6\s+([0-9]{1,5})\s+([0-9]{1,5})\s+255\s")


def require(ok: bool, error: str) -> None:
    if not ok:
        raise LabError(error)


def numeric_ppm_stats(raw: bytes) -> dict[str, int]:
    """Parse only bounded binary P6 PPM, no OCR, image logging or persistence."""
    require(0 < len(raw) <= MAX_SCREEN_BYTES, "missing/oversized VGA snapshot")
    match = HEADER.match(raw[:96])
    require(match is not None, "unexpected QEMU VGA screenshot format")
    width, height = int(match[1]), int(match[2])
    require(0 < width <= 4096 and 0 < height <= 2160,
            "unreasonable QEMU framebuffer geometry")
    pixels = raw[match.end():]
    require(len(pixels) == width * height * 3,
            "incomplete or oversized QEMU VGA framebuffer")
    every = max(1, width * height // 4096)
    sampled = [
        tuple(pixels[i * 3:i * 3 + 3])
        for i in range(0, width * height, every)
    ]
    unique = len(set(sampled))
    nonblack = sum(1 for r, g, b in sampled if max(r, g, b) > 32)
    dominant = max(Counter(sampled).values())
    return {
        "width": width,
        "height": height,
        "sampleCount": len(sampled),
        "uniqueRgbSampleCount": unique,
        "nonBlackPercent": round(100 * nonblack / len(sampled)),
        "dominantRgbPercent": round(100 * dominant / len(sampled)),
    }


def capture_owned_qemu_vga(monitor: Path, out: Path) -> dict[str, int]:
    """Request HMP screendump only to a fresh file in our private VM directory."""
    require_owned_hmp_socket(monitor)
    require(out.is_absolute()
            and out.parent == monitor.parent
            and out.name in ("first-stage-vga-early.ppm",
                             "first-stage-vga-timeout.ppm",
                             "diskless-vga-test.ppm")
            and not out.exists() and not out.is_symlink(),
            "refusing unowned or preexisting QEMU VGA destination")

    def until_prompt(conn: socket.socket) -> bytes:
        data = bytearray()
        while len(data) < 131072:
            fragment = conn.recv(8192)
            require(bool(fragment), "QEMU HMP closed before VGA acknowledgment")
            data.extend(fragment)
            if b"(qemu) " in data:
                return bytes(data)
        raise LabError("QEMU VGA HMP response exceeded allowed size")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(4)
            conn.connect(str(monitor))
            banner = until_prompt(conn)
            require(b"QEMU" in banner, "unexpected QEMU VGA HMP banner")
            conn.sendall(("screendump " + str(out) + "\n").encode("ascii"))
            response = until_prompt(conn).lower()
            require(not any(message in response for message in (
                b"error:", b"could not", b"unknown command", b"invalid",
            )), "QEMU failed to create VGA snapshot")
        require(out.is_file() and not out.is_symlink()
                and out.stat().st_uid == os.getuid()
                and stat.S_ISREG(out.stat().st_mode)
                and 0 < out.stat().st_size <= MAX_SCREEN_BYTES,
                "unowned, missing or oversized QEMU screenshot")
        with out.open("rb") as image:
            content = image.read(MAX_SCREEN_BYTES + 1)
        return numeric_ppm_stats(content)
    finally:
        # The exact destination was absent under the owned 0700 workspace.
        # Never archive framebuffer screenshots: Windows GUI may contain data.
        if (out.is_file() and not out.is_symlink()
                and out.stat().st_uid == os.getuid()):
            out.unlink()
