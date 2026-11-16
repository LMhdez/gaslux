#!/usr/bin/env python3
"""Read QEMU VGA via monitor after a real installed Plasma/KWin guest marker."""
from __future__ import annotations

import argparse
import re
import socket
import sys
import time
from pathlib import Path


class GraphicsEvidenceError(ValueError):
    pass


def verify_ppm(path: Path) -> tuple[int, int, int]:
    blob = path.read_bytes()
    if not (16 < len(blob) < 45_000_000 and blob.startswith(b"P6")):
        raise GraphicsEvidenceError("QEMU screendump not a bounded binary PPM")
    index = 2

    def token() -> bytes:
        nonlocal index
        while index < len(blob):
            if blob[index] == 35:  # Netpbm comment
                index = blob.find(b"\n", index) + 1
            elif blob[index] in b" \t\r\n":
                index += 1
            else:
                break
        start = index
        while index < len(blob) and blob[index] not in b" \t\r\n":
            index += 1
        return blob[start:index]

    try:
        width, height, maxval = (int(token()) for _ in range(3))
    except ValueError as exc:
        raise GraphicsEvidenceError("malformed framebuffer dimensions") from exc
    if not (640 <= width <= 4096 and 480 <= height <= 4096 and maxval == 255):
        raise GraphicsEvidenceError("unexpected framebuffer geometry")
    index += 1  # the single whitespace delimiter after maxval
    pixels = blob[index:]
    if len(pixels) != width * height * 3:
        raise GraphicsEvidenceError("framebuffer pixels truncated or padded")
    # A black/text-mode/solid-color frame is not a rendered Plasma session.
    distinct: set[bytes] = set()
    interval = max(3, (len(pixels) // 2500 // 3) * 3)
    for offset in range(0, len(pixels) - 3, interval):
        distinct.add(pixels[offset:offset + 3])
        if len(distinct) >= 32:
            break
    if len(distinct) < 32:
        raise GraphicsEvidenceError("framebuffer lacks meaningful pixel diversity")
    return width, height, len(distinct)


def run(monitor: Path, image: Path) -> tuple[int, int, int]:
    if (not monitor.is_absolute() or not image.is_absolute()
            or monitor.is_symlink() or image.exists()
            or not re.fullmatch(r"/tmp/cachyos-real-boot-[A-Za-z0-9]+/plasma-session.ppm",
                                str(image))):
        raise GraphicsEvidenceError("monitor and output must be fresh lab-only paths")
    if not monitor.is_socket():
        raise GraphicsEvidenceError("QEMU monitor socket missing")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(3)
        conn.connect(str(monitor))
        transcript = bytearray()
        until = time.monotonic() + 12
        while time.monotonic() < until:
            data = conn.recv(4096)
            if not data:
                raise GraphicsEvidenceError("QEMU monitor closed")
            transcript.extend(data)
            if b"(qemu)" in transcript:
                break
        else:
            raise GraphicsEvidenceError("QEMU monitor not ready")
        conn.sendall(("screendump " + str(image) + "\n").encode("ascii"))
        until = time.monotonic() + 25
        while time.monotonic() < until:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                data = b""
            transcript.extend(data)
            if b"Error:" in transcript or b"error:" in transcript:
                raise GraphicsEvidenceError("QEMU screenshot command rejected")
            if image.is_file() and image.stat().st_size > 0:
                try:
                    return verify_ppm(image)
                except GraphicsEvidenceError:
                    time.sleep(0.25)  # QEMU may still be writing pixels
            if not data:
                time.sleep(0.25)
    raise GraphicsEvidenceError("QEMU did not produce a graphical framebuffer")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        width, height, colors = run(args.socket, args.output)
    except (OSError, GraphicsEvidenceError) as error:
        print(f"GASLUX_QEMU_GRAPHICS_PROOF_FAILURE: {error}", file=sys.stderr)
        return 1
    print(f"GASLUX_QEMU_INSTALLED_PLASMA_FRAMEBUFFER_VERIFIED=1 "
          f"width={width} height={height} sample_colors={colors}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
