#!/usr/bin/env python3
"""Read-only screenshot gate for *one* Q4OS 6.10 live-desktop action.

The SHA-256 values below came from a previously inspected successful
official-ISO QEMU/VNC artifact #14287807199 (Actions #43990554360).
Full-image PNG SHA is NOT stable because the system clock in the taskbar
changes. Both independent display regions are invariant across five
prior VNC screenshots. This script never sends input or opens a disk.
"""

from __future__ import annotations

import hashlib
import stat
import sys
from pathlib import Path

from PIL import Image, UnidentifiedImageError

_EXPECTED_SCREEN = (1280, 800)
# Exact (x1,y1,x2,y2) and RGB pixel SHA of the desktop Install Q4OS icon.
_ICON = ((0, 0, 150, 160), "8503ab83390ec86930429be2620e8e96189a562e0e152bf0f7c1a58e5f425083")
# Exact Q4OS welcome dialogue in the centre of the first-run desktop.
_WELCOME = (
    (300, 70, 975, 600),
    "2d0d73d6ca27275d1dc716fef1965df06f12296c03a9dbdccb49cec106fc3d39",
)


def verified_q4os_welcome_desktop(path: Path) -> bool:
    if not isinstance(path, Path) or not path.is_absolute():
        return False
    try:
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or not 0 < meta.st_size < 2 * 1024 * 1024:
            return False
        with Image.open(path) as source:
            if source.size != _EXPECTED_SCREEN:
                return False
            # Convert explicitly so indexed/RGBA/png encoding differences do
            # not weaken the verified visual content, dimensions or geometry.
            pixels = source.convert("RGB")
            return all(
                hashlib.sha256(pixels.crop(box).tobytes()).hexdigest() == expected
                for box, expected in (_ICON, _WELCOME)
            )
    except (OSError, ValueError, UnidentifiedImageError, SyntaxError):
        return False


def main() -> int:
    if len(sys.argv) != 2:
        print("REFUSED: expected one Q4OS VNC screenshot path", file=sys.stderr)
        return 2
    if verified_q4os_welcome_desktop(Path(sys.argv[1])):
        print("GASLUX_Q4OS_DESKTOP_CROPS_VERIFIED=icon+welcome:1280x800")
        return 0
    print("REFUSED: Q4OS screenshot regions differ from prior verified ISO", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
