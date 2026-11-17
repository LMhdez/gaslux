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


def _open_verified_screen(path: Path) -> Image.Image | None:
    if not isinstance(path, Path) or not path.is_absolute():
        return None
    try:
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or not 0 < meta.st_size < 2 * 1024 * 1024:
            return None
        with Image.open(path) as source:
            if source.size != _EXPECTED_SCREEN:
                return None
            return source.convert("RGB")
    except (OSError, ValueError, UnidentifiedImageError, SyntaxError):
        return None


def _roi_sha(image: Image.Image, box: tuple[int, int, int, int]) -> str:
    return hashlib.sha256(image.crop(box).tobytes()).hexdigest()


def verified_q4os_welcome_desktop(path: Path) -> bool:
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return all(_roi_sha(screen, box) == expected for box, expected in (_ICON, _WELCOME))


def verified_after_close(path: Path) -> bool:
    """Before clicking installer, verify icon remains same and welcome is gone."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return (
        _roi_sha(screen, _ICON[0]) == _ICON[1]
        and _roi_sha(screen, _WELCOME[0]) != _WELCOME[1]
    )


def verified_centre_changed(before: Path, after: Path) -> bool:
    """Taskbar-clock updates alone must never satisfy a GUI transition."""
    previous = _open_verified_screen(before)
    current = _open_verified_screen(after)
    if previous is None or current is None:
        return False
    return _roi_sha(previous, _WELCOME[0]) != _roi_sha(current, _WELCOME[0])


def main() -> int:
    if len(sys.argv) < 3:
        print("REFUSED: expected mode and Q4OS VNC screenshot path", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    if mode == "welcome" and len(sys.argv) == 3:
        passed = verified_q4os_welcome_desktop(Path(sys.argv[2]))
    elif mode == "after-close" and len(sys.argv) == 3:
        passed = verified_after_close(Path(sys.argv[2]))
    elif mode == "changed-centre" and len(sys.argv) == 4:
        passed = verified_centre_changed(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        print("REFUSED: unknown Q4OS screenshot guard phase", file=sys.stderr)
        return 2
    if passed:
        print(f"GASLUX_Q4OS_VNC_GUARD_{mode.upper().replace('-', '_')}=passed")
        return 0
    print(f"REFUSED: Q4OS screenshot guard did not validate: {mode}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
