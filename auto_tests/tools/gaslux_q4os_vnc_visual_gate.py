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
_WELCOME_BOX = (300, 70, 975, 600)
# Both different Q4OS Welcome window positions were visually reviewed:
# - #43990554360/#14287807199 (Q4OS Welcome top edge y79)
# - #43991676156/#14288043285 (Q4OS Welcome top edge y71)
# The full panel moves a few pixels between boots; each allowed variant is
# pinned to its complete exact RGB crop, never matched by fuzzy resemblance.
_WELCOME_ALLOWED = (
    "2d0d73d6ca27275d1dc716fef1965df06f12296c03a9dbdccb49cec106fc3d39",
    "525c8efc637b680933499b7ad2dae4d26cd4d8ca9aad0a94e6c077df929738e7",
)
# Official Q4OS Andromeda native Calamares Welcome GUI from two independent
# successful QEMU runs: #43992830893/#14289030650 and
# #43992867613/#14287189577. These *two exact* RGB pixel regions
# verify the actual Calamares welcome+Next button before any wizard input.
_CALAMARES_WINDOW = (
    (128, 118, 1152, 667),
    "a451cb2b920944cfa5d80f904446b2ab86d3b4097b66b776abf86b4ffed3dd08",
)
_CALAMARES_NEXT = (
    (955, 619, 1044, 668),
    "c800cc03d280395a9e699e4b6216cb6d3d422c2dd40a54e6ceeca862220ea8e1",
)
# Independently matched RGB regions in two authentic Q4OS Location-page QEMU
# screenshots: Actions #43994316796/#14289276889 and
# #43994241710/#14289032417. Clocks/desktop outside this exact crop differ.
# This gate may authorize only one non-destructive Location -> Keyboard Next.
_CALAMARES_LOCATION_WINDOW = (
    (128, 118, 1152, 667),
    "449ed3c2023006430e6a872734e3cd5d0e212515adf9be5bb2165540fb8f0d19",
)
_CALAMARES_LOCATION_NEXT = (
    (961, 626, 1044, 663),
    "77799468f6fc2ec9dddd531bdcb376865c2176683af6e185fa6095c870ccac60",
)
# Official Q4OS ISO / native Calamares Keyboard view, verified by manual
# inspection of CI #44139349156, artifact #14353932390.
# The same exact crops were unchanged across four screenshots in that run.
# Only permits one non-destructive Keyboard -> Software Next click.
_CALAMARES_KEYBOARD_WINDOW = (
    (128, 118, 1152, 667),
    "570830d10805331de7e4ec4b6d10603c58f899517d2696a0447e952ee92ea588",
)
_CALAMARES_KEYBOARD_NEXT = (
    (960, 626, 1044, 663),
    "157a5d9d73c5c231ea486fa09312969567e247701384f51ee4f3cf4c20ed22b9",
)
# Official Q4OS 6.10 r2 Calamares Software screen, two independent
# 17 Nov QEMU runs: #44147193591/#14357786943 and #44147341109/#14357482399.
# None had any package/profile selected and Next was disabled.
_CALAMARES_SOFTWARE_WINDOW = (
    (128, 118, 1152, 667),
    "a3ca14d75d281ca13f387cbe9e3b07cf3ce90297034d36c6f46887915b4dfd7b",
)
_CALAMARES_SOFTWARE_PROFILE = (
    (327, 155, 500, 249),
    "2832aaeac6d7d6c3f008071a6fe7261d327efeeeee2c38a33aeb960749fd674e",
)
# Q4OS Desktop selected, native Calamares Software. Screenshots visually
# checked from separate official QEMU runs #44148940688/#14357204402 and
# #44149051278/#14357149677. Only ONE Next to observe Partitions is allowed.
_CALAMARES_DESKTOP_SELECTED_WINDOW = (
    (128, 118, 1152, 667),
    "4aa94d654bb23e5d0bf33af141112e4e086766f0484063dac7310a62f26ead70",
)
_CALAMARES_DESKTOP_NEXT = (
    (961, 626, 1044, 663),
    "2c31f373af722d9d51f946a8179a190e19c2c9e3fa2a786aa6e98efed8b65d6b",
)
# Three stable, exact RGB regions independently extracted from the official
# Q4OS 6.10 r2 Calamares Partitions screenshot in CI #44150534763,
# artifact #14359910610 (vnc-partitions-page.png). This does NOT grant
# storage-write or native installation permission: only a radio-button
# click on a SYNTHETIC, signed, snapshot-owned COW may follow.
_CALAMARES_SYNTHETIC_PARTITIONS_DEVICE = (
    (320, 146, 851, 189),
    "6975d6f85bebbb4dcd444c9bcdaa6f776880d8a9b5ff361e34b0829684cfb762",
)
_CALAMARES_SYNTHETIC_PARTITIONS_MAP = (
    (324, 534, 1143, 604),
    "c62608a7994f551be49ac138c245ab4c11d78c148671b827c2ceda2ac274219e",
)
_CALAMARES_SYNTHETIC_PARTITIONS_NEXT = (
    (957, 622, 1051, 663),
    "0416af48c325376e056f6ef8707b2ebdaedca7f935f2ddf8fc37bc93684d9512",
)
# Exact RGB regions from the successful, owned-COW radio-selected screenshot
# artifact #14528830855 / run #44520990890. This authorizes only one
# Partitions -> Users navigation click; it does not authorize storage writes.
_CALAMARES_SYNTHETIC_PARTITIONS_SELECTED_DEVICE = (
    (320, 146, 851, 189),
    "6975d6f85bebbb4dcd444c9bcdaa6f776880d8a9b5ff361e34b0829684cfb762",
)
_CALAMARES_SYNTHETIC_PARTITIONS_SELECTED_MAP = (
    (324, 534, 1143, 604),
    "fd5f08fbf49f7aa64c97690b7110cff4ed6b8aca17f76c95bfd8f0a1db61b743",
)
_CALAMARES_SYNTHETIC_PARTITIONS_SELECTED_NEXT = (
    (957, 622, 1051, 663),
    "7790dafec77bcc08aaeb33c5a36d74662d9cb6d4094b59ae3c543ae4da1ccc41",
)
_CALAMARES_SYNTHETIC_PARTITIONS_SELECTED_RADIO = (
    (320, 250, 350, 310),
    "be18b916129a47587ca7fc6576d18f275828679c494302d406abff24a5e6b145",
)
# Stable RGB regions independently reviewed in the native Q4OS 6.10 r2
# Users page screenshot from Actions run #44544993517. The gate is
# observation-only: no user data, password, or Next/Install action is allowed.
_CALAMARES_USERS_TITLE_PAGE = (
    (128, 118, 1152, 180),
    "b565add1ff9d5061918278f5cd8871a26b136dfdb04df78e6bcf74c8341b41e5",
)
_CALAMARES_USERS_SIDEBAR = (
    (128, 436, 318, 478),
    "afabb9afa668803a507dac9a4458cc51b54dbda969162f5f248034142c773693",
)
_CALAMARES_USERS_FIELDS = (
    (320, 220, 740, 365),
    "85f768249afb41deec46b9361dfd4a886bac27f367c82555d4477f394bc3ecd4",
)
_CALAMARES_USERS_PASSWORD_VALIDATION = (
    (320, 365, 850, 480),
    "4020b9656b5d9e434b24e2ecf884920c4652cfb6ba5f20c3307bfdb35c20b93a",
)
_CALAMARES_USERS_DISABLED_NEXT = (
    (957, 622, 1051, 663),
    "0416af48c325376e056f6ef8707b2ebdaedca7f935f2ddf8fc37bc93684d9512",
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
    return (
        _roi_sha(screen, _ICON[0]) == _ICON[1]
        and _roi_sha(screen, _WELCOME_BOX) in _WELCOME_ALLOWED
    )


def verified_after_close(path: Path) -> bool:
    """Before clicking installer, verify icon remains same and welcome is gone."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return (
        _roi_sha(screen, _ICON[0]) == _ICON[1]
        and _roi_sha(screen, _WELCOME_BOX) not in _WELCOME_ALLOWED
    )


def verified_native_calamares_welcome(path: Path) -> bool:
    """Allow a single, non-installing Next click only on pinned Calamares Welcome."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return all(
        _roi_sha(screen, box) == expected for box, expected in (_CALAMARES_WINDOW, _CALAMARES_NEXT)
    )


def verified_native_calamares_location(path: Path) -> bool:
    """Allow only Location -> Keyboard Next on independently pinned pixels."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return (
        _roi_sha(screen, _CALAMARES_LOCATION_WINDOW[0]) == _CALAMARES_LOCATION_WINDOW[1]
        and _roi_sha(screen, _CALAMARES_LOCATION_NEXT[0]) == _CALAMARES_LOCATION_NEXT[1]
    )


def verified_native_calamares_keyboard(path: Path) -> bool:
    """Keyboard -> Software is permitted ONLY for exact pinned Calamares pixels."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return (
        _roi_sha(screen, _CALAMARES_KEYBOARD_WINDOW[0]) == _CALAMARES_KEYBOARD_WINDOW[1]
        and _roi_sha(screen, _CALAMARES_KEYBOARD_NEXT[0]) == _CALAMARES_KEYBOARD_NEXT[1]
    )


def verified_native_calamares_software_unselected(path: Path) -> bool:
    """Allow only a Q4OS Desktop selection on the pinned unselected Software view."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return (
        _roi_sha(screen, _CALAMARES_SOFTWARE_WINDOW[0]) == _CALAMARES_SOFTWARE_WINDOW[1]
        and _roi_sha(screen, _CALAMARES_SOFTWARE_PROFILE[0]) == _CALAMARES_SOFTWARE_PROFILE[1]
    )


def verified_native_calamares_desktop_selected(path: Path) -> bool:
    """Allow Software -> Partitions only on a previously pinned Q4OS Desktop view."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return (
        _roi_sha(screen, _CALAMARES_DESKTOP_SELECTED_WINDOW[0])
        == _CALAMARES_DESKTOP_SELECTED_WINDOW[1]
        and _roi_sha(screen, _CALAMARES_DESKTOP_NEXT[0]) == _CALAMARES_DESKTOP_NEXT[1]
    )


def verified_synthetic_calamares_partitions_view(path: Path) -> bool:
    """Permit ONLY a synthetic-COW radio selection, never 'Next' or Install."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return all(
        _roi_sha(screen, box) == digest
        for box, digest in (
            _CALAMARES_SYNTHETIC_PARTITIONS_DEVICE,
            _CALAMARES_SYNTHETIC_PARTITIONS_MAP,
            _CALAMARES_SYNTHETIC_PARTITIONS_NEXT,
        )
    )


def verified_synthetic_calamares_partitions_selected(path: Path) -> bool:
    """Permit one Next click only on the exact radio-selected synthetic COW view."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return all(
        _roi_sha(screen, box) == digest
        for box, digest in (
            _CALAMARES_SYNTHETIC_PARTITIONS_SELECTED_DEVICE,
            _CALAMARES_SYNTHETIC_PARTITIONS_SELECTED_MAP,
            _CALAMARES_SYNTHETIC_PARTITIONS_SELECTED_NEXT,
            _CALAMARES_SYNTHETIC_PARTITIONS_SELECTED_RADIO,
        )
    )


def verified_native_calamares_users(path: Path) -> bool:
    """Verify the native Users page without authorizing any form interaction."""
    screen = _open_verified_screen(path)
    if screen is None:
        return False
    return all(
        _roi_sha(screen, box) == digest
        for box, digest in (
            _CALAMARES_USERS_TITLE_PAGE,
            _CALAMARES_USERS_SIDEBAR,
            _CALAMARES_USERS_FIELDS,
            _CALAMARES_USERS_PASSWORD_VALIDATION,
            _CALAMARES_USERS_DISABLED_NEXT,
        )
    )


def verified_centre_changed(before: Path, after: Path) -> bool:
    """Taskbar-clock updates alone must never satisfy a GUI transition."""
    previous = _open_verified_screen(before)
    current = _open_verified_screen(after)
    if previous is None or current is None:
        return False
    return _roi_sha(previous, _WELCOME_BOX) != _roi_sha(current, _WELCOME_BOX)


def main() -> int:
    if len(sys.argv) < 3:
        print("REFUSED: expected mode and Q4OS VNC screenshot path", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    if mode == "welcome" and len(sys.argv) == 3:
        passed = verified_q4os_welcome_desktop(Path(sys.argv[2]))
    elif mode == "after-close" and len(sys.argv) == 3:
        passed = verified_after_close(Path(sys.argv[2]))
    elif mode == "calamares-welcome" and len(sys.argv) == 3:
        passed = verified_native_calamares_welcome(Path(sys.argv[2]))
    elif mode == "calamares-location" and len(sys.argv) == 3:
        passed = verified_native_calamares_location(Path(sys.argv[2]))
    elif mode == "calamares-keyboard" and len(sys.argv) == 3:
        passed = verified_native_calamares_keyboard(Path(sys.argv[2]))
    elif mode == "calamares-software-unselected" and len(sys.argv) == 3:
        passed = verified_native_calamares_software_unselected(Path(sys.argv[2]))
    elif mode == "calamares-desktop-selected" and len(sys.argv) == 3:
        passed = verified_native_calamares_desktop_selected(Path(sys.argv[2]))
    elif mode == "calamares-synthetic-cow-partitions" and len(sys.argv) == 3:
        passed = verified_synthetic_calamares_partitions_view(Path(sys.argv[2]))
    elif mode == "calamares-synthetic-cow-partitions-selected" and len(sys.argv) == 3:
        passed = verified_synthetic_calamares_partitions_selected(Path(sys.argv[2]))
    elif mode == "calamares-users" and len(sys.argv) == 3:
        passed = verified_native_calamares_users(Path(sys.argv[2]))
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
