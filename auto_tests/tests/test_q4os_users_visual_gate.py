"""Fail-closed regression tests for the native Q4OS Calamares Users-page gate."""

import sys
from pathlib import Path

from PIL import Image

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from gaslux_q4os_vnc_visual_gate import (  # noqa: E402
    _CALAMARES_USERS_DISABLED_NEXT,
    _CALAMARES_USERS_FIELDS,
    _CALAMARES_USERS_PASSWORD_VALIDATION,
    _CALAMARES_USERS_SIDEBAR,
    _CALAMARES_USERS_TITLE_PAGE,
    _EXPECTED_SCREEN,
    verified_native_calamares_users,
)


def test_users_gate_pins_five_independent_regions():
    assert _EXPECTED_SCREEN == (1280, 800)
    assert _CALAMARES_USERS_TITLE_PAGE == (
        (128, 118, 1152, 180),
        "b565add1ff9d5061918278f5cd8871a26b136dfdb04df78e6bcf74c8341b41e5",
    )
    assert _CALAMARES_USERS_SIDEBAR == (
        (128, 436, 318, 478),
        "afabb9afa668803a507dac9a4458cc51b54dbda969162f5f248034142c773693",
    )
    assert _CALAMARES_USERS_FIELDS == (
        (320, 220, 740, 365),
        "85f768249afb41deec46b9361dfd4a886bac27f367c82555d4477f394bc3ecd4",
    )
    assert _CALAMARES_USERS_PASSWORD_VALIDATION == (
        (320, 365, 850, 480),
        "4020b9656b5d9e434b24e2ecf884920c4652cfb6ba5f20c3307bfdb35c20b93a",
    )
    assert _CALAMARES_USERS_DISABLED_NEXT == (
        (957, 622, 1051, 663),
        "0416af48c325376e056f6ef8707b2ebdaedca7f935f2ddf8fc37bc93684d9512",
    )


def test_users_gate_rejects_blank_and_wrong_size_screenshots(tmp_path):
    blank = tmp_path / "blank.png"
    Image.new("RGB", (1280, 800), "black").save(blank)
    wrong_size = tmp_path / "wrong-size.png"
    Image.new("RGB", (640, 480), "black").save(wrong_size)
    assert not verified_native_calamares_users(blank)
    assert not verified_native_calamares_users(wrong_size)


def test_users_gate_rejects_symlinked_screenshot(tmp_path):
    original = tmp_path / "original.png"
    Image.new("RGB", (1280, 800), "black").save(original)
    alias = tmp_path / "alias.png"
    alias.symlink_to(original)
    assert not verified_native_calamares_users(alias)
