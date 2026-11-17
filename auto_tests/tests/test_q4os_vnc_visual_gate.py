"""Read-only Q4OS VNC pixel-region gate tests; no GUI or disk operations."""

import subprocess
import sys
from pathlib import Path

from PIL import Image

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from gaslux_q4os_vnc_visual_gate import (  # noqa: E402
    _CALAMARES_NEXT,
    _CALAMARES_WINDOW,
    _CALAMARES_LOCATION_WINDOW,
    _CALAMARES_LOCATION_NEXT,
    _EXPECTED_SCREEN,
    _ICON,
    _WELCOME_ALLOWED,
    _WELCOME_BOX,
    verified_after_close,
    verified_centre_changed,
    verified_native_calamares_welcome,
    verified_native_calamares_location,
    verified_q4os_welcome_desktop,
)

GATE = TOOLS / "gaslux_q4os_vnc_visual_gate.py"


def test_visual_gate_binds_pinned_two_regions_and_1280x800_shape():
    assert _EXPECTED_SCREEN == (1280, 800)
    assert _ICON == (
        (0, 0, 150, 160),
        "8503ab83390ec86930429be2620e8e96189a562e0e152bf0f7c1a58e5f425083",
    )
    assert _WELCOME_BOX == (300, 70, 975, 600)
    assert _WELCOME_ALLOWED == (
        "2d0d73d6ca27275d1dc716fef1965df06f12296c03a9dbdccb49cec106fc3d39",
        "525c8efc637b680933499b7ad2dae4d26cd4d8ca9aad0a94e6c077df929738e7",
    )


def test_refuse_unknown_blank_and_wrong_size_screenshots(tmp_path):
    blank = tmp_path / "blank.png"
    Image.new("RGB", (1280, 800), "black").save(blank)
    short = tmp_path / "wrong.png"
    Image.new("RGB", (640, 480), "black").save(short)
    for path in (blank, short, tmp_path / "missing.png"):
        assert not verified_q4os_welcome_desktop(path)
        assert not verified_after_close(path)
        result = subprocess.run(
            [sys.executable, str(GATE), "welcome", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0
        assert "REFUSED" in result.stderr


def test_refuse_symlinked_screenshot_even_if_png_content_is_valid(tmp_path):
    base = tmp_path / "actual.png"
    Image.new("RGB", (1280, 800), "black").save(base)
    link = tmp_path / "alias.png"
    link.symlink_to(base)
    assert not verified_q4os_welcome_desktop(link)
    assert not verified_after_close(link)
    assert not verified_centre_changed(link, base)


def test_post_launcher_clock_only_change_does_not_count(tmp_path):
    before = Image.new("RGB", (1280, 800), "black")
    after = before.copy()
    after.putpixel((1200, 790), (255, 255, 255))
    initial = tmp_path / "initial.png"
    final = tmp_path / "clock-changed.png"
    before.save(initial)
    after.save(final)
    assert not verified_centre_changed(initial, final)
    result = subprocess.run(
        [sys.executable, str(GATE), "changed-centre", str(initial), str(final)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_valid_centre_transition_is_not_automatically_installer_proof(tmp_path):
    before = Image.new("RGB", (1280, 800), "black")
    after = before.copy()
    after.putpixel((620, 320), (255, 255, 255))
    initial = tmp_path / "initial.png"
    final = tmp_path / "centre-changed.png"
    before.save(initial)
    after.save(final)
    assert verified_centre_changed(initial, final)
    assert not verified_q4os_welcome_desktop(initial)
    assert not verified_after_close(final)
    assert not verified_q4os_welcome_desktop(final)


def test_gate_refuses_unknown_command_without_trusting_png(tmp_path):
    fake = tmp_path / "screen.png"
    Image.new("RGB", (1280, 800), "black").save(fake)
    result = subprocess.run(
        [sys.executable, str(GATE), "install", str(fake)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "unknown Q4OS screenshot guard phase" in result.stderr


def test_real_calamares_welcome_exact_regions_pinned_to_two_verified_artifacts():
    assert _CALAMARES_WINDOW == (
        (128, 118, 1152, 667),
        "a451cb2b920944cfa5d80f904446b2ab86d3b4097b66b776abf86b4ffed3dd08",
    )
    assert _CALAMARES_NEXT == (
        (955, 619, 1044, 668),
        "c800cc03d280395a9e699e4b6216cb6d3d422c2dd40a54e6ceeca862220ea8e1",
    )


def test_refuse_native_welcome_navigation_when_screen_is_not_pinned(tmp_path):
    fake = tmp_path / "not-calamares.png"
    Image.new("RGB", (1280, 800), "black").save(fake)
    assert not verified_native_calamares_welcome(fake)
    process = subprocess.run(
        [sys.executable, str(GATE), "calamares-welcome", str(fake)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert process.returncode != 0
    assert "REFUSED" in process.stderr


def test_real_calamares_location_regions_bound_to_two_independent_qemu_artifacts():
    assert _CALAMARES_LOCATION_WINDOW == (
        (128, 118, 1152, 667),
        "449ed3c2023006430e6a872734e3cd5d0e212515adf9be5bb2165540fb8f0d19",
    )
    assert _CALAMARES_LOCATION_NEXT == (
        (961, 626, 1044, 663),
        "77799468f6fc2ec9dddd531bdcb376865c2176683af6e185fa6095c870ccac60",
    )


def test_refuse_location_next_when_screenshot_unknown_or_tampered(tmp_path):
    fake = tmp_path / "unknown-location.png"
    Image.new("RGB", (1280, 800), "black").save(fake)
    assert not verified_native_calamares_location(fake)
    result = subprocess.run(
        [sys.executable, str(GATE), "calamares-location", str(fake)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "REFUSED" in result.stderr
