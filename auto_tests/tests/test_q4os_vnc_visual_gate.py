"""Read-only Q4OS VNC pixel-region gate tests; no GUI or disk operations."""

import subprocess
import sys
from pathlib import Path

from PIL import Image

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from gaslux_q4os_vnc_visual_gate import (  # noqa: E402
    _EXPECTED_SCREEN,
    _ICON,
    _WELCOME_ALLOWED,
    _WELCOME_BOX,
    verified_after_close,
    verified_centre_changed,
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
