"""Q4OS first-run graphical VNC safety checks; no GUI or disk is touched here."""

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "gaslux_q4os_calamares_gui_laboratory.sh"


def test_graphical_lab_requires_explicit_disposable_actions_authorization(tmp_path):
    iso = tmp_path / "fake.iso"
    iso.write_bytes(b"not Q4OS")
    env = os.environ.copy()
    env.pop("GITHUB_ACTIONS", None)
    env["GASLUX_Q4OS_GRAPHICS_LAB_ONLY"] = "1"
    result = subprocess.run(
        ["bash", str(SCRIPT), "q4os", str(iso), "0" * 64],
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "Explicit disposable GitHub Actions graphics lab authorization missing" in result.stderr


def test_untrusted_official_hash_refused_before_graphics_or_disk_setup(tmp_path):
    iso = tmp_path / "fake.iso"
    iso.write_bytes(b"not Q4OS")
    env = os.environ.copy()
    env["GASLUX_Q4OS_GRAPHICS_LAB_ONLY"] = "1"
    env["GITHUB_ACTIONS"] = "true"
    result = subprocess.run(
        ["bash", str(SCRIPT), "q4os", str(iso), "0" * 64],
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "Official Q4OS 6.10 r2 SHA-256 is not the independently pinned digest" in result.stderr


def test_only_exact_inspected_modal_allows_one_mouse_click():
    source = SCRIPT.read_text(encoding="utf-8")
    assert (
        "expected_modal='da8d7c7f26051f0962152a99494001960f852f222104cb49be2a9962ef95aac8'"
        in source
    )
    assert '"$current" == "$expected_modal"' in source
    assert '"$selected_modal" -eq 0' in source
    assert "move 585 391 click 1" in source
    assert '"$dismissed_modal" -eq 1' in source
    assert "vnc-after-language.png" in source
    assert "GASLUX_Q4OS_PINNED_FIRST_RUN_PROMPT_VERIFIED" in source
    assert "NOT PROVEN: native Calamares job execution" in source
    assert "calamares -d" not in source
    assert "xfconf-query" not in source
    assert "xdotool" not in source


def test_only_new_disposable_disk_is_visible_to_qemu():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'truncate -s 32G "$work/efi-disk.img"' in source
    assert 'file="$work/efi-disk.img"' in source
    assert '"${iso_args[@]}"' in source
    assert "readonly=on,format=raw,file=$iso" in source
    assert "-net none" in source
    assert "-drive file=/dev/" not in source
    assert "GASLUX_Q4OS_GRAPHICS_LAB_ONLY" in source


def test_desktop_installer_icon_launch_is_separately_exact_image_gated():
    source = SCRIPT.read_text(encoding="utf-8")
    assert (
        "expected_desktop='231a01a5e394937808d71080dbb4f1a8e9da3bc52e61d80e2e5cdebce8d638d7'"
        in source
    )
    assert 'launch_installer="${GASLUX_Q4OS_LAUNCH_INSTALLER:-no}"' in source
    assert '"$current" == "$expected_desktop"' in source
    assert "move 948 93 click 1 pause 1 move 57 39 click 1 pause 0.3 click 1" in source
    assert "GASLUX_Q4OS_PINNED_DESKTOP_LAUNCHER_VERIFIED" in source
    assert "vnc-after-installer-icon.png" in source
    assert '"$launcher_clicked" -eq 1 && "$post_launcher_frame" -eq 1' in source
    assert "NOT PROVEN: Calamares executable actually started" in source
    assert "calamares -d" not in source


def test_unknown_gui_mode_refused_before_disk_mutation(tmp_path):
    iso = tmp_path / "fake.iso"
    iso.write_bytes(b"synthetic")
    env = os.environ.copy()
    env["GASLUX_Q4OS_GRAPHICS_LAB_ONLY"] = "1"
    env["GASLUX_Q4OS_LAUNCH_INSTALLER"] = "untrusted"
    env["GITHUB_ACTIONS"] = "true"
    result = subprocess.run(
        ["bash", str(SCRIPT), "q4os", str(iso), "0" * 64],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Unrecognized Q4OS GUI launch laboratory mode" in result.stderr
