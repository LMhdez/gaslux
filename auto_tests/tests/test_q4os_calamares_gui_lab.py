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


def test_desktop_launcher_requires_pixel_attestations_and_closed_welcome():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'launch_installer="${GASLUX_Q4OS_LAUNCH_INSTALLER:-no}"' in source
    assert 'visual_gate="$(dirname "$0")/gaslux_q4os_vnc_visual_gate.py"' in source
    assert 'python3 "$visual_gate" welcome "$work/vnc-$tick.png"' in source
    assert "move 948 93 click 1" in source
    assert 'python3 "$visual_gate" after-close "$work/vnc-before-icon-click.png"' in source
    assert "move 57 39 click 1 pause 0.3 click 1" in source
    assert 'python3 "$visual_gate" changed-centre' in source
    assert "GASLUX_Q4OS_PINNED_DESKTOP_LAUNCHER_VERIFIED" in source
    assert "vnc-after-installer-icon.png" in source
    assert '"$launcher_clicked" -eq 1 && "$post_launcher_frame" -eq 1' in source
    assert (
        "NOT PROVEN: Calamares GUI identity unless screenshot is independently reviewed." in source
    )
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


def test_calamares_welcome_to_location_is_source_gated_and_never_installs():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'advance_welcome="${GASLUX_Q4OS_ADVANCE_WELCOME:-no}"' in source
    assert "Calamares page navigation requires the verified desktop launcher" in source
    assert 'python3 "$visual_gate" calamares-welcome "$work/vnc-after-installer-icon.png"' in source
    assert "move 1002 644 click 1" in source
    assert "vnc-location-page.png" in source
    assert '"$calamares_welcome_next_clicked" -eq 1 && "$calamares_location_frame" -eq 1' in source
    assert "NOT PERFORMED: partition choice, user setup, Install confirmation" in source
    assert "calamares -d" not in source
    # Only the temporary lab-created FAT32 ESP may be formatted; no Linux root.
    assert 'mkfs.vfat -F 32 -n GASLUXLAB "$work/efi-part.img"' in source
    assert "mkfs.ext4" not in source
    assert "mkfs.xfs" not in source
    assert "mkfs.btrfs" not in source
    assert "mkfs.ntfs" not in source


def test_welcome_next_opt_in_requires_exact_gui_launcher_mode(tmp_path):
    iso = tmp_path / "fake.iso"
    iso.write_bytes(b"synthetic")
    env = os.environ.copy()
    env["GASLUX_Q4OS_GRAPHICS_LAB_ONLY"] = "1"
    env["GITHUB_ACTIONS"] = "true"
    env["GASLUX_Q4OS_LAUNCH_INSTALLER"] = "no"
    env["GASLUX_Q4OS_ADVANCE_WELCOME"] = "yes"
    result = subprocess.run(
        ["bash", str(SCRIPT), "q4os", str(iso), "0" * 64],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Calamares page navigation requires the verified desktop launcher" in result.stderr


def test_calamares_location_to_keyboard_requires_exact_image_and_never_installs():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'advance_location="${GASLUX_Q4OS_ADVANCE_LOCATION:-no}"' in source
    assert "Calamares Location navigation requires SHA-verified Welcome step" in source
    assert 'python3 "$visual_gate" calamares-location "$work/vnc-location-page.png"' in source
    assert '"$calamares_location_next_clicked" -eq 1 && "$calamares_keyboard_frame" -eq 1' in source
    assert "vnc-keyboard-page.png" in source
    assert (
        "NOT PROVEN: Keyboard screen identity without independent screenshot inspection." in source
    )
    assert "NOT PERFORMED: partition choice, user setup, Install confirmation" in source
    assert "mkfs.ext4" not in source
    assert "calamares -d" not in source


def test_location_opt_in_without_verified_welcome_refused_before_disk_setup(tmp_path):
    iso = tmp_path / "fake.iso"
    iso.write_bytes(b"not Q4OS")
    env = os.environ.copy()
    env["GITHUB_ACTIONS"] = "true"
    env["GASLUX_Q4OS_GRAPHICS_LAB_ONLY"] = "1"
    env["GASLUX_Q4OS_LAUNCH_INSTALLER"] = "yes"
    env["GASLUX_Q4OS_ADVANCE_WELCOME"] = "no"
    env["GASLUX_Q4OS_ADVANCE_LOCATION"] = "yes"
    result = subprocess.run(
        ["bash", str(SCRIPT), "q4os", str(iso), "0" * 64],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Calamares Location navigation requires SHA-verified Welcome step" in result.stderr
