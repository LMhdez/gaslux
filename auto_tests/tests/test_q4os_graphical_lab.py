"""Fail-closed gates for Q4OS disposable graphical lab only.

A passing static test is not installation evidence.
"""

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "gaslux_q4os_graphical_lab.sh"


def test_explicit_authorization_refuses_before_mutating_any_virtual_disk(tmp_path):
    result = subprocess.run(
        ["bash", str(SCRIPT), "q4os", str(tmp_path / "missing.iso"), "0" * 64],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Explicit disposable Q4OS graphics lab authorization missing" in result.stderr


def test_only_q4os_and_hash_checked_verified_readonly_media():
    source = SCRIPT.read_text()
    assert '[[ "$distro" == q4os ]]' in source
    assert "sha256sum -c --status" in source
    assert "readonly=on,format=raw,file=$iso" in source
    assert "-net none" in source
    assert "GASLUX_Q4OS_GRAPHICS_LAB_ONLY" in source


def test_guest_target_is_created_from_scratch_in_temporary_workspace():
    source = SCRIPT.read_text()
    assert 'work="$(mktemp -d -t gaslux-q4os-graphics-XXXXXX)"' in source
    assert 'truncate -s 32G "$work/efi-disk.img"' in source
    assert 'truncate -s 512M "$work/efi-part.img"' in source
    assert 'file="$work/efi-disk.img"' in source
    assert 'file="$work/nvram.fd"' in source
    assert "bootindex=1" in source
    assert 'rm -rf -- "$work"' in source
    assert "-drive file=/dev/" not in source


def test_guest_graphics_requires_real_kernel_and_vnc_frames_not_bootloader_only():
    source = SCRIPT.read_text()
    assert "systemd.unit=graphical.target" in source
    assert "-vnc 127.0.0.1:1" in source
    assert "vncdo -s 127.0.0.1:1 capture" in source
    assert '"$guest_verified" -eq 1 && "$frame_count" -gt 0' in source
    assert "NOT PROVEN: graphical desktop state" in source
    assert "calamares -d" not in source.lower()
