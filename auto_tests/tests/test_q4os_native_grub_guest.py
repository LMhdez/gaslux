"""Guest-only native Q4OS GRUB, second-reboot, isolation regression gates.

No QEMU guest is launched by these unit tests and no disk is formatted.
"""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "tools"
HOST = ROOT / "gaslux_q4os_installed_root_lab.sh"
GUEST = ROOT / "gaslux_q4os_native_grub_guest.sh"


def test_native_grub_installation_is_guest_owned_and_never_changes_nvram():
    script = GUEST.read_text(encoding="utf-8")
    assert "[[ -d /sys/firmware/efi ]]" in script
    assert "GASLUX-Q4OS-ROOT" in script
    assert "GASLUX-Q4OS-ESP" in script
    assert '[[ "$root_device" == /dev/vda2 && "$esp_device" == /dev/vda1 ]]' in script
    assert "windows-efi-tree-not-allowed" in script
    assert "windows-loader-not-allowed" in script
    assert "more-than-one-guest-disk" in script
    assert "guest-efi-fallback-was-replaced" in script
    assert "grub-install --target=x86_64-efi" in script
    assert "--no-nvram --recheck" in script
    assert "--no-extra-removable" not in script
    assert "native-grub-modified-fallback-without-ownership" in script
    assert "grub-mkconfig -o /boot/grub/grub.cfg" in script
    assert '"$native_loader" "$boot_fallback"' in script
    assert "GASLUX_Q4OS_NATIVE_GRUB_SECOND_BOOT=" in script
    assert "GASLUX_Q4OS_NATIVE_GRUB_SECOND_KERNEL=6.12.111+deb13-amd64" in script
    assert "second-kernel-was-not-started-by-grub" in script
    assert "GASLUX_Q4OS_NATIVE_GRUB_INSTALLED=" in script
    assert "efibootmgr -c" not in script
    assert "mkfs." not in script


def test_guest_rejects_invocation_outside_approved_qemu():
    # No writes: fail the guest identity/permissions checks before any GRUB call.
    result = subprocess.run(
        ["bash", str(GUEST), "install"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "GASLUX_Q4OS_NATIVE_GRUB_REFUSED" in result.stderr


def test_guest_refuses_unknown_operation():
    result = subprocess.run(
        ["bash", str(GUEST), "erase"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "usage" in result.stderr


def test_host_uses_exactly_its_temporary_gpt_and_two_vm_reboots():
    script = HOST.read_text(encoding="utf-8")
    assert 'native_grub="${GASLUX_Q4OS_NATIVE_GRUB_LAB:-no}"' in script
    assert '[[ "${GITHUB_ACTIONS:-}" == true ]]' in script
    assert 'disk="$work/guest-q4os-gpt.raw"' in script
    assert "gaslux_q4os_native_grub_guest.sh" in script
    assert "native-grub-guest install" in script
    assert "native-grub-guest verify-second" in script
    assert "GASLUX_Q4OS_NATIVE_GRUB_INSTALLED=6.10-deb13u1" in script
    assert "GASLUX_Q4OS_NATIVE_GRUB_SECOND_BOOT=6.10-deb13u1" in script
    assert "GASLUX_Q4OS_NATIVE_GRUB_SECOND_KERNEL=6.12.111+deb13-amd64" in script
    assert "Loading Q4OS operating system" in script
    assert "serial-native-grub.log" in script
    assert "No second installed Q4OS boot proof from package-owned GRUB" in script
    assert "-net none" in script
    assert "-cdrom" not in script
    assert 'file="$disk"' in script


def test_native_mode_requires_disposable_ci_even_when_source_is_present(tmp_path):
    iso = tmp_path / "fake.iso"
    iso.write_bytes(b"not-a-real-iso")
    env = os.environ.copy()
    env["GASLUX_Q4OS_ALLOW_DISPOSABLE_INSTALL"] = "yes"
    env["GASLUX_Q4OS_NATIVE_GRUB_LAB"] = "yes"
    env.pop("GITHUB_ACTIONS", None)
    result = subprocess.run(
        ["bash", str(HOST), str(iso), "0" * 64, str(tmp_path)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "requires a disposable GitHub Actions runner" in result.stderr
