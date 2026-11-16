"""Static regression gates for disposable Q4OS/Pop QEMU media transport.

These tests never run QEMU or write a disk. A passing static gate is not
evidence of a live boot, native install, Windows boot, or rollback.
"""

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "gaslux_candidate_live_boot.sh"


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_both_candidates_receive_hash_verified_read_only_virtio_iso():
    script = _source()
    assert "sha256sum -c --status" in script
    assert '[[ "$iso" != *,* ]]' in script
    assert "id=officialiso,readonly=on,format=raw,file=$iso" in script
    assert "-device virtio-blk-pci,drive=officialiso,bootindex=2" in script
    assert '"${iso_args[@]}"' in script
    assert "-cdrom" not in script
    assert 'if [[ "$distro" == popos ]]; then' in script
    assert "else\n  # Debian/Q4OS native live media" in script


def test_grub_fails_closed_when_verified_q4os_kernel_is_not_visible():
    script = _source()
    assert "if ! search --no-floppy --file --set=source /$kernel; then" in script
    assert "echo 'Verified live kernel is not visible on any guest block device'" in script
    assert "echo 'Pinned guest live initramfs not found'" in script
    assert r"  initrd (\$source)/$initrd" in script


def test_disposable_ovmf_has_no_host_disk_or_network_passthrough():
    script = _source()
    assert 'truncate -s 256M "$work/efi-disk.img"' in script
    assert 'file="$work/efi-disk.img"' in script
    assert 'file="$work/nvram.fd"' in script
    assert "-net none" in script
    assert '"file:$work/serial.log"' in script
    assert "GASLUX_GUEST_MEDIA=isolated-virtio-readonly-iso" in script


def test_live_boot_requires_guest_userspace_and_kernel_evidence():
    script = _source()
    assert "grep -Eiq '(^|[^A-Za-z])login:|login: $'" in script
    assert "grep -Eiq 'Linux version|Freeing unused kernel|systemd" in script
    assert "guest_verified=1" in script
    assert "NO REAL GUEST LOGIN PROOF" in script


def test_reject_symlink_before_iso_canonicalization(tmp_path):
    """Early refusal never runs QEMU, mounts an ISO or writes a target disk."""
    original = tmp_path / "real.iso"
    original.write_bytes(b"test-only data")
    link = tmp_path / "link.iso"
    link.symlink_to(original)
    result = subprocess.run(
        ["bash", str(SCRIPT), "q4os", str(link), "0" * 64],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Refuse symlink/non-regular ISO" in result.stderr
