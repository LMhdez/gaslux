"""Read-only guards for ephemeral OVMF Pop!_OS optical ISO attachment."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / "auto_tests/tools/gaslux_candidate_live_boot.sh"


def test_iso_is_emulated_as_read_only_optical_and_never_host_block_device():
    source = BOOT.read_text(encoding="utf-8")
    assert 'printf \'%s  %s\\n\' "$digest" "$iso" | sha256sum -c --status' in source
    assert 'readonly=on,format=raw,file="$iso"' in source
    assert "-device qemu-xhci" in source
    assert "-device usb-storage,drive=officialiso" in source
    assert '  -cdrom "$iso"' not in source
    assert '  -device virtio-blk-pci,drive=labefi,bootindex=1' in source
    assert '  -net none' in source
    assert '  -no-reboot' in source


def test_kernel_lookup_fails_closed_and_guest_login_is_required():
    source = BOOT.read_text(encoding="utf-8")
    assert 'if ! search --no-floppy --file --set=source /$kernel; then' in source
    assert "Verified live kernel is not visible on any guest block device" in source
    assert "guest_verified=0" in source
    assert "NO REAL GUEST LOGIN PROOF" in source
