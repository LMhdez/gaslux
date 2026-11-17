"""Non-destructive contract gates for a native Pop first-boot VM experiment."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
from gaslux_popos_native_install_serial import (  # noqa: E402
    PRECHECK_RESULT,
    RESULT,
    START_RESULT,
    SUCCESS,
)

WORKFLOW = ROOT / ".github/workflows/gaslux-popos-official-iso.yml"
RUNNER = ROOT / "auto_tests/tools/gaslux_popos_native_full_firstboot_vm.sh"
INSTALL = ROOT / "auto_tests/tools/gaslux_popos_native_full_install_guest.sh"
FIRSTBOOT = ROOT / "auto_tests/tools/gaslux_popos_native_firstboot_guest.sh"


def test_native_install_is_isolated_to_explicit_hosted_kvm_lab():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    run = RUNNER.read_text(encoding="utf-8")
    assert "GASLUX_POP_NATIVE_FULL_VM: '1'" in workflow
    assert "GITHUB_ACTIONS:-" in run
    assert "CI:-" in run
    assert "/dev/kvm" in run
    assert "accel=kvm" in run
    assert "-net none" in run
    assert "sudo setfacl" in run
    assert 'truncate -s 32G "$target"' in run
    assert "GASLUX-OWNED-ESP" in run
    assert "GASLUX-OWNED-ROOT" in run
    assert "serial=GASLUXPOPFULLVM" in run
    assert "readonly=on,format=raw,file=$iso" in run
    assert "GASLUX_POP_NATIVE_FULL_INSTALL_GUEST_PROVEN" not in run
    assert "sha256sum -c --status" in run
    assert "GASLUX_POP_NATIVE_FIRSTBOOT_WITHOUT_LIVE_ISO=1" in run
    assert "::/agent.sha256" in run
    assert "agent.sha256" in RUNNER.read_text(encoding="utf-8")
    controller = (ROOT / "auto_tests/tools/gaslux_popos_native_install_serial.py").read_text(
        encoding="utf-8"
    )
    assert "Startup finished in" in controller
    assert "GASLUX_POP_LIVE_SHELL_READY" in controller
    assert "wait_for(conn, transcript, ROOT_DEBUG_SHELL, timeout_seconds=60)" not in controller
    assert "GASLUX_POP_LAB_MOUNT_READY=1" in controller
    assert "GASLUX_POP_LAB_CONTROL_VERIFIED=1" in controller
    assert 'conn.sendall(b"bash install.sh\\r")' in controller


def test_second_vm_has_only_native_installed_disk():
    run = RUNNER.read_text(encoding="utf-8")
    first, second = run.split("# The SECOND QEMU has NO lab EFI disk and NO live ISO.")
    assert "grub-mkstandalone" in first
    assert "drive=labefi" in first
    assert "drive=verifiediso" in first
    assert "drive=ownedtarget" in first
    assert "-device virtio-blk-pci,drive=popinstalled" in second
    assert "-device virtio-blk-pci,drive=verifiediso" not in second
    assert "-device virtio-blk-pci,drive=labefi" not in second
    assert "grub-mkstandalone" not in second
    assert "GASLUX_POP_NATIVE_FIRSTBOOT_VERIFIED=1" in second


def test_real_distinst_not_test_mode_and_only_linux_owned_disk():
    source = INSTALL.read_text(encoding="utf-8")
    assert "systemd-detect-virt --vm" in source
    assert "SecureBoot-" in source
    assert "SetupMode-" in source
    assert "GASLUX_POP_VM_SECUREBOOT_DISABLED_SETUPMODE_1=1" in source
    assert "sha256sum /usr/bin/distinst" in source
    assert "virtio-GASLUXPOPFULLVM" in source
    assert "lsblk -dn -o SERIAL" in source
    assert "blockdev --getsize64" in source
    assert "root already contains a filesystem" in source
    assert "lsblk -dn -o NAME,TYPE" in source
    assert "filesystem.manifest-remove" in source
    assert 'mount -t vfat -o ro "$by_id-part1"' in source
    assert "EFI/systemd/systemd-bootx64.efi" in source
    assert "EFI/BOOT/BOOTX64.EFI" in source
    assert "GASLUX_POP_NATIVE_FULL_INSTALL_COMPLETED=1" in source
    assert "GASLUX_POP_NATIVE_INSTALL_PREFLIGHT_OK=1" in source
    assert "GASLUX_POP_NATIVE_INSTALL_DISTINST_STARTED=1" in source
    controller = (ROOT / "auto_tests/tools/gaslux_popos_native_install_serial.py").read_text(
        encoding="utf-8"
    )
    assert 'conn.sendall(b"sync\\r")' in controller
    assert 'conn.sendall(b"systemctl poweroff -i\\r")' in controller
    assert "ROOT_DEBUG_SHELL, timeout_seconds=120" in controller
    assert "native guest did not close serial after poweroff" in controller
    assert "agent.sha256" in source
    assert "GASLUX_POP_NATIVE_INSTALL_DIAGNOSTIC_TAIL_BEGIN" in source
    assert "tail -n 6" in source
    assert 'wait "$native_pid" || native_rc="$?"' in source
    invocation = source.split("1500s /usr/bin/distinst", maxsplit=1)[1].split(
        '> "$log"', maxsplit=1
    )[0]
    assert "--no-efi-vars" in invocation
    assert '--block "$disk"' in invocation
    assert '--use "$disk:1:reuse:mount=/boot/efi"' in invocation
    assert '--use "$disk:2:ext4:mount=/"' in invocation
    for unsafe in ("--test", "--new-table", "--delete", "--move", "--modify-boot"):
        assert unsafe not in invocation


def test_firstboot_marker_is_from_real_installed_pop_root():
    source = FIRSTBOOT.read_text(encoding="utf-8")
    for required in (
        'ID:-}" == pop',
        'VERSION_ID:-}" == 24.04',
        "systemd-detect-virt --vm",
        "readlink -e",
        "findmnt -n -o SOURCE /",
        "virtio-GASLUXPOPFULLVM",
        "lsblk -dn -o NAME,TYPE",
        "zram|ram",
        "EFI/systemd/systemd-bootx64.efi",
        "GASLUX_POP_NATIVE_FIRSTBOOT_VERIFIED=1",
    ):
        assert required in source


def test_serial_proof_does_not_accept_shell_echo_or_failed_install():
    assert SUCCESS.search(b"\nGASLUX_POP_NATIVE_FULL_INSTALL_COMPLETED=1\r\n")
    assert not RESULT.search(b"\nGASLUX_POP_NATIVE_INSTALL_FAILURE: ")
    assert RESULT.search(b"\nGASLUX_POP_NATIVE_INSTALL_FAILURE: missing firmware\n")
    assert PRECHECK_RESULT.search(b"\nGASLUX_POP_NATIVE_INSTALL_PREFLIGHT_OK=1\n")
    assert START_RESULT.search(b"\nGASLUX_POP_NATIVE_INSTALL_DISTINST_STARTED=1\n")
    assert PRECHECK_RESULT.search(b"\nGASLUX_POP_NATIVE_INSTALL_FAILURE: missing EFI\n")
    assert not START_RESULT.search(b"echo GASLUX_POP_NATIVE_INSTALL_DISTINST_STARTED=1")
    assert not SUCCESS.search(b"echo GASLUX_POP_NATIVE_FULL_INSTALL_COMPLETED=1")
    assert RESULT.search(b"\nGASLUX_POP_NATIVE_INSTALL_FAILURE: disk validation\r\n")
    assert re.fullmatch(r"[a-f0-9]{64}", "b" * 64)
    assert not re.fullmatch(r"[a-f0-9]{64}", "0" * 63 + " ")
