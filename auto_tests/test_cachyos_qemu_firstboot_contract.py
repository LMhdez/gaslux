"""CachyOS installed-firstboot laboratory contract tests (no disk writes)."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERIAL_PATH = ROOT / "auto_tests/tools/cachyos_live_guest_serial.py"
SMOKE = ROOT / "auto_tests/tools/cachyos_real_live_kernel_smoke.sh"
INSTALL = ROOT / "auto_tests/tools/cachyos_guest_vm_only_install.sh"
WORKFLOW = ROOT / ".github/workflows/cachyos-official-iso.yml"
SPEC = importlib.util.spec_from_file_location("gaslux_firstboot_serial", SERIAL_PATH)
assert SPEC and SPEC.loader
SERIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERIAL)


class FakeSerial:
    def __init__(self, *answers: bytes):
        self.answers = list(answers)
        self.sent: list[bytes] = []

    def settimeout(self, seconds: float) -> None:
        assert seconds > 0

    def recv(self, count: int) -> bytes:
        return self.answers.pop(0) if self.answers else b""

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


class CachyosFirstBootContracts(unittest.TestCase):
    @staticmethod
    def guest(*, installer_output=b"GASLUX_LAB_TARGET_INSTALLED=1\r\n",
              early_installer_marker=False) -> FakeSerial:
        preflight = (b"GASLUX_OVMF_SECUREBOOT_DISABLED_VERIFIED=1\r\n"
                     b"GASLUX_SIGNED_GRUB_CMDLINE_VERIFIED=1\r\n"
                     b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n")
        if early_installer_marker:
            preflight += b"GASLUX_LAB_TARGET_INSTALLED=1\r\n"
        return FakeSerial(
            b"CachyOS login: ", b"[root@CachyOS ~]# ",
            b"[root@CachyOS ~]# \r\nGASLUX_ROOT_SHELL_READY\r\n",
            preflight, installer_output,
        )

    def test_fresh_target_success_requires_actual_guest_output(self):
        guest = self.guest()
        SERIAL.probe(guest, bytearray(), boot_timeout=2,
                     require_signed_entry=True, run_lab_install=True)
        sent = b"".join(guest.sent)
        self.assertIn(b"sha256sum -c install.sha256 &&", sent)
        self.assertIn(b"GASLUX_DISPOSABLE_VM=I_ACCEPT_DISPOSABLE_VM_ONLY &&", sent)
        self.assertIn(b"bash /run/gaslux-lab/install.sh", sent)

    def test_early_marker_does_not_prove_pacstrap(self):
        guest = self.guest(early_installer_marker=True, installer_output=b"")
        with self.assertRaises(SERIAL.ProbeError):
            SERIAL.probe(guest, bytearray(), boot_timeout=2,
                         require_signed_entry=True, run_lab_install=True)

    def test_install_failure_cannot_be_overridden_by_success(self):
        guest = self.guest(installer_output=(
            b"GASLUX_LAB_INSTALL_FAILURE: pacstrap failed\r\n"
            b"GASLUX_LAB_TARGET_INSTALLED=1\r\n"
        ))
        with self.assertRaisesRegex(SERIAL.ProbeError, "staging failed"):
            SERIAL.probe(guest, bytearray(), boot_timeout=2,
                         require_signed_entry=True, run_lab_install=True)

    def test_install_cannot_skip_signed_guest_gate(self):
        guest = self.guest()
        with self.assertRaisesRegex(SERIAL.ProbeError, "requires the signed boot"):
            SERIAL.probe(guest, bytearray(), boot_timeout=2,
                         require_signed_entry=False, run_lab_install=True)

    def test_vm_lab_only_target_approval(self):
        script = INSTALL.read_text()
        for required in (
            "I_ACCEPT_DISPOSABLE_VM_ONLY", "systemd-detect-virt --vm",
            "/dev/disk/by-id/virtio-GASLUXLABTARGET",
            "lsblk -dn -o TYPE", "blockdev --getsize64",
            "signed boot or Secure Boot proof rejected", "SecureBoot", "SetupMode",
            "sgdisk --clear", "mkfs.ext4", "mkfs.vfat",
            "pacstrap -K", "linux-cachyos-lts", "cachyos-hooks",
            "/usr/share/libalpm/scripts/cachyos-branding os-release",
            "GASLUX_LAB_OFFICIAL_BRANDING_VERIFIED=1",
            "grep -qx 'ID=cachyos'", "grep -qx 'ID_LIKE=arch'",
            "pacman-key --gpgdir", "--populate archlinux cachyos",
            "GASLUX_LAB_OFFICIAL_KEYRING_POPULATED=1",
            "grub-install --target=x86_64-efi",
            "--no-nvram --removable", "grub-mkconfig",
            "GASLUX_LAB_PACSTRAP_FINISHED=1",
            "GASLUX_LAB_TARGET_INSTALLED=1",
        ):
            self.assertIn(required, script)
        for unsafe in ("/dev/sda", "/dev/nvme0n1", "efibootmgr -c",
                       "SigLevel = Never", "--skippgpcheck", "--assume-installed",
                       "wipefs", "Set-Partition", "bcdedit"):
            self.assertNotIn(unsafe, script)

    def test_first_boot_requires_installed_os_root_and_pacman(self):
        script = INSTALL.read_text()
        start = script.index("cat > \"$TARGET/usr/local/sbin/gaslux-ci-firstboot-audit\"")
        audit = script[start:]
        for required in (
            "grep -qx ID=cachyos /etc/os-release",
            "findmnt -rn -M / -o FSTYPE",
            "blkid -s UUID", "pacman -Q linux-cachyos-lts grub base",
            "id gasluxtest", "uname -r",
            "GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1",
        ):
            self.assertIn(required, audit)
        self.assertIn("firstboot.service", audit)
        self.assertIn("After=local-fs.target", audit)

    def test_real_vm_second_phase_excludes_live_iso_and_windows(self):
        script = SMOKE.read_text()
        phase = script.split("GASLUX_LAB_STAGE_COMPLETE:", maxsplit=1)[1]
        before_assert = phase.split("for _ in $(seq 1 84)", maxsplit=1)[0]
        self.assertIn('file="$w/target.qcow2"', before_assert)
        self.assertIn("bootindex=1", before_assert)
        self.assertIn('file="$w/installed-nvram.fd"', before_assert)
        self.assertNotIn("id=bootimg", before_assert)
        self.assertNotIn("id=isoimg", before_assert)
        self.assertIn("GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1", phase)
        self.assertIn("cachyos-installed-firstboot-serial.log", phase)

    def test_real_iso_job_is_explicitly_branch_gated(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("feature/cachyos-qemu-pacstrap-firstboot", workflow)
        self.assertIn("GASLUX_LAB_FIRSTBOOT:", workflow)
        self.assertIn("GASLUX_SIGNED_EVIDENCE_DIR:", workflow)
        self.assertIn("cachyos_guest_vm_only_install.sh", workflow)
        self.assertIn("timeout-minutes: 95", workflow)


if __name__ == "__main__":
    unittest.main()
