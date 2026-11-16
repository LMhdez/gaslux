"""Fail-closed configuration tests for disposable Secure Boot-capable OVMF VM.

No disk images, Windows disks, firmware variables or QEMU guests are changed
by these tests. The official ISO GitHub workflow performs the actual boot.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "auto_tests/tools/cachyos_real_live_kernel_smoke.sh"
PROBE = ROOT / "auto_tests/tools/cachyos_live_guest_readonly_probe.sh"
SERIAL = ROOT / "auto_tests/tools/cachyos_live_guest_serial.py"


class OvmfSecureBootLabContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke = SMOKE.read_text(encoding="utf-8")
        cls.probe = PROBE.read_text(encoding="utf-8")
        cls.serial = SERIAL.read_text(encoding="utf-8")

    def test_selects_secure_boot_capable_firmware_explicitly(self):
        self.assertIn("OVMF_CODE_4M.secboot.fd", self.smoke)
        self.assertIn("OVMF_VARS_4M.fd", self.smoke)
        self.assertNotIn("OVMF_VARS_4M.ms.fd", self.smoke)
        self.assertIn("smm=on", self.smoke)
        self.assertIn("property=secure,value=on", self.smoke)

    def test_uefi_variables_are_copied_into_disposable_vm_storage(self):
        self.assertIn('cp "$vars" "$w/nvram.fd"', self.smoke)
        self.assertIn('-drive if=pflash,format=raw,file="$w/nvram.fd"', self.smoke)
        self.assertNotIn('file="$vars"', self.smoke)

    def test_missing_firmware_or_unknown_variables_fail_closed(self):
        self.assertIn("Missing dedicated OVMF Secure Boot-capable", self.smoke)
        self.assertIn("Secure Boot is enabled or unverifiable", self.probe)
        self.assertIn("missing or linked", self.probe)
        self.assertIn("invalid length", self.probe)

    def test_secure_boot_evidence_requires_real_efivarfs_bytes(self):
        self.assertIn("data = path.read_bytes()", self.probe)
        self.assertIn("if len(data) != 5:", self.probe)
        self.assertIn("return data[4]", self.probe)
        self.assertIn("if secure != 0:", self.probe)
        self.assertIn("if setup != 1:", self.probe)
        self.assertIn("active Secure Boot refused", self.probe)
        self.assertIn("unexpected key enrollment in lab", self.probe)

    def test_final_guest_pass_depends_on_secureboot_marker(self):
        self.assertIn("GASLUX_OVMF_SECUREBOOT_DISABLED_VERIFIED=1", self.probe)
        self.assertIn("wait_for(sock, trace, (SECURE_BOOT_DISABLED,)", self.serial)
        self.assertIn('[[ "$guest_proven" -eq 1 ]]', self.smoke)
        self.assertIn('"$w/guest-console.log"', self.smoke)

    def test_real_guest_pass_does_not_depend_on_systemd_timing_format(self):
        self.assertIn("CachyOS login:", self.smoke)
        self.assertIn("GASLUX_LIVE_GUEST_PROBE:-0", self.smoke)
        self.assertIn("non-interactive live boot has no systemd startup timing evidence", self.smoke)
        self.assertIn('[[ "$guest_proven" -eq 1 ]]', self.smoke)
        self.assertIn("SECURE_BOOT_DISABLED", self.serial)

    def test_does_not_change_production_secure_boot_state(self):
        for forbidden in ("mokutil --disable-validation", "mokutil --import", "efi-updatevar",
                          "sbctl enroll-keys", "efibootmgr --bootorder",
                          "Set-SecureBootUEFI", "Set-Partition", "bcdedit /set"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.probe + "\n" + self.smoke)


if __name__ == "__main__":
    unittest.main()
