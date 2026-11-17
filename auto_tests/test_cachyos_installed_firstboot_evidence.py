"""Negative regressions for installed CachyOS serial acceptance (read-only)."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "auto_tests/tools/cachyos_installed_firstboot_evidence.py"
SPEC = importlib.util.spec_from_file_location("cachyos_installed_evidence", PATH)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
UUID = b"GASLUX_INSTALLED_CACHYOS_ROOT_UUID=01234567-89ab-cdef-0123-456789abcdef\r\n"
PASS = b"GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1\r\n"


class InstalledEvidenceTests(unittest.TestCase):
    def test_valid(self):
        MOD.verify(b"UEFI GRUB boot\r\n" + UUID + PASS)

    def test_real_ovmf_console_bare_cr_and_escape_sequences(self):
        # From the structure of the official CachyOS installed-boot serial
        # artifact #14272809927, including agetty CR cursor movement.
        MOD.verify(b"\x1b[2JUEFI Misc Device\r\n" + UUID + PASS
                   + b"\x1b[!p\x1bP+q6E616D65\x1b\\\r\r\nCachyOS login: ")

    def test_failure_with_bare_cr_is_not_ignored(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(UUID + PASS + b"GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_FAIL: error\r")

    def test_missing_root(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(PASS)

    def test_root_after_pass(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(PASS + UUID)

    def test_wrong_root(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(UUID.replace(b"abcdef", b"abcdee") + PASS)

    def test_duplicate_success(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(UUID + PASS + PASS)

    def test_duplicate_root(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(UUID + UUID + PASS)

    def test_failure_after_success(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(UUID + PASS + b"GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_FAIL: mismatch\n")

    def test_failure_before_success(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(b"GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_FAIL: mismatch\n" + UUID + PASS)

    def test_echo_does_not_match(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(b"echo GASLUX_INSTALLED_CACHYOS_ROOT_UUID=01234567-89ab-cdef-0123-456789abcdef\n" + PASS)

    def test_oversized(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(b"x" * (MOD.MAX_BYTES + 1))

    def test_binary(self):
        with self.assertRaises(MOD.EvidenceError):
            MOD.verify(UUID + PASS + b"\x00")

    def test_smoke_uses_verifier(self):
        smoke = (ROOT / "auto_tests/tools/cachyos_real_live_kernel_smoke.sh").read_text()
        self.assertGreaterEqual(smoke.count("python3 auto_tests/tools/cachyos_installed_firstboot_evidence.py"), 2)


if __name__ == "__main__":
    unittest.main()
