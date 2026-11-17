"""VM-only negative tests for firstboot proof, clean poweroff and serial lines."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_tcg_firstboot.py"
spec = importlib.util.spec_from_file_location("gaslux_win_poweroff", SOURCE)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


def witness(profile="win10_22h2_en_us_x64", build="19045"):
    return ("\n".join([
        f"GASLUX_WINDOWS_X64_BOOT_BUILD={build}",
        "GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
        "GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
        "GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
        "GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
        "GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
        f"{vm.MARKER}={profile}",
    ]) + "\n").encode("ascii")


class FakeQemu:
    def __init__(self, rc):
        self.rc = rc
        self.killed = False
        self.waited = False

    def poll(self):
        return self.rc

    def kill(self):
        self.killed = True
        self.rc = -9

    def wait(self, timeout):
        self.waited = True
        return self.rc


class InstalledWindowsPoweroffContracts(unittest.TestCase):
    def run_guest(self, content: bytes, rc: int | None, seconds: int = 700):
        with tempfile.TemporaryDirectory() as root:
            serial = Path(root) / "windows-serial.log"
            serial.write_bytes(content)
            qemu = FakeQemu(rc)
            fake_clock = iter(range(0, 3000, 100))
            with patch.object(vm.subprocess, "Popen", return_value=qemu), patch.object(
                vm.time, "monotonic", side_effect=lambda: next(fake_clock)
            ), patch.object(vm.time, "sleep", return_value=None):
                result = vm.boot_vm(
                    ["qemu-system-x86_64", "-machine", "q35,accel=tcg"],
                    serial, seconds, "win10_22h2_en_us_x64",
                )
            return result, qemu

    def test_valid_guest_proof_and_graceful_acpi_poweroff_accepted(self):
        (ok, info), qemu = self.run_guest(witness(), 0)
        self.assertTrue(ok, info)
        self.assertIn("clean VM poweroff verified", info)
        self.assertFalse(qemu.killed)

    def test_valid_guest_proof_but_abnormal_qemu_exit_rejected(self):
        (ok, info), qemu = self.run_guest(witness(), 1)
        self.assertFalse(ok)
        self.assertIn("abnormally", info)
        self.assertFalse(qemu.killed)

    def test_valid_guest_proof_without_shutdown_is_not_stability(self):
        (ok, info), qemu = self.run_guest(witness(), None, seconds=2000)
        self.assertFalse(ok)
        self.assertIn("did not power off cleanly", info)
        self.assertTrue(qemu.killed)
        self.assertTrue(qemu.waited)

    def test_missing_winre_enabled_marker_rejected(self):
        lines = witness().replace(b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1\n", b"")
        (ok, info), _ = self.run_guest(lines, 0)
        self.assertFalse(ok)
        self.assertIn("before installed Windows first-logon witness", info)

    def test_wrong_build_prefix_rejected(self):
        (ok, info), _ = self.run_guest(witness(build="22000"), 0)
        self.assertFalse(ok)
        self.assertIn("before installed Windows first-logon witness", info)

    def test_markers_must_be_complete_delimited_tokens_not_substrings(self):
        data = b"UNTRUSTED_PREFIX_" + witness()
        (ok, info), _ = self.run_guest(data, 0)
        self.assertFalse(ok)

    def test_coalesced_genuine_win10_evidence_with_boot_manager(self):
        # Synthetic replay of the authentic Windows 10 Actions artifact:
        # OVMF Windows Boot Manager, then all seven audit tokens on ONE line.
        # No guest GPT GUID, credentials or machine identifiers are copied.
        serial = (
            b'BdsDxe: starting Boot0003 "Windows Boot Manager"\n'
            + b" ".join(witness().splitlines()) + b"\n"
        )
        (ok, info), qemu = self.run_guest(serial, 0)
        self.assertTrue(ok, info)
        self.assertIn("clean VM poweroff verified", info)
        self.assertFalse(qemu.killed)

    def test_coalesced_witness_missing_winre_rejected(self):
        serial = b" ".join(witness().splitlines()).replace(
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1", b"")
        (ok, info), _ = self.run_guest(serial, 0)
        self.assertFalse(ok)
        self.assertIn("before installed Windows first-logon witness", info)

    def test_coalesced_build_prefix_is_not_a_build_witness(self):
        for suffix in (b"0", b"_EXTRA", b"-bad"):
            with self.subTest(suffix=suffix):
                serial = b" ".join(witness().splitlines()).replace(
                    b"GASLUX_WINDOWS_X64_BOOT_BUILD=19045",
                    b"GASLUX_WINDOWS_X64_BOOT_BUILD=19045" + suffix,
                )
                (ok, info), _ = self.run_guest(serial, 0)
                self.assertFalse(ok)
                self.assertIn("before installed Windows first-logon witness", info)

    def test_coalesced_proofs_must_have_full_token_boundaries(self):
        for prefix in (b"UNTRUSTED_", b"X"):
            with self.subTest(prefix=prefix):
                serial = b" ".join(witness().splitlines()).replace(
                    b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
                    prefix + b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
                )
                (ok, _), _ = self.run_guest(serial, 0)
                self.assertFalse(ok)

    def test_coalesced_negative_guest_audit_overrides_success(self):
        serial = (b" ".join(witness().splitlines())
                  + b" GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL:"
                    b" guest audit rejected\n")
        (ok, info), _ = self.run_guest(serial, 0)
        self.assertFalse(ok)
        self.assertIn("explicitly rejected", info)

    def test_coalesced_success_needs_clean_shutdown(self):
        (ok, info), qemu = self.run_guest(
            b" ".join(witness().splitlines()), 1)
        self.assertFalse(ok)
        self.assertIn("abnormally", info)
        self.assertFalse(qemu.killed)

    def test_witness_can_mix_newlines_and_whitespace(self):
        serial = witness().replace(
            b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1\n"
            b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
            b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1 "
            b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
        )
        (ok, info), _ = self.run_guest(serial, 0)
        self.assertTrue(ok, info)

    def test_windows_com1_newline_is_actual_lf(self):
        p = vm.witness_powershell("win10_22h2_en_us_x64", "19045")
        self.assertIn('$ser.NewLine = "' + chr(96) + 'n"', p)
        self.assertNotIn('$ser.NewLine = "\\n"', p)


if __name__ == "__main__":
    unittest.main()
