"""Regressions for streaming Windows COM1 proof, with no ISO or QEMU disk."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "gaslux_windows_full_serial", TOOLS / "windows_x64_tcg_firstboot.py"
)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)

PROOFS = (b" "
          b"GASLUX_WINDOWS_X64_BOOT_BUILD=19045 "
          b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1 "
          b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1 "
          b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1 "
          b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1 "
          b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1 "
          b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win10_22h2_en_us_x64\n")


class FakeQemu:
    def __init__(self, code=0):
        self.code = code
        self.killed = False

    def poll(self):
        return self.code

    def kill(self):
        self.killed = True
        self.code = -9

    def wait(self, timeout):
        return self.code


class FullSerialAuditContracts(unittest.TestCase):
    def boot(self, data, code=0, dvd=False):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "guest.log"
            path.write_bytes(data)
            qemu = FakeQemu(code)
            with patch.object(vm.subprocess, "Popen", return_value=qemu):
                result = vm.boot_vm(
                    ["qemu-system-x86_64"], path, 10,
                    "win10_22h2_en_us_x64",
                    reject_repeated_dvd_boot=dvd,
                )
            return result

    def test_proof_earlier_than_400k_is_not_erased(self):
        self.assertTrue(
            self.boot(PROOFS + b"Firmware debug output\n" * 28000)[0]
        )

    def test_earlier_guest_failure_cannot_be_erased_by_later_proof(self):
        data = (b"GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL:WinRE missing\n"
                + b"Firmware debug output\n" * 28000 + PROOFS)
        (ok, msg) = self.boot(data)
        self.assertFalse(ok)
        self.assertIn("explicitly rejected", msg)

    def test_failure_after_proof_still_rejects(self):
        (ok, msg) = self.boot(
            PROOFS + b"Firmware debug output\n" * 28000
            + b"GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL:BCD missing\n"
        )
        self.assertFalse(ok)
        self.assertIn("explicitly rejected", msg)

    def test_dvd_replay_earlier_than_400k_still_rejects(self):
        boot = b'BdsDxe: starting Boot00AF "UEFI QEMU DVD-ROM\n'
        (ok, msg) = self.boot(
            boot + b"Firmware debug output\n" * 28000 + boot + PROOFS,
            dvd=True,
        )
        self.assertFalse(ok)
        self.assertIn("retried", msg)

    def test_split_marker_across_read_boundary(self):
        prefix = b"X" * (65536 - 7) + b"\n"
        (ok, msg) = self.boot(prefix + PROOFS)
        self.assertTrue(ok, msg)

    def test_append_fragment_not_valid_until_delimited(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "guest.log"
            path.write_bytes(b"GASLUX_WINDOWS_X64_BOOT_BUILD=190")
            found, offset, carry, dropping = vm.scan_windows_guest_tokens(
                path, 0, b"", False,
            )
            self.assertEqual(found, set())
            self.assertFalse(dropping)
            self.assertTrue(carry.endswith(b"190"))
            with path.open("ab") as f:
                f.write(b"45\n")
            found, offset, carry, dropping = vm.scan_windows_guest_tokens(
                path, offset, carry, dropping,
            )
            self.assertEqual(found, {b"GASLUX_WINDOWS_X64_BOOT_BUILD=19045"})
            self.assertEqual(carry, b"")
            self.assertFalse(dropping)

    def test_oversized_undelimited_prefix_does_not_create_false_witness(self):
        (ok, _) = self.boot(
            b"X" * (65536 + 10)
            + b"GASLUX_WINDOWS_X64_BOOT_BUILD=19045 "
            + PROOFS.replace(b"GASLUX_WINDOWS_X64_BOOT_BUILD=19045 ", b"")
        )
        self.assertFalse(ok)

    def test_oversized_failure_prefix_still_fails_closed(self):
        (ok, msg) = self.boot(
            b"GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL:" + b"x" * 70000
            + b"\n" + PROOFS
        )
        self.assertFalse(ok)
        self.assertIn("explicitly rejected", msg)

    def test_unterminated_final_marker_is_accepted_only_after_exit(self):
        (ok, msg) = self.boot(PROOFS.rstrip(b"\n"))
        self.assertTrue(ok, msg)

    def test_truncated_serial_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "guest.log"
            path.write_bytes(PROOFS)
            _, offset, carry, dropping = vm.scan_windows_guest_tokens(
                path, 0, b"", False,
            )
            path.write_bytes(b"tiny")
            with self.assertRaisesRegex(vm.LabError, "truncated"):
                vm.scan_windows_guest_tokens(path, offset, carry, dropping)

    def test_symlink_serial_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "guest.log"
            target = Path(root) / "real.log"
            target.write_bytes(PROOFS)
            path.symlink_to(target)
            with self.assertRaisesRegex(vm.LabError, "untrusted"):
                vm.scan_windows_guest_tokens(path, 0, b"", False)


if __name__ == "__main__":
    unittest.main()
