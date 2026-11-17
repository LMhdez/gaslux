"""Strict QEMU exit barrier for Windows COM1 proof and negative markers.

Uses a synthetic Popen that appends a guest serial payload *inside* poll();
no Windows ISO, guest, host block disk, network, or subprocesses are started.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parent / "tools" / "windows_x64_tcg_firstboot.py"
sys.path.insert(0, str(SRC.parent))
spec = importlib.util.spec_from_file_location("gaslux_final_com1_drain", SRC)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)

BM = b'BdsDxe: starting Boot0003 "Windows Boot Manager"\r\n'
PROOFS = (b"GASLUX_WINDOWS_X64_BOOT_BUILD=26300 "
          b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1 "
          b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1 "
          b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1 "
          b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1 "
          b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1 "
          b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64\n")
ERROR = b"GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL: rejected\n"

class PollAppendsSerial:
    def __init__(self, transcript: Path, data: bytes = b"", code: int = 0):
        self.transcript = transcript
        self.data = data
        self.code = code
        self.called = False

    def poll(self):
        if not self.called:
            self.called = True
            with self.transcript.open("ab") as file:
                file.write(self.data)
        return self.code

    def kill(self):
        raise AssertionError("unexpected kill: fake guest already exited")

    def wait(self, timeout):
        return self.code


class FinalCom1DrainTests(unittest.TestCase):
    def boot(self, initial: bytes, appended: bytes, status: int = 0):
        with tempfile.TemporaryDirectory() as tmp:
            serial = Path(tmp) / "installed-serial.log"
            serial.write_bytes(initial)
            guest = PollAppendsSerial(serial, appended, status)
            with patch.object(vm.subprocess, "Popen", return_value=guest):
                result = vm.boot_vm(
                    ["qemu-system-x86_64"], serial, 30,
                    "win11_26h2_en_us_x64",
                    reject_repeated_dvd_boot=True,
                )
            self.assertTrue(guest.called)
            return result

    def test_earlier_full_witness_does_not_override_final_failure(self):
        good, diag = self.boot(BM + PROOFS, ERROR)
        self.assertFalse(good)
        self.assertIn("explicitly rejected", diag)

    def test_final_failure_stage_cannot_become_proof(self):
        good, diag = self.boot(BM + PROOFS,
                               b"GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL_STAGE=BCD\n"
                               + ERROR)
        self.assertFalse(good)
        self.assertIn("explicitly rejected", diag)

    def test_final_reboot_after_all_tokens_rejected_despite_exit_zero(self):
        good, diag = self.boot(BM + PROOFS, BM)
        self.assertFalse(good)
        self.assertIn("rebooted after first-logon", diag)

    def test_final_reboot_after_large_serial_gap_rejected(self):
        good, diag = self.boot(BM + PROOFS, b"x" * 550_000 + BM)
        self.assertFalse(good)
        self.assertIn("rebooted after first-logon", diag)

    def test_final_split_bootmanager_marker_rejected(self):
        good, diag = self.boot(BM + PROOFS + BM[:19], BM[19:])
        self.assertFalse(good)
        self.assertIn("rebooted after first-logon", diag)

    def test_final_duplicate_dvd_boot_rejected(self):
        dvd = b'BdsDxe: starting Boot0001 "UEFI QEMU DVD-ROM\r\n'
        good, diag = self.boot(BM + PROOFS + dvd, dvd)
        self.assertFalse(good)
        self.assertIn("retried", diag)

    def test_final_valid_proof_is_accepted_if_qemu_exited_zero(self):
        partial = PROOFS.split(b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=")[0]
        last = b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64\n"
        good, diag = self.boot(BM + partial, last)
        self.assertTrue(good, diag)

    def test_final_truncated_proof_is_not_accepted(self):
        partial = PROOFS.split(b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=")[0]
        good, diag = self.boot(BM + partial,
                               b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11")
        self.assertFalse(good)
        self.assertIn("before installed Windows", diag)

    def test_negative_marker_as_last_unterminated_token_rejected(self):
        good, diag = self.boot(BM + PROOFS, ERROR.rstrip(b"\n"))
        self.assertFalse(good)
        self.assertIn("explicitly rejected", diag)

    def test_abnormal_exit_remains_unverified(self):
        good, diag = self.boot(BM + PROOFS, b"", status=1)
        self.assertFalse(good)
        self.assertIn("abnormally", diag)


if __name__ == "__main__":
    unittest.main()
