"""Adversarial Zorin kernel powerdown and fail-closed diagnostic contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from zorin_shutdown_witness import (
    MAX_SERIAL, ZorinShutdownWitnessError, save_zorin_shutdown_diagnostic,
    verify_zorin_shutdown_serial,
)

SERIAL = (
    b"[    0.000000] Linux version 6.17.0-20-generic (builder)\n"
    b"[    0.000000] Kernel command line: root=UUID=12345678-1234-4234-8234-123456789abc\n"
    b"GASLUXZORIN login: [  OK  ] Started service.\n"
    b"[\x1b[0;32m  OK  \x1b[0m] Stopped serial-getty@ttyS0.service - Serial Getty on ttyS0.\n"
    b"[  OK  ] Reached target shutdown.target - System Shutdown.\n"
    b"[  OK  ] Finished systemd-poweroff.service - System Power Off.\n"
    b"[  OK  ] Reached target poweroff.target - System Power Off.\n"
    b"[   42.342717] reboot: Power down\n"
)


class ZorinShutdownWitnessContracts(unittest.TestCase):
    def reject(self, serial: bytes, reason: str = "Zorin"):
        with self.assertRaisesRegex(ZorinShutdownWitnessError, reason):
            verify_zorin_shutdown_serial(serial)

    def test_genuine_powerdown_order_with_ansi_and_login_suffix(self):
        proof = verify_zorin_shutdown_serial(SERIAL)
        self.assertEqual(proof["terminalKernelPowerDown"],
                         "[   42.342717] reboot: Power down")
        self.assertEqual(proof["serialSha256"], hashlib.sha256(SERIAL).hexdigest())
        self.assertLess(proof["witnessLineIndices"]["shutdownTarget"],
                        proof["witnessLineIndices"]["kernelPowerDown"])

    def test_qmp_ack_and_qemu_exit_without_kernel_witness_rejected(self):
        self.reject(SERIAL.replace(b"[   42.342717] reboot: Power down\n", b""),
                    "orderly shutdown")

    def test_shutdown_target_alone_is_insufficient(self):
        self.reject(SERIAL.split(b"[  OK  ] Finished systemd-poweroff")[0],
                    "orderly shutdown")

    def test_poweroff_service_without_target_rejected(self):
        self.reject(SERIAL.replace(
            b"[  OK  ] Reached target poweroff.target - System Power Off.\n", b""),
            "poweroffTarget")

    def test_truncated_log_rejected(self):
        self.reject(SERIAL[:-8], "kernelPowerDown")

    def test_line_after_kernel_powerdown_rejected(self):
        self.reject(SERIAL + b"console: still alive\n", "terminal")

    def test_order_inverted_rejected(self):
        a = b"[  OK  ] Reached target shutdown.target - System Shutdown.\n"
        b = b"[  OK  ] Finished systemd-poweroff.service - System Power Off.\n"
        self.reject(SERIAL.replace(a + b, b + a), "reordered")

    def test_fake_marker_inside_untrusted_journal_field_rejected(self):
        self.reject(SERIAL.replace(
            b"[   42.342717] reboot: Power down",
            b"journal: [   42.342717] reboot: Power down"),
            "kernelPowerDown")

    def test_foreign_second_boot_session_rejected(self):
        self.reject(SERIAL.replace(
            b"GASLUXZORIN login:",
            b"[  6.000] Linux version 6.17.0-20-generic (second)\nGASLUXZORIN login:"),
            "one session")

    def test_missing_serial_getty_stop_rejected(self):
        self.reject(SERIAL.replace(
            b"Stopped serial-getty@ttyS0.service",
            b"Stopped serial-getty@ttyS1.service"),
            "gettyStopped")

    def test_oversized_log_rejected(self):
        self.reject(SERIAL + b"x" * MAX_SERIAL, "oversized")

    def test_nonbytes_log_rejected(self):
        with self.assertRaises(ZorinShutdownWitnessError):
            verify_zorin_shutdown_serial("fake serial log")

    def test_diagnostic_retains_failure_qmp_pid_and_serial_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zorin-shutdown-diagnostics.json"
            save_zorin_shutdown_diagnostic(
                path, raw=SERIAL,
                qmp_proof={"qmpCommandAcknowledged": True,
                           "qmpPowerdownEventObserved": True},
                qemu_pid=123, qmp_socket_inode=456,
                cow_path=Path(tmp) / "trial.qcow2",
                root_uuid="12345678-1234-4234-8234-123456789abc",
                return_code=0, failure="SERIAL_WITNESS_MISSING", witness=None)
            data = json.loads(path.read_text())
            self.assertEqual(data["qemuExitCode"], 0)
            self.assertTrue(data["qmpPowerdownEventObserved"])
            self.assertFalse(data["linuxOrderlyShutdownWitness"])
            self.assertEqual(data["serialSha256"], hashlib.sha256(SERIAL).hexdigest())
            self.assertFalse(data["qmpPidFdBindingIndependentlyAuthenticated"])
            with self.assertRaisesRegex(ZorinShutdownWitnessError, "reused"):
                save_zorin_shutdown_diagnostic(
                    path, raw=SERIAL, qmp_proof={},
                    qemu_pid=1, qmp_socket_inode=1, cow_path=Path(tmp),
                    root_uuid="uuid", return_code=None, failure=None, witness=None)


if __name__ == "__main__":
    unittest.main()
