"""Read-only CachyOS live serial controller tests; no disk/VM writes."""
from __future__ import annotations

import importlib.util
import socket
import threading
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "auto_tests/tools/cachyos_live_guest_serial.py"
SPEC = importlib.util.spec_from_file_location("cachyos_live_guest_serial", SOURCE)
assert SPEC and SPEC.loader
SERIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERIAL)


class SerialGuestContractTests(unittest.TestCase):
    def run_fake_guest(self, *, password=False, result=True, echo_only=False):
        client, guest = socket.socketpair()
        received = []
        errors = []

        def read_line():
            line = bytearray()
            guest.settimeout(3)
            while not line.endswith(b"\r"):
                chunk = guest.recv(1)
                if not chunk:
                    raise ConnectionError("fake serial client ended mid-command")
                line.extend(chunk)
            return bytes(line)

        def guest_session():
            try:
                guest.sendall(b"Welcome to CachyOS\nCachyOS login: ")
                received.append(read_line())
                if password:
                    guest.sendall(b"Password: ")
                    received.append(read_line())
                guest.sendall(b"[root@CachyOS ~]# ")
                ready = read_line()
                received.append(ready)
                guest.sendall(
                    b"printf 'GASLUX_ROOT_SHELL_READY\\n'\r\n"
                    b"GASLUX_ROOT_SHELL_READY\r\n"
                )
                command = read_line()
                received.append(command)
                if result:
                    guest.sendall(
                        b"bash /run/gaslux-lab/probe.sh\r\n"
                        b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n"
                    )
                elif echo_only:
                    guest.sendall(
                        b"printf 'GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\\n'\r\n"
                    )
                else:
                    guest.sendall(
                        b"GASLUX_GUEST_PREFLIGHT_FAILURE: wrong official Archiso ID\r\n"
                    )
            except Exception as error:
                errors.append(error)
            finally:
                guest.close()

        thread = threading.Thread(target=guest_session, daemon=True)
        thread.start()
        try:
            if result:
                trace = bytearray()
                SERIAL.probe(client, trace, boot_timeout=3)
                self.assertIn(b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1", trace)
            else:
                with self.assertRaises(SERIAL.ProbeError):
                    SERIAL.probe(client, bytearray(), boot_timeout=3)
        finally:
            client.close()
            thread.join(timeout=3)
        self.assertFalse(errors)
        self.assertEqual(received[0], b"root\r")
        if password:
            self.assertEqual(received[1], b"cachyos\r")
        self.assertIn(b"printf 'GASLUX_ROOT_SHELL_READY", received[-2])
        self.assertIn(b"mount -t vfat -o ro", received[-1])
        self.assertIn(b"bash /run/gaslux-lab/probe.sh", received[-1])

    def test_passwordless_guest_login(self):
        self.run_fake_guest()

    def test_guest_tty_with_default_lab_password(self):
        self.run_fake_guest(password=True)

    def test_stage_verification_failure_is_rejected(self):
        self.run_fake_guest(result=False)

    def test_echoed_command_is_not_success(self):
        self.run_fake_guest(result=False, echo_only=True)

    def test_serial_success_requires_anchored_stdout(self):
        fake = bytearray(b"echo GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n")
        self.assertIsNone(SERIAL.PASSED.search(bytes(fake)))
        fake.extend(b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n")
        self.assertIsNotNone(SERIAL.PASSED.search(bytes(fake)))

    def test_unexpected_guest_failure_marker(self):
        self.assertIsNotNone(
            SERIAL.FAILED.search(b"failed command\r\nGASLUX_GUEST_PREFLIGHT_FAILURE: missing repo\r\n")
        )

    def test_live_probe_shell_script_contains_no_mutating_commands(self):
        script = SOURCE.with_name("cachyos_live_guest_readonly_probe.sh").read_text()
        for token in ("pacstrap -K", "mkfs.", "wipefs ", "sgdisk ", "efibootmgr -", "bcdedit ",
                      "parted ", "mount -o rw", "chpasswd "):
            self.assertNotIn(token, script)
        self.assertIn("bash /run/gaslux-lab/stage.sh --check", script)


if __name__ == "__main__":
    unittest.main()
