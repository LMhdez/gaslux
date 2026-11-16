"""Deterministic socket transcript tests for the read-only CachyOS guest gate.

No QEMU guest is started by this unit test. The real ISO job executes the
separate actual guest/firmware check.
"""
from __future__ import annotations

import importlib.util
import socket
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "auto_tests/tools/cachyos_live_guest_serial.py"
SPEC = importlib.util.spec_from_file_location("cachyos_live_guest_serial", SOURCE)
assert SPEC and SPEC.loader
SERIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERIAL)


class FakeSerial:
    def __init__(self, *messages):
        self.messages = list(messages)
        self.sent = []

    def settimeout(self, timeout):
        assert timeout > 0

    def recv(self, max_size):
        return self.messages.pop(0) if self.messages else b""

    def sendall(self, content):
        self.sent.append(content)


class SerialGuestContractTests(unittest.TestCase):
    def fake(self, *, password=False, result=(b"GASLUX_OVMF_SECUREBOOT_DISABLED_VERIFIED=1\r\n"
                                              b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n")):
        prompts = [b"Welcome to CachyOS\nCachyOS login: "]
        if password:
            prompts.append(b"Password: ")
        else:
            prompts.append(b"[root@CachyOS ~]# ")
        prompts.append(b"[root@CachyOS ~]# \r\nGASLUX_ROOT_SHELL_READY\r\n")
        prompts.append(result)
        return FakeSerial(*prompts)

    def assert_remote_sequence(self, guest, password=False):
        self.assertEqual(guest.sent[0], b"root\r")
        if password:
            self.assertEqual(guest.sent[1], b"cachyos\r")
        self.assertTrue(any(x.startswith(b"printf 'GASLUX_ROOT_SHELL_READY") for x in guest.sent))
        self.assertTrue(any(b"mount -t vfat -o ro" in x for x in guest.sent))
        self.assertTrue(any(b"bash /run/gaslux-lab/probe.sh" in x for x in guest.sent))

    def test_passwordless_live_root(self):
        guest = self.fake()
        trace = bytearray()
        SERIAL.probe(guest, trace, boot_timeout=3)
        self.assertIn(b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1", trace)
        self.assert_remote_sequence(guest)

    def test_live_root_with_lab_password(self):
        guest = self.fake(password=True)
        SERIAL.probe(guest, bytearray(), boot_timeout=3)
        self.assert_remote_sequence(guest, password=True)

    def test_success_without_verified_secure_boot_var_is_rejected(self):
        guest = self.fake(result=b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n")
        with self.assertRaises(SERIAL.ProbeError):
            SERIAL.probe(guest, bytearray(), boot_timeout=3)

    def test_exact_disabled_secure_boot_marker_required(self):
        self.assertIsNone(
            SERIAL.SECURE_BOOT_DISABLED.search(
                b"echo GASLUX_OVMF_SECUREBOOT_DISABLED_VERIFIED=1\r\n"
            )
        )
        self.assertIsNotNone(
            SERIAL.SECURE_BOOT_DISABLED.search(
                b"GASLUX_OVMF_SECUREBOOT_DISABLED_VERIFIED=1\r\n"
            )
        )

    def test_bad_secure_boot_mode_does_not_satisfy_success(self):
        guest = self.fake(result=(
            b"GASLUX_SECUREBOOT_EFIVAR: SecureBoot=1 SetupMode=0\r\n"
            b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n"
        ))
        with self.assertRaises(SERIAL.ProbeError):
            SERIAL.probe(guest, bytearray(), boot_timeout=3)

    def test_guest_stage_refusal(self):
        guest = self.fake(result=b"GASLUX_GUEST_PREFLIGHT_FAILURE: wrong IMAGE_ID\r\n")
        with self.assertRaisesRegex(SERIAL.ProbeError, "explicitly failed"):
            SERIAL.probe(guest, bytearray(), boot_timeout=3)
        self.assert_remote_sequence(guest)

    def test_echoed_success_string_is_not_evidence(self):
        guest = self.fake(
            result=b"printf 'GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\\n'\r\n"
        )
        with self.assertRaises(SERIAL.ProbeError):
            SERIAL.probe(guest, bytearray(), boot_timeout=3)

    def test_success_must_be_entire_guest_stdout_line(self):
        self.assertIsNone(
            SERIAL.PASSED.search(b"echo GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n")
        )
        self.assertIsNotNone(
            SERIAL.PASSED.search(b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n")
        )

    def test_real_cachyos_systemd_osc_command_marker_is_normalized(self):
        # Captured structure of the official live ISO's systemd OSC 3008
        # command lifecycle plus CSI bracketed-paste terminal sequences.
        raw = (
            b"\x1b]3008;start=123;user=root;hostname=CachyOS;type=command\x1b\\"
            b"\x1b[?2004l\r\n"
            b"GASLUX_ROOT_SHELL_READY\r\n"
            b"\x1b]3008;end=123;exit=success\x1b\\"
            b"\x1b[?2004h"
        )
        clean = SERIAL.normalized_tty(raw)
        self.assertIn(b"GASLUX_ROOT_SHELL_READY\n", clean)
        self.assertIsNotNone(SERIAL.READY.search(clean))
        self.assertNotIn(b"\x1b", clean)

    def test_real_cachyos_systemd_osc_success_line_is_normalized(self):
        raw = (
            b"preflight starting\r\n"
            b"\x1b]3008;start=456;user=root;type=command\x1b\\"
            b"GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n"
        )
        self.assertIsNotNone(SERIAL.PASSED.search(SERIAL.normalized_tty(raw)))

    def test_terminal_echo_does_not_count_as_guest_success(self):
        raw = (
            b"\x1b]3008;start=567;user=root;type=command\x1b\\"
            b"[root@CachyOS ~]# printf 'GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\\n'\r\n"
        )
        self.assertIsNone(SERIAL.PASSED.search(SERIAL.normalized_tty(raw)))

    def test_unknown_escape_sequence_never_fakes_success(self):
        raw = b"\x1b[?9000zGASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n"
        # Unknown control sequences are not stripped; they cannot be treated
        # as an exact, anchored stdout proof.
        self.assertIsNone(SERIAL.PASSED.search(SERIAL.normalized_tty(raw)))

    def test_official_serial_log_bare_cr_before_ready_is_normalized(self):
        # Captured from real CachyOS 260809 QEMU guest: a lone CR is
        # emitted immediately before stdout, not CRLF.
        raw = (
            b"\x1b]3008;start=123;type=command\x1b\\"
            b"\rGASLUX_ROOT_SHELL_READY\r\n"
            b"\x1b]3008;end=123;exit=success\x1b\\"
        )
        clean = SERIAL.normalized_tty(raw)
        self.assertIsNotNone(SERIAL.READY.search(clean))
        self.assertIn(b"\nGASLUX_ROOT_SHELL_READY\n", clean)

    def test_official_serial_log_bare_cr_before_guest_pass_is_normalized(self):
        raw = (
            b"[root@CachyOS ~]# bash /run/gaslux-lab/probe.sh\r\n"
            b"\x1b]3008;start=123;type=command\x1b\\"
            b"\rGASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\r\n"
        )
        self.assertIsNotNone(
            SERIAL.PASSED.search(SERIAL.normalized_tty(raw))
        )

    def test_empty_serial_transport_fails_closed(self):
        with self.assertRaisesRegex(SERIAL.ProbeError, "serial connection terminated"):
            SERIAL.probe(FakeSerial(b""), bytearray(), boot_timeout=3)

    def test_guest_probe_is_readonly(self):
        script = SOURCE.with_name("cachyos_live_guest_readonly_probe.sh").read_text()
        for forbidden in ("pacstrap -K", "mkfs.", "wipefs ", "sgdisk ",
                          "efibootmgr -", "bcdedit ", "parted ", "chpasswd "):
            self.assertNotIn(forbidden, script)
        self.assertIn("bash /run/gaslux-lab/stage.sh --check", script)

    def test_probe_enforces_explicit_vm_firmware_and_live_identity(self):
        script = SOURCE.with_name("cachyos_live_guest_readonly_probe.sh").read_text()
        for required in ("ID=cachyos", "IMAGE_VERSION=2026.08.09", "systemd-detect-virt",
                         "/sys/firmware/efi/efivars", "SecureBoot", "SetupMode", "GASLUX_OVMF_SECUREBOOT_DISABLED_VERIFIED=1",
                         "sha256sum -c stage.sha256"):
            self.assertIn(required, script)


if __name__ == "__main__":
    unittest.main()
