"""Isolated QEMU HMP one-time installer ISO boot-key regression tests.

Never boots Windows or accepts a synthetic serial marker as boot evidence.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_tcg_firstboot.py"
spec = importlib.util.spec_from_file_location("windows_boot_key", SOURCE)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class FakeQemu:
    def __init__(self, rc: int | None = None):
        self.rc = rc
        self.killed = False
    def poll(self):
        return self.rc
    def kill(self):
        self.killed = True
        self.rc = -9
    def wait(self, timeout):
        return self.rc


class OfficialISOBootPromptTests(unittest.TestCase):
    def test_only_one_initial_iso_boot_key_even_with_repeated_prompt(self):
        with tempfile.TemporaryDirectory() as temp:
            logfile = pathlib.Path(temp) / "serial.log"
            logfile.write_bytes(vm.BOOT_FROM_CD_PROMPT + b"...\n" +
                                vm.BOOT_FROM_CD_PROMPT + b"...\n")
            qemu = FakeQemu()
            tick = iter(range(0, 2000, 20))
            hmp = pathlib.Path(temp) / "monitor.sock"
            with patch.object(vm.subprocess, "Popen", return_value=qemu), patch.object(
                vm.time, "monotonic", side_effect=lambda: next(tick)
            ), patch.object(vm.time, "sleep", return_value=None), patch.object(
                vm, "send_first_iso_boot_key"
            ) as send:
                ok, info = vm.boot_vm(
                    ["qemu-system-x86_64"], logfile, 1000,
                    "win10_22h2_en_us_x64", monitor_socket=hmp)
            self.assertFalse(ok, info)
            self.assertEqual(send.call_count, 1)
            send.assert_called_once_with(hmp)
            self.assertTrue(qemu.killed)

    def test_no_prompt_means_fail_closed_without_monitor_injection(self):
        with tempfile.TemporaryDirectory() as temp:
            logfile = pathlib.Path(temp) / "serial.log"
            logfile.write_bytes(b"UEFI firmware, NO boot device\n")
            qemu = FakeQemu()
            tick = iter(range(0, 2000, 30))
            with patch.object(vm.subprocess, "Popen", return_value=qemu), patch.object(
                vm.time, "monotonic", side_effect=lambda: next(tick)
            ), patch.object(vm.time, "sleep", return_value=None), patch.object(
                vm, "send_first_iso_boot_key"
            ) as send:
                ok, info = vm.boot_vm(
                    ["qemu-system-x86_64"], logfile, 1500,
                    "win11_26h2_en_us_x64",
                    monitor_socket=pathlib.Path(temp) / "hmp.sock",
                )
            self.assertFalse(ok)
            self.assertIn("did not reach UEFI DVD boot or serial prompt", info)
            send.assert_not_called()

    def test_windows11_uefi_dvd_fallback_only_once_when_no_serial_prompt(self):
        with tempfile.TemporaryDirectory() as temp:
            logfile = pathlib.Path(temp) / "serial.log"
            logfile.write_bytes(vm.WINDOWS11_DVD_BOOT_START + b'\\r\\n')
            qemu = FakeQemu()
            tick = iter(range(0, 4000, 30))
            monitor = pathlib.Path(temp) / "monitor.sock"
            with patch.object(vm.subprocess, "Popen", return_value=qemu), patch.object(
                vm.time, "monotonic", side_effect=lambda: next(tick)
            ), patch.object(vm.time, "sleep", return_value=None), patch.object(
                vm, "send_first_iso_boot_key"
            ) as sender:
                ok, info = vm.boot_vm(
                    ["qemu-system-x86_64"], logfile, 2000,
                    "win11_26h2_en_us_x64", monitor_socket=monitor)
            self.assertFalse(ok, info)
            sender.assert_called_once_with(monitor, hold_ms=6000)
            self.assertTrue(qemu.killed)

    def test_windows10_never_uses_dvd_start_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            logfile = pathlib.Path(temp) / "serial.log"
            logfile.write_bytes(vm.WINDOWS11_DVD_BOOT_START + b'\\r\\n')
            qemu = FakeQemu()
            tick = iter(range(0, 4000, 30))
            with patch.object(vm.subprocess, "Popen", return_value=qemu), patch.object(
                vm.time, "monotonic", side_effect=lambda: next(tick)
            ), patch.object(vm.time, "sleep", return_value=None), patch.object(
                vm, "send_first_iso_boot_key"
            ) as sender:
                ok, info = vm.boot_vm(
                    ["qemu-system-x86_64"], logfile, 2000,
                    "win10_22h2_en_us_x64",
                    monitor_socket=pathlib.Path(temp) / "hmp.sock")
            self.assertFalse(ok, info)
            sender.assert_not_called()

    def test_unapproved_key_duration_refused_even_for_owned_socket(self):
        monitor = pathlib.Path(
            "/home/runner/work/_temp/gaslux-win-x64-safe/hmp.sock"
        )
        with self.assertRaisesRegex(vm.LabError, "unapproved"):
            vm.send_first_iso_boot_key(monitor, hold_ms=12000)

    def test_untrusted_socket_path_denied(self):
        with self.assertRaisesRegex(vm.LabError, "unowned QEMU monitor"):
            vm.send_first_iso_boot_key(pathlib.Path("/tmp/foreign-hmp.sock"))

    def test_fragmented_hmp_echo_requires_complete_prompt(self):
        safe = pathlib.Path(
            "/home/runner/work/_temp/gaslux-win-x64-probe/initial-installer-hmp.sock"
        )
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [
            b"QEMU 8.2 monitor\r\n", b"(qemu) ",
            b"s\x1b[K", b"sendkey ret 300\r\n", b"(qemu) ",
        ]
        with patch.object(pathlib.Path, "is_socket", return_value=True), patch.object(
            pathlib.Path, "is_symlink", return_value=False
        ), patch.object(vm.socket, "socket", return_value=sock):
            vm.send_first_iso_boot_key(safe)
        self.assertEqual(sock.recv.call_count, 5)
        sock.sendall.assert_called_once_with(b"sendkey ret 300\n")

    def test_hmp_disconnect_before_acknowledgment_is_rejected(self):
        safe = pathlib.Path(
            "/home/runner/work/_temp/gaslux-win-x64-probe/initial-installer-hmp.sock"
        )
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [b"QEMU monitor\r\n(qemu) ", b"s\x1b[K", b""]
        with patch.object(pathlib.Path, "is_socket", return_value=True), patch.object(
            pathlib.Path, "is_symlink", return_value=False
        ), patch.object(vm.socket, "socket", return_value=sock):
            with self.assertRaisesRegex(vm.LabError, "closed before acknowledging"):
                vm.send_first_iso_boot_key(safe)

    def test_hmp_explicit_command_error_is_rejected(self):
        safe = pathlib.Path(
            "/home/runner/work/_temp/gaslux-win-x64-probe/initial-installer-hmp.sock"
        )
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [
            b"QEMU monitor\r\n(qemu) ",
            b"error: command invalid\r\n(qemu) ",
        ]
        with patch.object(pathlib.Path, "is_socket", return_value=True), patch.object(
            pathlib.Path, "is_symlink", return_value=False
        ), patch.object(vm.socket, "socket", return_value=sock):
            with self.assertRaisesRegex(vm.LabError, "refused"):
                vm.send_first_iso_boot_key(safe)

    def test_partial_hmp_prompt_inside_reply_does_not_acknowledge_key(self):
        safe = pathlib.Path(
            "/home/runner/work/_temp/gaslux-win-x64-probe/initial-installer-hmp.sock"
        )
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [
            b"QEMU monitor\\r\\n(qemu) ",
            b"progress (qemu) not a terminal prompt", b"",
        ]
        with patch.object(pathlib.Path, "is_socket", return_value=True), patch.object(
            pathlib.Path, "is_symlink", return_value=False
        ), patch.object(vm.socket, "socket", return_value=sock):
            with self.assertRaisesRegex(vm.LabError, "closed before acknowledging"):
                vm.send_first_iso_boot_key(safe)

    def test_exact_qemu_hmp_command_through_ephemeral_unix_socket(self):
        safe = pathlib.Path(
            "/home/runner/work/_temp/gaslux-win-x64-probe/initial-installer-hmp.sock"
        )
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [b"QEMU 8.2.2 monitor - type 'help'\r\n(qemu) ",
                                 b"sendkey ret 300\r\n(qemu) "]
        with patch.object(pathlib.Path, "is_socket", return_value=True), patch.object(
            pathlib.Path, "is_symlink", return_value=False
        ), patch.object(vm.socket, "socket", return_value=sock) as maker:
            vm.send_first_iso_boot_key(safe)
        maker.assert_called_once_with(vm.socket.AF_UNIX, vm.socket.SOCK_STREAM)
        sock.connect.assert_called_once_with(str(safe))
        sock.sendall.assert_called_once_with(b"sendkey ret 300\n")
        sock.settimeout.assert_called_once_with(2)


if __name__ == "__main__":
    unittest.main()
