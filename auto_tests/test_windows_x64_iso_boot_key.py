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


class LocalVncIsoBootKeyTests(unittest.TestCase):
    def test_vnc_rejects_foreign_monitor_before_network_access(self):
        with self.assertRaisesRegex(vm.LabError, "unapproved"):
            vm.send_first_iso_boot_key_vnc(
                pathlib.Path("/home/runner/work/_temp/gaslux-win-x64-lab/hmp.sock"),
                hold_ms=12000,
            )
        with patch.dict(vm.os.environ, {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
        }):
            with self.assertRaisesRegex(vm.LabError, "unowned QEMU monitor"):
                vm.send_first_iso_boot_key_vnc(pathlib.Path("/tmp/foreign.sock"))

    def test_loopback_rfb_sends_exactly_one_return_pair(self):
        monitor = pathlib.Path(
            "/home/runner/work/_temp/gaslux-win-x64-vnc/initial-installer-hmp.sock"
        )
        sock = MagicMock()
        sock.__enter__.return_value = sock
        name = b"QEMU"
        server_init = bytes(20) + len(name).to_bytes(4, "big")
        sock.recv.side_effect = [
            b"RFB 003.008\\n", b"\\x01", b"\\x01", b"\\x00" * 4, server_init, name
        ]
        hosted = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
        }
        with patch.dict(vm.os.environ, hosted), patch.object(
            pathlib.Path, "is_socket", return_value=True
        ), patch.object(pathlib.Path, "is_symlink", return_value=False), patch.object(
            vm.socket, "create_connection", return_value=sock
        ) as maker, patch.object(vm.time, "sleep", return_value=None):
            vm.send_first_iso_boot_key_vnc(monitor)
        maker.assert_called_once_with(("127.0.0.1", 5979), timeout=5)
        self.assertEqual(
            [call.args[0] for call in sock.sendall.call_args_list],
            [
                b"RFB 003.008\\n", b"\\x01", b"\\x01",
                vm.struct.pack(">BBHI", 4, 1, 0, 0xFF0D),
                vm.struct.pack(">BBHI", 4, 0, 0, 0xFF0D),
            ],
        )



if __name__ == "__main__":
    unittest.main()
