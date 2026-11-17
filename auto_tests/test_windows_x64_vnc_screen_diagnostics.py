"""Read-only QEMU framebuffer diagnostic contract tests (no guest or disks)."""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "windows_vnc_diag", TOOLS / "windows_x64_tcg_firstboot.py")
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class FakeQemu:
    def __init__(self):
        self.killed = False

    def poll(self):
        return -9 if self.killed else None

    def kill(self):
        self.killed = True

    def wait(self, timeout):
        return -9


class WindowsVncScreenDiagnostics(unittest.TestCase):
    def test_rejects_foreign_hmp_socket_before_host_access(self):
        with patch.dict(vm.os.environ, {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
        }):
            with self.assertRaisesRegex(vm.LabError, "unowned"):
                vm.capture_vm_screen(
                    pathlib.Path("/tmp/other-user-hmp.sock"),
                    pathlib.Path("/tmp/windows-dvd-90s.ppm"),
                )

    def test_captures_only_after_real_firmware_prompt_and_key(self):
        with tempfile.TemporaryDirectory() as temp:
            work = pathlib.Path(temp)
            transcript = work / "serial.log"
            transcript.write_bytes(vm.BOOT_FROM_CD_PROMPT + b"...\r\n")
            qemu = FakeQemu()
            ticks = iter(range(0, 3000, 20))
            with patch.object(vm.subprocess, "Popen", return_value=qemu), patch.object(
                vm.time, "monotonic", side_effect=lambda: next(ticks)
            ), patch.object(vm.time, "sleep", return_value=None), patch.object(
                vm, "send_first_iso_boot_key_vnc"
            ) as key, patch.object(
                vm, "capture_vm_screen", return_value="a" * 64
            ) as capture:
                ok, reason = vm.boot_vm(
                    ["qemu-system-x86_64"], transcript, 600,
                    "win10_22h2_en_us_x64",
                    monitor_socket=work / "monitor.sock",
                    boot_key_transport="vnc", diagnostic_dir=work)
            self.assertFalse(ok, reason)
            self.assertIn("timed out", reason)
            key.assert_called_once()
            self.assertEqual(capture.call_count, 2)
            self.assertEqual(
                [call.args[1].name for call in capture.call_args_list],
                ["windows-dvd-90s.ppm", "windows-dvd-180s.ppm"],
            )
            self.assertTrue(qemu.killed)


    def test_fragmented_hmp_echo_waits_for_terminal_prompt(self):
        class FakeMonitor:
            def __init__(self):
                self.chunks = iter([
                    b"QEMU 8.2.2 monitor\r\n(qe", b"mu) ",
                    b"s\x1b[K", b"scr\x1b[K", b"screendump ",
                    b"/home/runner/work/_temp/owned.ppm\r\n", b"(qemu) ",
                ])
            def recv(self, unused_count):
                return next(self.chunks)
        qemu = FakeMonitor()
        self.assertEqual(
            vm._receive_complete_hmp_reply(qemu, banner=True),
            b"QEMU 8.2.2 monitor\r\n(qemu) ",
        )
        reply = vm._receive_complete_hmp_reply(qemu, banner=False)
        self.assertTrue(reply.endswith(b"\r\n(qemu) "))
        self.assertIn(b"screendump ", reply)

    def test_false_midstream_prompt_cannot_end_hmp_reply(self):
        class FakeMonitor:
            def __init__(self):
                self.chunks = iter([
                    b"(qemu) inside echoed text\r\nstill working",
                    b"\r\n(qemu) ",
                ])
            def recv(self, unused_count):
                return next(self.chunks)
        reply = vm._receive_complete_hmp_reply(FakeMonitor(), banner=False)
        self.assertTrue(reply.endswith(b"\r\n(qemu) "))

    def test_incomplete_or_disconnected_hmp_command_fails_closed(self):
        class FakeMonitor:
            def __init__(self):
                self.chunks = iter([b"screendump file.ppm\r\n(qemu)", b""])
            def recv(self, unused_count):
                return next(self.chunks)
        with self.assertRaisesRegex(vm.LabError, "disconnected"):
            vm._receive_complete_hmp_reply(FakeMonitor(), banner=False)

    def test_no_boot_prompt_never_captures_framebuffer(self):
        with tempfile.TemporaryDirectory() as temp:
            work = pathlib.Path(temp)
            transcript = work / "serial.log"
            transcript.write_bytes(b"no bootable device\r\n")
            qemu = FakeQemu()
            ticks = iter(range(0, 3000, 20))
            with patch.object(vm.subprocess, "Popen", return_value=qemu), patch.object(
                vm.time, "monotonic", side_effect=lambda: next(ticks)
            ), patch.object(vm.time, "sleep", return_value=None), patch.object(
                vm, "send_first_iso_boot_key_vnc"
            ) as key, patch.object(vm, "capture_vm_screen") as capture:
                ok, _ = vm.boot_vm(
                    ["qemu-system-x86_64"], transcript, 600,
                    "win10_22h2_en_us_x64",
                    monitor_socket=work / "monitor.sock",
                    boot_key_transport="vnc", diagnostic_dir=work)
            self.assertFalse(ok)
            key.assert_not_called()
            capture.assert_not_called()
            self.assertTrue(qemu.killed)


if __name__ == "__main__":
    unittest.main()
