"""Fail-closed Windows x64 UEFI QEMU display diagnostics; no guest boot claims."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

PATH = Path(__file__).resolve().parent / "tools/windows_x64_uefi_visual_probe.py"
spec = importlib.util.spec_from_file_location("qemu_windows_visual_probe", PATH)
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DisplayProbeTests(unittest.TestCase):
    def test_foreign_socket_is_rejected(self):
        with self.assertRaisesRegex(probe.ProbeError, "unowned QEMU monitor path"):
            probe.validate_monitor_path(Path("/tmp/untrusted/monitor.sock"))

    def test_only_owned_private_temp_socket_is_permitted(self):
        sock = probe.RUNNER_ROOT / "gaslux-win-x64-1234" / "initial-installer-hmp.sock"
        def stat_for(path):
            if path == sock.parent:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=os.getuid())
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=os.getuid())
        with patch.object(Path, "is_socket", return_value=True), \
             patch.object(Path, "is_symlink", return_value=False), \
             patch.object(Path, "resolve", lambda p: p), \
             patch.object(Path, "stat", stat_for):
            probe.validate_monitor_path(sock)

    def test_bad_workspace_permissions_rejected(self):
        sock = probe.RUNNER_ROOT / "gaslux-win-x64-1234" / "initial-installer-hmp.sock"
        with patch.object(Path, "is_socket", return_value=True), \
             patch.object(Path, "is_symlink", return_value=False), \
             patch.object(Path, "resolve", lambda p: p), \
             patch.object(Path, "stat", lambda p: SimpleNamespace(
                 st_mode=stat.S_IFDIR | 0o755, st_uid=os.getuid())):
            with self.assertRaisesRegex(probe.ProbeError, "unsafe QEMU workspace"):
                probe.validate_monitor_path(sock)

    def test_capture_is_read_only_and_hash_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            monitor = base / "initial-installer-hmp.sock"
            evidence = base / "evidence"
            evidence.mkdir()
            class FakeHmp:
                def __init__(self):
                    self.calls = 0
                    self.messages = []
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    return None
                def settimeout(self, value):
                    self.assert_timeout = value
                def connect(self, value):
                    self.connected = value
                def recv(self, amount):
                    self.calls += 1
                    return b"QEMU 8.2 monitor (qemu) " if self.calls == 1 else b"(qemu) "
                def sendall(self, payload):
                    self.messages.append(payload)
                    command = payload.decode("ascii")
                    self_path = Path(command.removeprefix("screendump ").strip())
                    self_path.write_bytes(b"P6\n2 2\n255\n" + b"\x00" * 12)
            fake = FakeHmp()
            with patch.object(probe, "validate_monitor_path"), \
                 patch.object(probe.socket, "socket", return_value=fake):
                result = probe.snapshot(monitor, evidence, probe.PROFILES[0], probe.LABELS[0])
            self.assertEqual(result["bytes"], 23)
            self.assertEqual(len(result["sha256"]), 64)
            self.assertEqual(fake.messages, [
                f"screendump {base}/gaslux-00-dvd.ppm\n".encode("ascii")
            ])
            self.assertTrue((evidence / result["file"]).is_file())
            self.assertNotIn(b"sendkey", b"".join(fake.messages))

    def test_partial_hmp_echo_must_be_drained_before_socket_close(self):
        class FragmentedQemu:
            def __init__(self):
                self.parts = iter([
                    b"QEMU 8.2 monitor\r\n",
                    b"(qemu) ",
                    b"s\x1b[K",
                    b"screendump /tmp/test.ppm\r\n",
                    b"(qemu) ",
                ])
            def recv(self, count):
                return next(self.parts)
        hmp = FragmentedQemu()
        first = probe.read_hmp_prompt(hmp)
        self.assertIn(b"(qemu) ", first)
        second = probe.read_hmp_prompt(hmp)
        self.assertIn(b"screendump /tmp/test.ppm", second)
        self.assertTrue(second.endswith(b"(qemu) "))

    def test_hmp_disconnect_fails_closed(self):
        class ClosedQemu:
            def recv(self, count):
                return b"QEMU 8.2 monitor\r\n" if not hasattr(self, "read") else b""
            read = True
        with self.assertRaisesRegex(probe.ProbeError, "disconnected"):
            probe.read_hmp_prompt(ClosedQemu())

    def test_no_ci_authorization_rejects_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(probe.ProbeError, "disposable hosted"):
                    probe.validate_ci(Path(temp))

    def test_production_only_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(probe, "validate_monitor_path"):
                with self.assertRaisesRegex(probe.ProbeError, "invalid screenshot label"):
                    probe.snapshot(Path(temp) / "hmp.sock", Path(temp),
                                   probe.PROFILES[0], "delete-all-disks")


if __name__ == "__main__":
    unittest.main()
