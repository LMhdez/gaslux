"""QMP ACPI dispatch must be acknowledged and emit a POWERDOWN event."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from zorin_qmp_powerdown import request_guest_acpi_powerdown, ZorinQmpError


class FakeQmp:
    def __init__(self, *, powerdown_event=True, error=None, only_greeting=False):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "qmp.sock"
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        self.listener.listen(1)
        self.powerdown_event = powerdown_event
        self.error = error
        self.only_greeting = only_greeting
        self.received = []
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    def serve(self):
        try:
            conn, _ = self.listener.accept()
            with conn:
                conn.sendall(b'{"QMP":{"version":{"qemu":{"major":8}},"capabilities":[]}}\n')
                if self.only_greeting:
                    return
                buffer = conn.makefile("rb")
                for expected in ("qmp_capabilities", "system_powerdown"):
                    item = json.loads(buffer.readline())
                    self.received.append(item["execute"])
                    if item["execute"] != expected:
                        return
                    if expected == "system_powerdown" and self.error:
                        response = {"id": item["id"], "error": {"class": "GenericError",
                                                               "desc": self.error}}
                    else:
                        response = {"id": item["id"], "return": {}}
                    conn.sendall((json.dumps(response) + "\n").encode())
                    if expected == "system_powerdown" and self.powerdown_event:
                        conn.sendall(b'{"event":"POWERDOWN","timestamp":{"seconds":1,"microseconds":2}}\n')
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def close(self):
        self.listener.close()
        self.worker.join(timeout=2)
        self.tmp.cleanup()


class TestZorinQmpPowerdown(unittest.TestCase):
    def test_ack_and_powerdown_event(self):
        fake = FakeQmp()
        try:
            proof = request_guest_acpi_powerdown(fake.path, timeout_seconds=3)
            self.assertEqual(proof, {"qmpCommandAcknowledged": True,
                                    "qmpPowerdownEventObserved": True})
            self.assertEqual(fake.received, ["qmp_capabilities", "system_powerdown"])
        finally:
            fake.close()

    def test_ack_without_powerdown_event_refused(self):
        fake = FakeQmp(powerdown_event=False)
        try:
            with self.assertRaises(ZorinQmpError):
                request_guest_acpi_powerdown(fake.path, timeout_seconds=3)
        finally:
            fake.close()

    def test_command_error_refused(self):
        fake = FakeQmp(error="unsupported")
        try:
            with self.assertRaisesRegex(ZorinQmpError, "refused"):
                request_guest_acpi_powerdown(fake.path, timeout_seconds=3)
        finally:
            fake.close()

    def test_incomplete_handshake_refused(self):
        fake = FakeQmp(only_greeting=True)
        try:
            with self.assertRaises(ZorinQmpError):
                request_guest_acpi_powerdown(fake.path, timeout_seconds=3)
        finally:
            fake.close()

    def test_non_socket_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qmp.sock"
            path.write_text("not a socket", encoding="utf-8")
            with self.assertRaisesRegex(ZorinQmpError, "socket"):
                request_guest_acpi_powerdown(path, timeout_seconds=3)

    def test_out_of_bounds_timeout_refused(self):
        with self.assertRaisesRegex(ZorinQmpError, "bounded"):
            request_guest_acpi_powerdown(Path("/missing"), timeout_seconds=90)


if __name__ == "__main__":
    unittest.main()
