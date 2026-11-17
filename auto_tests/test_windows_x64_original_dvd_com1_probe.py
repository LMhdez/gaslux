"""Diskless original Win10 UEFI prompt integration: fail-closed offline contracts."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SRC = TOOLS / "windows_x64_original_dvd_com1_probe.py"
SPEC = importlib.util.spec_from_file_location("original_dvd_probe_tests", SRC)
assert SPEC and SPEC.loader
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)

GOOD_DIR = Path("/home/runner/work/_temp/gaslux-win-x64-unit")


def vm_args(ser: Path, mon: Path) -> list[str]:
    return ["qemu-system-x86_64", "-net", "none", "-serial",
            "file:" + str(ser), "-monitor",
            f"unix:{mon},server,nowait",
            "-drive", "if=pflash,format=raw,readonly=on,file=/tmp/ovmf-code.fd",
            "-drive", "if=pflash,format=raw,file=/tmp/private-vars.fd",
            "-drive", "if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file=/tmp/original.iso"]


class OriginalDvdOnlySafety(unittest.TestCase):
    def rejects(self, args: list[str], serial: Path | None = None,
                monitor: Path | None = None):
        serial = serial or GOOD_DIR / "serial.log"
        monitor = monitor or GOOD_DIR / "initial-installer-hmp.sock"
        with patch.object(P.subprocess, "Popen") as spawn:
            with self.assertRaises(P.LabError):
                P.original_dvd_probe(args, serial, monitor, 300)
            spawn.assert_not_called()

    def test_foreign_runner_directory_rejected_before_vm(self):
        ser = Path("/tmp/foreign/serial.log")
        mon = Path("/tmp/foreign/initial-installer-hmp.sock")
        self.rejects(vm_args(ser, mon), ser, mon)

    def test_any_host_disk_drive_argument_rejected(self):
        ser = GOOD_DIR / "serial.log"
        mon = GOOD_DIR / "initial-installer-hmp.sock"
        self.rejects(vm_args(ser, mon) +
                     ["-drive", "if=none,id=only_windows,format=raw,file=/dev/sda"])

    def test_network_enabled_rejected(self):
        ser = GOOD_DIR / "serial.log"
        mon = GOOD_DIR / "initial-installer-hmp.sock"
        a = vm_args(ser, mon)
        a[a.index("-net") + 1] = "user"
        self.rejects(a)

    def test_writable_iso_rejected(self):
        ser = GOOD_DIR / "serial.log"
        mon = GOOD_DIR / "initial-installer-hmp.sock"
        args = vm_args(ser, mon)
        args[-1] = args[-1].replace("readonly=on,", "")
        self.rejects(args)

    def test_wrong_hmp_endpoint_rejected(self):
        ser = GOOD_DIR / "serial.log"
        mon = GOOD_DIR / "initial-installer-hmp.sock"
        a = vm_args(ser, mon)
        a[a.index("-monitor") + 1] = "none"
        self.rejects(a)

    def test_disallowed_hold_duration_rejected(self):
        ser = GOOD_DIR / "serial.log"
        mon = GOOD_DIR / "initial-installer-hmp.sock"
        with patch.object(P.subprocess, "Popen") as spawn:
            with self.assertRaises(P.LabError):
                P.original_dvd_probe(vm_args(ser, mon), ser, mon, 12000)
            spawn.assert_not_called()

    def test_short_probe_never_attaches_a_guest_disk(self):
        source = SRC.read_text()
        self.assertIn('"-net", "none"', source)
        self.assertIn('"if=none,id=verified_iso,media=cdrom,readonly=on', source)
        self.assertIn('sum("if=pflash" in x for x in drive_values) == 2', source)
        self.assertIn('len(drive_values) == 3', source)
        self.assertNotIn('"-drive", "if=none,id=only_windows', source)
        self.assertIn('NOT TESTED: WinPE Setup, Windows installation', source)


if __name__ == "__main__":
    unittest.main()
