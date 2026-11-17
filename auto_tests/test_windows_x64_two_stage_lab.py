"""Two-stage no-prompt Windows KVM laboratory safety contract (synthetic).

These tests do NOT download an ISO, start QEMU or modify any disk. Full
Windows client firstboot requires a separate real guest serial witness.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_tcg_firstboot.py"
SPEC = importlib.util.spec_from_file_location("gaslux_two_stage_windows", SOURCE)
assert SPEC and SPEC.loader
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)


class TwoStageSafetyTests(unittest.TestCase):
    def cli(self, *extra):
        return subprocess.run(
            [sys.executable, str(SOURCE), "--profile", "win10_22h2_en_us_x64",
             *extra],
            capture_output=True, text=True, timeout=12,
        )

    def test_opt_in_required_and_only_kvm(self):
        self.assertNotEqual(
            self.cli("--derived-no-prompt", "--accel", "kvm").returncode, 0
        )
        self.assertNotEqual(
            self.cli("--lab-install-derived", "--accel", "kvm").returncode, 0
        )
        self.assertNotEqual(
            self.cli("--lab-install-derived", "--derived-no-prompt",
                     "--accel", "tcg").returncode, 0
        )

    def test_probe_and_installer_cannot_run_together(self):
        result = self.cli(
            "--boot-probe-only", "--lab-install-derived",
            "--derived-no-prompt", "--accel", "kvm",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not use --boot-probe-only", result.stderr)

    def test_lab_requires_sufficient_timeout(self):
        result = self.cli(
            "--lab-install-derived", "--derived-no-prompt",
            "--accel", "kvm", "--boot-timeout", "120",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("at least 1800s", result.stderr)

    def test_only_disposable_installed_qcow2_is_exposed_to_stage_two(self):
        with tempfile.TemporaryDirectory() as p:
            root = Path(p)
            iso, floppy, disk = (root / "iso", root / "unattend", root / "target.qcow2")
            code, vars_file = root / "ovmf.code", root / "ovmf.vars"
            socket, serial = root / "hmp.sock", root / "setup.log"
            new = root / "installed.log"
            first = [
                "qemu-system-x86_64",
                "-machine", "q35,accel=kvm,smm=on",
                "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive", f"if=pflash,format=raw,file={vars_file}",
                "-drive", f"if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file={iso}",
                "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
                "-monitor", f"unix:{socket},server,nowait",
                "-drive", f"if=floppy,format=raw,file={floppy}",
                "-drive", f"if=none,id=only_windows,format=qcow2,file={disk}",
                "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
                "-serial", f"file:{serial}",
                "-boot", "order=dc",
            ]
            opts = dict(iso=iso, floppy=floppy, target=disk, code=code,
                        nvram=vars_file, monitor=socket, first_serial=serial,
                        installed_serial=new)
            second = VM.installed_only_qemu_command(first, **opts)
            self.assertEqual(second[-1], "order=c")
            self.assertIn(f"if=none,id=only_windows,format=qcow2,file={disk}",
                          second)
            self.assertEqual(sum(x == "-drive" for x in second), 3)
            self.assertFalse(any(str(iso) in x or str(floppy) in x for x in second))
            self.assertNotIn("-monitor", second)
            self.assertNotIn("ide-cd,drive=verified_iso,bus=lab_sata.1", second)
            self.assertNotIn("-no-reboot", second)
            self.assertIn(f"file:{new}", second)

            with self.assertRaisesRegex(VM.LabError, "second-stage QEMU disk"):
                VM.installed_only_qemu_command(
                    first + ["-drive", "if=none,id=foreign,file=/dev/sda"],
                    **opts,
                )
            with self.assertRaisesRegex(VM.LabError, "media removal"):
                VM.installed_only_qemu_command(
                    first[:-4] + first[-2:], **opts
                )
            with self.assertRaisesRegex(VM.LabError, "disk ownership"):
                VM.installed_only_qemu_command(
                    [v for idx, v in enumerate(first)
                     if idx not in (first.index("ide-hd,drive=only_windows,bus=lab_sata.0") - 1,
                                   first.index("ide-hd,drive=only_windows,bus=lab_sata.0"))],
                    **opts,
                )

    def test_setup_requires_no_reboot_and_non_reused_serial(self):
        with tempfile.TemporaryDirectory() as p:
            serial = Path(p) / "setup.log"
            with self.assertRaisesRegex(VM.LabError, "reboot contract"):
                VM.stage_verified_dvd_until_first_restart(
                    ["qemu-system-x86_64"], serial, 600
                )
            serial.write_text("stale marker")
            with self.assertRaisesRegex(VM.LabError, "reboot contract"):
                VM.stage_verified_dvd_until_first_restart(
                    ["qemu-system-x86_64", "-no-reboot"], serial, 600
                )

    def test_derivative_does_not_claim_boot_from_firmware_only(self):
        text = SOURCE.read_text()
        self.assertIn("labSecondQemuBootMediaDetached", text)
        self.assertIn("monitor_socket=None", text)
        self.assertIn('report["windowsClientBootVerified"] = ok', text)
        self.assertIn('report["stable"]', text)
        self.assertNotIn('report["stable"] = True', text)


if __name__ == "__main__":
    unittest.main()
