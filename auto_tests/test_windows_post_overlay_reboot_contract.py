"""No-VM regressions for Windows 10 post-overlay guest attestation wiring."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "windows_post_overlay_contract", TOOLS / "windows_x64_tcg_firstboot.py")
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


def synthetic_qemu_arguments(temp: Path) -> list[str]:
    return [
        "qemu-system-x86_64", "-machine", "q35,accel=kvm,smm=on",
        "-monitor", f"unix:{temp}/monitor.sock,server,nowait",
        "-drive", "if=none,id=only_windows,format=qcow2,file=/tmp/synthetic.qcow2",
        "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
        "-drive", "if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file=/tmp/synthetic.iso",
        "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
        "-drive", "if=floppy,format=raw,file=/tmp/synthetic-answer.img",
        "-serial", f"file:{temp}/first-stage.log",
        "-boot", "order=dc",
    ]


class WindowsPostOverlayRebootContract(unittest.TestCase):
    def test_third_guest_excludes_installer_and_floppy_and_uses_fresh_serial(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            post = folder / "post-overlay-guest"
            post.mkdir(mode=0o700)
            serial = post / "win-post-overlay-serial.log"
            args = vm.build_post_overlay_disk_boot_args(
                synthetic_qemu_arguments(folder), serial)
            self.assertIn("order=c", args)
            self.assertEqual(args[args.index("-serial") + 1], "file:" + str(serial))
            self.assertEqual(args[args.index("-monitor") + 1], "none")
            self.assertTrue(any("id=only_windows" in x for x in args))
            self.assertFalse(any("verified_iso" in x or "if=floppy" in x
                                 for x in args))
            self.assertNotIn("-no-reboot", args)

    def test_reused_guest_serial_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            post = folder / "post-overlay-guest"
            post.mkdir(mode=0o700)
            serial = post / "win-post-overlay-serial.log"
            serial.write_text("stale")
            with self.assertRaisesRegex(vm.LabError, "reused"):
                vm.build_post_overlay_disk_boot_args(
                    synthetic_qemu_arguments(folder), serial)

    def test_first_guest_arms_startup_task_before_emitting_evidence(self):
        script = vm.witness_powershell(
            "win10_22h2_en_us_x64", "19045", arm_post_overlay=True)
        self.assertIn("A:\\GASLUX2.PS1", script)
        self.assertIn("schtasks.exe /Create", script)
        self.assertLess(script.index("schtasks.exe /Create"),
                        script.index("$serialProof = @("))
        self.assertIn("GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=", script)
        self.assertNotIn("GASLUX_WINDOWS_X64_POST_OVERLAY_BOOT_VERIFIED=", script)
        self.assertIn("bcdedit /enum", script)
        self.assertIn("reagentc /info", script)

    def test_second_guest_executes_independent_audit_and_removes_task(self):
        script = vm.witness_powershell(
            "win10_22h2_en_us_x64", "19045", post_overlay=True)
        self.assertIn("schtasks.exe /Delete", script)
        self.assertLess(script.index("schtasks.exe /Delete"),
                        script.index("$serialProof = @("))
        self.assertNotIn("schtasks.exe /Create", script)
        self.assertNotIn("GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=", script)
        self.assertIn("GASLUX_WINDOWS_X64_POST_OVERLAY_BOOT_VERIFIED=", script)
        for witness in ("bcdedit /enum", "reagentc /info",
                        "Get-Partition -DiskNumber 0", "winload.efi",
                        "GASLUX_WINDOWS_X64_WINRE_ENABLED=1"):
            self.assertIn(witness, script)

    def test_default_firstboot_does_not_install_reboot_task(self):
        script = vm.witness_powershell("win10_22h2_en_us_x64", "19045")
        self.assertNotIn("schtasks.exe", script)
        self.assertIn("GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=", script)

    def test_conflicting_guest_phases_are_rejected(self):
        with self.assertRaisesRegex(vm.LabError, "ambiguous"):
            vm.witness_powershell(
                "win10_22h2_en_us_x64", "19045",
                arm_post_overlay=True, post_overlay=True)


if __name__ == "__main__":
    unittest.main()
