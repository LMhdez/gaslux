"""Proven Windows 10 FAT12 historical control plus hardened COM1 proof.

Only synthetic arguments/XML/PowerShell; never launch a guest or touch disks.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "gaslux_hardened_fat12_control", TOOLS / "windows_x64_tcg_firstboot.py"
)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


def qemu_args(parent: pathlib.Path):
    return [
        "qemu-system-x86_64", "-machine", "q35,accel=kvm,smm=on",
        "-monitor", f"unix:{parent}/hmp.sock,server,nowait",
        "-drive", "if=none,id=only_windows,format=qcow2,file=/tmp/mock.qcow2",
        "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
        "-drive", "if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file=/tmp/derived.iso",
        "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
        "-drive", f"if=floppy,format=raw,file={parent}/unattend-floppy.img",
        "-serial", f"file:{parent}/win-guest-serial.log",
        "-boot", "order=c,once=d",
    ]


class HardenedFat12Control(unittest.TestCase):
    def test_default_path_refuses_floppy(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(vm.LabError, "read-only owned USB"):
                vm.build_two_stage_qemu_args(
                    qemu_args(pathlib.Path(d)), pathlib.Path(d) / "stage1.log",
                )

    def test_explicit_floppy_only_and_disk_only_after_reboot(self):
        with tempfile.TemporaryDirectory() as d:
            args = qemu_args(pathlib.Path(d))
            dvd, disk = vm.build_two_stage_qemu_args(
                args, pathlib.Path(d) / "stage1.log",
                fat12_control_lab=True,
            )
            self.assertIn("-no-reboot", dvd)
            self.assertNotIn("-no-reboot", disk)
            self.assertEqual(dvd[dvd.index("-boot") + 1], "order=d")
            self.assertEqual(disk[disk.index("-boot") + 1], "order=c")
            self.assertIn("if=floppy,format=raw,file=", " ".join(disk))
            self.assertNotIn("verified_iso", " ".join(disk))
            self.assertNotIn("ide-cd,", " ".join(disk))
            self.assertNotIn("lab_unattend", " ".join(disk))
            self.assertIn("only_windows", " ".join(disk))

    def test_foreign_floppy_and_extra_usb_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            parent = pathlib.Path(d)
            args = qemu_args(parent)
            ix = next(i for i, a in enumerate(args) if "if=floppy" in a)
            for change in ("unowned.img", "/dev/sda", "unattend-floppy.img.bak"):
                with self.subTest(change=change):
                    modified = args[:]
                    modified[ix] = (
                        "if=floppy,format=raw,file=" +
                        (change if change.startswith("/") else str(parent / change))
                    )
                    with self.assertRaisesRegex(vm.LabError, "unique VM-owned"):
                        vm.build_two_stage_qemu_args(
                            modified, parent / "stage1.log",
                            fat12_control_lab=True,
                        )
            mixed = args + ["-device", "usb-storage,drive=lab_unattend,bus=lab_usb.0"]
            with self.assertRaisesRegex(vm.LabError, "unique VM-owned"):
                vm.build_two_stage_qemu_args(
                    mixed, parent / "stage1.log", fat12_control_lab=True,
                )

    def test_xml_floppy_path_retained_only_in_control(self):
        x = vm.generate_unattend("win10_22h2_en_us_x64", "19045")
        y = vm.generate_unattend(
            "win10_22h2_en_us_x64", "19045", removable_answer=True,
        )
        self.assertIn(b"A:\\GASLUX.PS1", x)
        self.assertNotIn(b"A:\\GASLUX.PS1", y)
        self.assertIn(b"Get-Volume -FileSystemLabel GASLUXCI", y)

    def test_real_guest_script_produces_seven_independent_tokens(self):
        script = vm.witness_powershell("win10_22h2_en_us_x64", "19045")
        self.assertIn("('GASLUX_WINDOWS_X64_BOOT_BUILD=' + $os.BuildNumber)", script)
        self.assertNotIn("'GASLUX_WINDOWS_X64_BOOT_BUILD=' + $os.BuildNumber,", script)
        self.assertIn("@($serialProof).Count -ne 7", script)
        self.assertIn("$line -isnot [string]", script)
        self.assertIn("$line -match '\\s'", script)
        self.assertIn("GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL_STAGE=", script)
        self.assertIn("Get-Partition", script)
        self.assertIn("reagentc /info", script)
        self.assertIn("bcdedit /enum", script)

    def test_fat12_flag_requires_explicit_hosted_consent(self):
        args = [
            "--profile", "win10_22h2_en_us_x64", "--accel", "kvm",
            "--derived-no-prompt", "--two-stage-install-only",
            "--fat12-proof-control",
        ]
        with patch.dict(os.environ, {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GASLUX_WINDOWS_FAT12_PROOF_CONSENT": "",
        }):
            with self.assertRaisesRegex(SystemExit, "per-profile hosted KVM consent"):
                vm.main(args)

    def test_fat12_flag_requires_exact_client_and_install_mode(self):
        for profile, extra in (
            ("win11_26h2_en_us_x64", []),
            ("win10_22h2_en_us_x64", ["--fixture-only"]),
            ("win10_22h2_en_us_x64", ["--one-shot-install-only"]),
        ):
            with self.subTest(profile=profile, extra=extra):
                args = [
                    "--profile", profile, "--accel", "kvm",
                    "--derived-no-prompt", "--two-stage-install-only",
                    "--fat12-proof-control", *extra,
                ]
                with patch.dict(os.environ, {
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_ENVIRONMENT": "github-hosted",
                    "GASLUX_WINDOWS_FAT12_PROOF_CONSENT":
                        "I_ACCEPT_DISPOSABLE_HOSTED_KVM_FAT12_CONTROL",
                }):
                    with self.assertRaisesRegex(SystemExit, "per-profile hosted KVM consent"):
                        vm.main(args)


    def test_win11_requires_its_own_distinct_tpm_control_consent(self):
        args = [
            "--profile", "win11_26h2_en_us_x64", "--accel", "kvm",
            "--derived-no-prompt", "--two-stage-install-only",
            "--fat12-proof-control",
        ]
        for inherited in ("", "I_ACCEPT_DISPOSABLE_HOSTED_KVM_FAT12_CONTROL"):
            with self.subTest(consent=inherited), patch.dict(os.environ, {
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "GASLUX_WINDOWS_FAT12_PROOF_CONSENT": inherited,
            }):
                with patch.object(vm, "load_catalog",
                                  side_effect=AssertionError("must not read catalog")):
                    with self.assertRaisesRegex(SystemExit, "per-profile hosted KVM consent"):
                        vm.main(args)

    def test_win11_explicit_consent_passes_only_preflight_not_guest_boot(self):
        args = [
            "--profile", "win11_26h2_en_us_x64", "--accel", "kvm",
            "--derived-no-prompt", "--two-stage-install-only",
            "--fat12-proof-control",
        ]
        with patch.dict(os.environ, {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GASLUX_WINDOWS_FAT12_PROOF_CONSENT":
                "I_ACCEPT_DISPOSABLE_HOSTED_KVM_WIN11_TPM_FAT12_CONTROL",
            "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
                "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
        }):
            # Abort deliberately before catalog, ISO, subprocess or any VM.
            with patch.object(vm, "load_catalog",
                              side_effect=RuntimeError("passed control preflight")):
                with self.assertRaisesRegex(RuntimeError, "passed control preflight"):
                    vm.main(args)

    def test_win11_control_never_approves_win10_consent(self):
        args = [
            "--profile", "win10_22h2_en_us_x64", "--accel", "kvm",
            "--derived-no-prompt", "--two-stage-install-only",
            "--fat12-proof-control",
        ]
        with patch.dict(os.environ, {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GASLUX_WINDOWS_FAT12_PROOF_CONSENT":
                "I_ACCEPT_DISPOSABLE_HOSTED_KVM_WIN11_TPM_FAT12_CONTROL",
        }):
            with self.assertRaisesRegex(SystemExit, "per-profile hosted KVM consent"):
                vm.main(args)

    def test_win11_audit_requires_full_seven_independent_markers(self):
        script = vm.witness_powershell("win11_26h2_en_us_x64", "26300")
        self.assertIn("('GASLUX_WINDOWS_X64_BOOT_BUILD=' + $os.BuildNumber)", script)
        self.assertIn("@($serialProof).Count -ne 7", script)
        self.assertIn("$line -isnot [string]", script)
        self.assertIn("GASLUX_WINDOWS_X64_WINRE_ENABLED=1", script)
        self.assertIn("bcdedit /enum", script)
        self.assertIn("reagentc /info", script)
        self.assertIn("GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL_STAGE=", script)
        self.assertIn("GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64", script)

    def test_win11_fat12_guest_requires_private_tpm_restart(self):
        # The guard executes before launching either QEMU stage.
        import inspect
        code = inspect.getsource(vm.boot_two_stage_windows)
        self.assertIn('profile_key != "win11_26h2_en_us_x64" or restart_tpm is not None', code)
        self.assertIn("restart_tpm()", code)
        self.assertIn("fat12_control_lab=fat12_control_lab", code)
        self.assertIn("reject_repeated_dvd_boot=True", code)



    def test_win11_immediate_local_shutdown_not_restart(self):
        guest = vm.witness_powershell("win11_26h2_en_us_x64", "26300")
        self.assertIn('& "$env:WINDIR\\System32\\shutdown.exe" /p /f', guest)
        self.assertNotIn('shutdown.exe" /r', guest)
        self.assertIn("@($serialProof).Count -ne 7", guest)
        self.assertIn("reagentc /info", guest)

    def test_win10_historical_shutdown_command_unchanged(self):
        guest = vm.witness_powershell("win10_22h2_en_us_x64", "19045")
        self.assertIn('& "$env:WINDIR\\System32\\shutdown.exe" /s /f /t 0',
                      guest)
        self.assertNotIn('shutdown.exe" /p /f', guest)

    def test_repeated_windows_boot_manager_rejects_even_with_full_witness(self):
        import unittest.mock
        from pathlib import Path
        class FakeQemu:
            def poll(self): return 0
            def kill(self): raise AssertionError("already stopped")
            def wait(self, timeout): return 0
        guest = b" ".join([
            b"GASLUX_WINDOWS_X64_BOOT_BUILD=26300",
            b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
            b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
            b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
            b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
            b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64",
        ]) + b"\n"
        boot = b'BdsDxe: starting Boot0003 "Windows Boot Manager"\r\n'
        with tempfile.TemporaryDirectory() as root:
            serial = Path(root) / "serial.log"
            serial.write_bytes(boot + guest + boot)
            with patch.object(vm.subprocess, "Popen", return_value=FakeQemu()):
                success, msg = vm.boot_vm(
                    ["qemu-system-x86_64"], serial, 60,
                    "win11_26h2_en_us_x64",
                    reject_repeated_dvd_boot=True,
                )
            self.assertFalse(success)
            self.assertIn("rebooted after first-logon", msg)

    def test_single_windows_boot_manager_with_full_proof_still_accepted(self):
        from pathlib import Path
        class FakeQemu:
            def poll(self): return 0
            def kill(self): raise AssertionError("already stopped")
            def wait(self, timeout): return 0
        with tempfile.TemporaryDirectory() as root:
            serial = Path(root) / "serial.log"
            serial.write_bytes(
                b'BdsDxe: starting Boot0003 "Windows Boot Manager"\r\n'
                b"GASLUX_WINDOWS_X64_BOOT_BUILD=26300 "
                b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1 "
                b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1 "
                b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1 "
                b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1 "
                b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1 "
                b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64\n"
            )
            with patch.object(vm.subprocess, "Popen", return_value=FakeQemu()):
                success, msg = vm.boot_vm(
                    ["qemu-system-x86_64"], serial, 60,
                    "win11_26h2_en_us_x64",
                    reject_repeated_dvd_boot=True,
                )
            self.assertTrue(success, msg)

    def test_split_windows_boot_manager_marker_detected_after_long_serial(self):
        from pathlib import Path
        marker = b'BdsDxe: starting Boot0AF3 "Windows Boot Manager"'
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "serial.log"
            path.write_bytes(marker[:23])
            n1, offset, carry, _ = vm.scan_two_stage_dvd_serial(
                path, 0, b"", vm.WINDOWS_BOOT_MANAGER_START,
            )
            self.assertEqual(n1, 0)
            with path.open("ab") as stream:
                stream.write(marker[23:] + b"\n" + b"X" * 500_000 + marker)
            n2, offset, carry, _ = vm.scan_two_stage_dvd_serial(
                path, offset, carry, vm.WINDOWS_BOOT_MANAGER_START,
            )
            self.assertEqual(n2, 2)



if __name__ == "__main__":
    unittest.main()
