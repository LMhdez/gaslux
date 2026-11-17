"""Fail-closed tests: no DVD in second EFI guest, no host disk or fake boot proof.

No Windows ISO, QEMU guest or host storage mutation is executed by this suite.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
SRC = TOOLS / "windows_x64_tcg_firstboot.py"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("gaslux_windows_two_stage_lab", SRC)
assert SPEC and SPEC.loader
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)


def synthetic_args(tmp):
    return [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm,smm=on",
        "-monitor", f"unix:{tmp}/hmp.sock,server,nowait",
        "-drive", "if=none,id=only_windows,format=qcow2,file=/tmp/mock.qcow2",
        "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
        "-drive", "if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file=/tmp/derived.iso",
        "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
        "-drive", "if=floppy,format=raw,file=/tmp/autounattend.img",
        "-serial", f"file:{tmp}/win-guest-serial.log",
        "-boot", "order=c,once=d",
    ]


class WindowsTwoStageSafetyTests(unittest.TestCase):

    def test_incremental_dvd_scan_preserves_old_boot_when_log_exceeds_400k(self):
        with tempfile.TemporaryDirectory() as d:
            serial = pathlib.Path(d) / "vm-serial.log"
            first = b'BdsDxe: starting Boot0001 "UEFI QEMU DVD-ROM'
            second = b'BdsDxe: starting Boot00AF "UEFI QEMU DVD-ROM'
            serial.write_bytes(first)
            n, offset, carry, tail = VM.scan_two_stage_dvd_serial(
                serial, 0, b"",
            )
            self.assertEqual(n, 1)
            self.assertIn(first, tail)
            with serial.open("ab") as stream:
                stream.write(b"x" * 500_000 + second)
            n2, offset, carry, tail = VM.scan_two_stage_dvd_serial(
                serial, offset, carry,
            )
            self.assertEqual(n2, 1)
            self.assertNotIn(first, tail)
            self.assertIn(second, tail)
            self.assertEqual(n + n2, 2)

    def test_fragmented_hex_uefi_marker_counted_once(self):
        marker = b'BdsDxe: starting Boot0AF3 "UEFI QEMU DVD-ROM'
        count, carry = 0, b""
        for fragment in (
            marker[:8], marker[8:18], marker[18:30], marker[30:],
        ):
            found, carry = VM.scan_dvd_firmware_starts(fragment, carry)
            count += found
        self.assertEqual(count, 1)
        found, carry = VM.scan_dvd_firmware_starts(
            b"waiting for installed guest", carry,
        )
        self.assertEqual(found, 0)

    def test_stage_one_serial_truncation_denied_before_second_guest(self):
        with tempfile.TemporaryDirectory() as d:
            serial = pathlib.Path(d) / "vm-serial.log"
            serial.write_bytes(b'BdsDxe: starting Boot0001 "UEFI QEMU DVD-ROM')
            VM.scan_two_stage_dvd_serial(serial, 0, b"")
            with self.assertRaisesRegex(VM.LabError, "truncated"):
                VM.scan_two_stage_dvd_serial(serial, 1024, b"")

    def test_two_stage_boot_uses_incremental_full_uefi_marker_count(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn("dvd_start_count += found", source)
        self.assertIn("if dvd_start_count > 1:", source)
        self.assertIn("if dvd_start_count != 1:", source)
        self.assertIn("scan_two_stage_dvd_serial(", source)
        self.assertNotIn("initial_serial.read_bytes()[-400_000:]", source)

    def test_qemu_args_protect_second_boot_from_dvd_reinstallation(self):
        with tempfile.TemporaryDirectory() as d:
            first, second = VM.build_two_stage_qemu_args(
                synthetic_args(d), pathlib.Path(d) / "stage1-serial.log",
            )
        self.assertIn("-no-reboot", first)
        self.assertNotIn("-no-reboot", second)
        self.assertEqual(first[first.index("-boot") + 1], "order=d")
        self.assertEqual(second[second.index("-boot") + 1], "order=c")
        self.assertEqual(first[first.index("-monitor") + 1], "none")
        self.assertEqual(second[second.index("-monitor") + 1], "none")
        self.assertIn("/tmp/derived.iso", " ".join(first))
        self.assertNotIn("/tmp/derived.iso", " ".join(second))
        self.assertNotIn("verified_iso", " ".join(second))
        self.assertNotIn("ide-cd,", " ".join(second))
        self.assertIn("only_windows", " ".join(second))
        self.assertIn("autounattend.img", " ".join(second))
        self.assertNotEqual(first[first.index("-serial") + 1],
                            second[second.index("-serial") + 1])


    def test_win11_immediate_poweroff_reuses_previously_proven_control(self):
        win11 = VM.witness_powershell("win11_26h2_en_us_x64", "26300")
        win10 = VM.witness_powershell("win10_22h2_en_us_x64", "19045")
        self.assertIn('& "$env:WINDIR\\System32\\shutdown.exe" /p /f', win11)
        self.assertIn('& "$env:WINDIR\\System32\\shutdown.exe" /s /f /t 0', win10)
        self.assertNotIn('shutdown.exe" /r', win11)

    def test_second_windows_boot_manager_is_rejected_even_with_full_proof(self):
        class ExitQemu:
            def poll(self):
                return 0
            def kill(self):
                raise AssertionError("already stopped")
            def wait(self, timeout):
                return 0
        boot = b'BdsDxe: starting Boot0003 "Windows Boot Manager"\\r\\n'
        proof = b"\\n".join([
            b"GASLUX_WINDOWS_X64_BOOT_BUILD=26300",
            b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
            b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
            b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
            b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
            b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64",
        ]) + b"\\n"
        with tempfile.TemporaryDirectory() as tmp:
            serial = pathlib.Path(tmp) / "serial.log"
            serial.write_bytes(boot + proof + boot)
            with patch.object(VM.subprocess, "Popen", return_value=ExitQemu()):
                ok, why = VM.boot_vm(["qemu-system-x86_64"], serial, 30,
                                      "win11_26h2_en_us_x64",
                                      reject_repeated_dvd_boot=True)
            self.assertFalse(ok)
            self.assertIn("rebooted after first-logon", why)

    def test_incremental_windows_boot_manager_detection_spans_400k(self):
        signature = b'BdsDxe: starting Boot0AF3 "Windows Boot Manager"'
        with tempfile.TemporaryDirectory() as tmp:
            serial = pathlib.Path(tmp) / "serial.log"
            serial.write_bytes(signature[:25])
            n, off, carry, _ = VM.scan_two_stage_dvd_serial(
                serial, 0, b"", VM.WINDOWS_BOOT_MANAGER_START)
            self.assertEqual(n, 0)
            with serial.open("ab") as stream:
                stream.write(signature[25:] + b"x" * 500_000 + signature)
            hits, off, carry, _ = VM.scan_two_stage_dvd_serial(
                serial, off, carry, VM.WINDOWS_BOOT_MANAGER_START)
            self.assertEqual(hits, 2)


    def test_acpi_monitor_rejects_fake_socket_before_any_guest_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "windows11-acpi-hmp.sock"
            path.write_bytes(b"NOT A SOCKET")
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(VM.LabError, "unowned Windows guest ACPI"):
                    VM.request_owned_windows_acpi_powerdown(path)

    def test_acpi_power_button_only_after_full_windows11_firstlogon_proof(self):
        class Qemu:
            finished = False
            def poll(self): return 0 if self.finished else None
            def kill(self): raise AssertionError("ACPI poweroff must not kill QEMU")
            def wait(self, timeout): return 0
        guest = Qemu()
        witness = b"\n".join([
            b'BdsDxe: starting Boot0003 "Windows Boot Manager"',
            b"GASLUX_WINDOWS_X64_BOOT_BUILD=26300",
            b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
            b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
            b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
            b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
            b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64",
        ]) + b"\n"
        sent = []
        def approve(sock):
            sent.append(sock)
            guest.finished = True
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "serial.log"
            path.write_bytes(witness)
            sock = pathlib.Path(tmp) / "fake.sock"
            with patch.object(VM.subprocess, "Popen", return_value=guest), \
                 patch.object(VM, "request_owned_windows_acpi_powerdown", side_effect=approve), \
                 patch.object(VM.time, "sleep", return_value=None):
                good, detail = VM.boot_vm(
                    ["qemu-system-x86_64"], path, 50, "win11_26h2_en_us_x64",
                    reject_repeated_dvd_boot=True, acpi_powerdown_socket=sock)
            self.assertTrue(good, detail)
            self.assertEqual(sent, [sock])

    def test_guest_without_full_audit_never_receives_acpi_power_button(self):
        class ExitedQemu:
            def poll(self): return 0
            def kill(self): raise AssertionError("already stopped")
            def wait(self, timeout): return 0
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "serial.log"
            path.write_bytes(b'BdsDxe: starting Boot0003 "Windows Boot Manager"\n')
            with patch.object(VM.subprocess, "Popen", return_value=ExitedQemu()), \
                 patch.object(VM, "request_owned_windows_acpi_powerdown") as ask:
                good, detail = VM.boot_vm(
                    ["qemu-system-x86_64"], path, 50, "win11_26h2_en_us_x64",
                    reject_repeated_dvd_boot=True,
                    acpi_powerdown_socket=pathlib.Path(tmp) / "fake.sock")
                ask.assert_not_called()
            self.assertFalse(good)
            self.assertIn("before installed Windows", detail)

    def test_guest_reboot_after_acpi_still_denied(self):
        class Qemu:
            finished = False
            def poll(self): return 0 if self.finished else None
            def kill(self): raise AssertionError("already stopped")
            def wait(self, timeout): return 0
        guest = Qemu()
        boot = b'BdsDxe: starting Boot0003 "Windows Boot Manager"\n'
        witness = b"\n".join([
            b"GASLUX_WINDOWS_X64_BOOT_BUILD=26300",
            b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
            b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
            b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
            b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
            b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64",
        ]) + b"\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "serial.log"
            path.write_bytes(boot + witness)
            def reboot(_):
                with path.open("ab") as log:
                    log.write(boot)
                guest.finished = True
            with patch.object(VM.subprocess, "Popen", return_value=guest), \
                 patch.object(VM, "request_owned_windows_acpi_powerdown", side_effect=reboot), \
                 patch.object(VM.time, "sleep", return_value=None):
                good, detail = VM.boot_vm(
                    ["qemu-system-x86_64"], path, 50, "win11_26h2_en_us_x64",
                    reject_repeated_dvd_boot=True,
                    acpi_powerdown_socket=pathlib.Path(tmp) / "fake.sock")
            self.assertFalse(good)
            self.assertIn("rebooted after first-logon", detail)


    def test_one_delayed_guest_acpi_retry_then_real_clean_exit(self):
        class PendingQemu:
            clean = False
            def poll(self): return 0 if self.clean else None
            def kill(self): raise AssertionError("no host kill for ACPI success")
            def wait(self, timeout): return 0
        guest = PendingQemu()
        proof = b"\n".join([
            b'BdsDxe: starting Boot0003 "Windows Boot Manager"',
            b"GASLUX_WINDOWS_X64_BOOT_BUILD=26300",
            b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
            b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
            b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
            b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
            b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64",
        ]) + b"\n"
        events = []
        clock = {"t": 0.0}
        def advance(_):
            clock["t"] += 65.0
        def press(sock):
            events.append(sock)
            if len(events) == 2:
                guest.clean = True
        with tempfile.TemporaryDirectory() as tmp:
            transcript = pathlib.Path(tmp)/"com1.log"
            transcript.write_bytes(proof)
            socket = pathlib.Path(tmp)/"socket"
            with patch.object(VM.subprocess, "Popen", return_value=guest), \
                 patch.object(VM, "request_owned_windows_acpi_powerdown",
                              side_effect=press), \
                 patch.object(VM.time, "monotonic",
                              side_effect=lambda: clock["t"]), \
                 patch.object(VM.time, "sleep", side_effect=advance):
                success, reason = VM.boot_vm(
                    ["qemu-system-x86_64"], transcript, 800,
                    "win11_26h2_en_us_x64",
                    reject_repeated_dvd_boot=True, acpi_powerdown_socket=socket)
        self.assertTrue(success, reason)
        self.assertEqual(events, [socket, socket])

    def test_two_ignored_guest_acpi_requests_never_establish_boot(self):
        class HungQemu:
            killed = False
            def poll(self): return -9 if self.killed else None
            def kill(self): self.killed = True
            def wait(self, timeout): return -9
        guest = HungQemu()
        proof = b"\n".join([
            b'BdsDxe: starting Boot0003 "Windows Boot Manager"',
            b"GASLUX_WINDOWS_X64_BOOT_BUILD=26300",
            b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
            b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
            b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
            b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
            b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
            b"GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT=win11_26h2_en_us_x64",
        ]) + b"\n"
        events = []
        clock = {"t": 0.0}
        def advance(_): clock["t"] += 125.0
        with tempfile.TemporaryDirectory() as tmp:
            transcript = pathlib.Path(tmp)/"com1.log"
            transcript.write_bytes(proof)
            socket = pathlib.Path(tmp)/"socket"
            with patch.object(VM.subprocess, "Popen", return_value=guest), \
                 patch.object(VM, "request_owned_windows_acpi_powerdown",
                              side_effect=lambda arg: events.append(arg)), \
                 patch.object(VM.time, "monotonic",
                              side_effect=lambda: clock["t"]), \
                 patch.object(VM.time, "sleep", side_effect=advance):
                success, reason = VM.boot_vm(
                    ["qemu-system-x86_64"], transcript, 800,
                    "win11_26h2_en_us_x64",
                    reject_repeated_dvd_boot=True, acpi_powerdown_socket=socket)
        self.assertFalse(success)
        self.assertIn("ignored two bounded", reason)
        self.assertTrue(guest.killed)
        self.assertEqual(events, [socket, socket])

    def test_duplicate_iso_device_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            args = synthetic_args(d)
            args.extend(["-device", "ide-cd,drive=verified_iso,bus=lab_sata.1"])
            with self.assertRaisesRegex(VM.LabError, "ambiguous"):
                VM.build_two_stage_qemu_args(args, pathlib.Path(d) / "before.log")

    def test_missing_iso_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            args = synthetic_args(d)
            pos = args.index("if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file=/tmp/derived.iso") - 1
            del args[pos:pos + 2]
            with self.assertRaises(VM.LabError):
                VM.build_two_stage_qemu_args(args, pathlib.Path(d) / "before.log")

    def test_unexpected_qemu_configuration_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            args = synthetic_args(d)
            args.extend(["-boot", "order=d"])
            with self.assertRaisesRegex(VM.LabError, "ambiguous"):
                VM.build_two_stage_qemu_args(args, pathlib.Path(d) / "before.log")

    def assert_rejected_before_iso_download(self, args, env=None):
        with patch.dict(os.environ, env or {}, clear=True):
            result = subprocess.run(
                [sys.executable, str(SRC), "--profile",
                 "win10_22h2_en_us_x64", *args],
                capture_output=True, text=True, timeout=15,
                env=dict(os.environ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("two-stage Windows lab installation requires", result.stderr)

    def test_missing_separate_consent_rejected(self):
        self.assert_rejected_before_iso_download([
            "--two-stage-install-only", "--derived-no-prompt", "--accel", "kvm",
        ])

    def test_tcg_rejected_with_correct_consent(self):
        self.assert_rejected_before_iso_download(
            ["--two-stage-install-only", "--derived-no-prompt", "--accel", "tcg"],
            {"GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
             "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY"},
        )

    def test_original_iso_unchanged_mode_rejected_as_two_stage(self):
        self.assert_rejected_before_iso_download(
            ["--two-stage-install-only", "--accel", "kvm"],
            {"GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
             "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY"},
        )

    def test_probe_cannot_be_mistaken_for_full_two_stage_install(self):
        self.assert_rejected_before_iso_download(
            ["--two-stage-install-only", "--boot-probe-only",
             "--derived-no-prompt", "--accel", "kvm"],
            {"GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
             "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY"},
        )

    def test_real_guest_path_required_even_with_consent(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            disk = tmp / "mock.qcow2"
            disk.write_bytes(b"not-an-installed-OS")
            with patch.dict(
                os.environ,
                {
                    "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
                    "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
                    "RUNNER_ENVIRONMENT": "github-hosted",
                },
                clear=True,
            ):
                with self.assertRaisesRegex(VM.LabError, "unowned disk"):
                    VM.boot_two_stage_windows(
                        synthetic_args(d), disk, tmp / "win-guest-serial.log",
                        1000, "win10_22h2_en_us_x64",
                    )

    def test_early_second_guest_exit_reports_qemu_code_not_windows_boot(self):
        with tempfile.TemporaryDirectory() as d, patch.object(
            VM.subprocess, "Popen"
        ) as popen:
            popen.return_value.poll.return_value = 17
            ok, diagnostic = VM.boot_vm(
                ["qemu-system-x86_64"], pathlib.Path(d) / "second-serial.log",
                30, "win11_26h2_en_us_x64", monitor_socket=None,
            )
        self.assertFalse(ok)
        self.assertIn("QEMU exit code 17", diagnostic)
        self.assertIn("Windows still unverified", diagnostic)

    def test_second_stage_stderr_is_retained_without_any_guest_boot_claim(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn('("qemu-stderr.log", "second-qemu-stderr", 256_000)', source)
        self.assertIn('source.is_file() and not source.is_symlink()', source)
        self.assertIn('0 < source.stat().st_size <= max_bytes', source)
        self.assertIn('if not ok:\n                raise LabError(diagnostic)', source)

    def test_fake_firmware_markers_not_a_real_firstboot(self):
        code = SRC.read_text()
        self.assertIn("return boot_vm(", code)
        self.assertIn("second, final_serial, remaining, profile_key,", code)
        self.assertIn('first.append("-no-reboot")', code)
        self.assertIn('all("verified_iso" not in arg for arg in second)', code)
        self.assertIn("windowsClientBootVerified", code)
        self.assertIn("winReAndBcdRecovered", code)


if __name__ == "__main__":
    unittest.main()
