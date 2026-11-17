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
        "-drive", f"if=none,id=lab_unattend,format=raw,readonly=on,file={tmp}/only-disposable-answer-usb.img",
        "-device", "usb-storage,drive=lab_unattend,bus=lab_usb.0",
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
        self.assertEqual(first[first.index("-monitor") + 1], f"unix:{d}/hmp.sock,server,nowait")
        self.assertEqual(second[second.index("-monitor") + 1], "none")
        self.assertIn("/tmp/derived.iso", " ".join(first))
        self.assertNotIn("/tmp/derived.iso", " ".join(second))
        self.assertNotIn("verified_iso", " ".join(second))
        self.assertNotIn("ide-cd,", " ".join(second))
        self.assertIn("only_windows", " ".join(second))
        self.assertIn("only-disposable-answer-usb.img", " ".join(second))
        self.assertIn("usb-storage,drive=lab_unattend,bus=lab_usb.0", " ".join(second))
        self.assertNotIn("if=floppy", " ".join(second))
        self.assertNotEqual(first[first.index("-serial") + 1],
                            second[second.index("-serial") + 1])

    def test_missing_or_writable_answer_usb_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            original = synthetic_args(d)
            ans = next(x for x in original if x.startswith(
                "if=none,id=lab_unattend,"))
            for replacement in (
                ans.replace("readonly=on,", ""),
                ans.replace("only-disposable-answer-usb.img", "foreign-usb.img"),
                ans.replace(str(pathlib.Path(d)), "/tmp/foreign-gaslux-vm"),
            ):
                with self.subTest(replacement=replacement):
                    modified = list(original)
                    modified[modified.index(ans)] = replacement
                    with self.assertRaisesRegex(VM.LabError, "read-only owned USB"):
                        VM.build_two_stage_qemu_args(
                            modified, pathlib.Path(d) / "first.log")
            modified = [x for x in original
                        if not x.startswith("usb-storage,drive=lab_unattend,")]
            with self.assertRaisesRegex(VM.LabError, "read-only owned USB"):
                VM.build_two_stage_qemu_args(
                    modified, pathlib.Path(d) / "first.log")

    def test_two_stage_removable_answer_has_unique_label_and_oobe_defaults(self):
        for profile, build in (("win10_22h2_en_us_x64", "19045"),
                               ("win11_26h2_en_us_x64", "26300")):
            with self.subTest(profile=profile):
                xml = VM.generate_unattend(
                    profile, build, removable_answer=True)
                VM.validate_oobe_answer_pass(xml)
                root = VM.ET.fromstring(xml)
                commands = [e.text for e in root.iter()
                            if e.tag.endswith("}CommandLine")]
                self.assertEqual(len(commands), 1)
                self.assertIn("Get-Volume -FileSystemLabel GASLUXCI",
                              commands[0])
                self.assertIn("$v.Count -ne 1", commands[0])
                self.assertIn("GASLUX.PS1", commands[0])
                self.assertNotIn("-File A:", commands[0])
                self.assertLess(len(commands[0]), 240)

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

    def test_original_iso_without_two_stage_consent_is_refused(self):
        self.assert_rejected_before_iso_download(
            ["--two-stage-install-only", "--official-original-iso",
             "--accel", "kvm"])

    def test_original_iso_cannot_combine_with_derived_media(self):
        with patch.dict(os.environ, {
            "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
            "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
        }, clear=True):
            proc = subprocess.run([
                sys.executable, str(SRC), "--profile", "win10_22h2_en_us_x64",
                "--two-stage-install-only", "--official-original-iso",
                "--derived-no-prompt", "--accel", "kvm",
            ], capture_output=True, text=True, timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("original Microsoft ISO requires exclusive", proc.stderr)

    def test_original_iso_forbidden_as_fixture_probe_or_one_shot(self):
        for args in (
            ["--fixture-only"],
            ["--one-shot-install-only"],
            ["--boot-probe-only"],
            [],
        ):
            with self.subTest(args=args):
                proc = subprocess.run([
                    sys.executable, str(SRC), "--profile",
                    "win10_22h2_en_us_x64",
                    "--official-original-iso", *args,
                ], capture_output=True, text=True, timeout=15)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(
                    "original Microsoft ISO requires exclusive", proc.stderr)

    def test_original_media_mode_still_requires_real_client_proof(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn(
            'GASLUX_WINDOWS_ORIGINAL_MICROSOFT_ISO_DIRECT_KVM=1', source)
        self.assertIn('report["labDerivedIsoOnly"] = False', source)
        self.assertIn('report["officialIsoUnmodified"] = True', source)
        self.assertIn("ok, diagnostic = boot_two_stage_windows(", source)
        self.assertIn('report["windowsClientBootVerified"] = ok', source)
        self.assertIn('if not ok:\\n                raise LabError(diagnostic)', source)
        self.assertIn('send_first_iso_boot_key(expected_monitor, hold_ms=6000)',
                      source)

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

    def test_initial_dvd_hmp_only_first_guest_with_full_ack(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn('expected_monitor = final_serial.parent / "initial-installer-hmp.sock"', source)
        self.assertIn('send_first_iso_boot_key(expected_monitor, hold_ms=6000)', source)
        self.assertIn('dvd_key_sent = True', source)
        self.assertIn("def until_prompt() -> bytes:", source)
        self.assertIn("QEMU HMP closed before acknowledging boot key", source)
        self.assertIn('if args is second:', source)
        self.assertIn('args[args.index("-monitor") + 1] = "none"', source)
        self.assertIn('first_stage_stalled = True', source)
        self.assertIn('diagnose_stalled_windows_stage(', source)
        self.assertNotIn('response = monitor.recv(8192)', source)

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
