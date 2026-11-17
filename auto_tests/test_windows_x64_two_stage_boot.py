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


    def test_swtpm_lifecycle_refuses_foreign_workspace_without_touching_process(self):
        class FakeProcess:
            def poll(self):
                raise AssertionError("foreign TPM process must not be inspected")
        with tempfile.TemporaryDirectory() as d, patch.dict(
            os.environ,
            {"GITHUB_ACTIONS": "true",
             "RUNNER_ENVIRONMENT": "github-hosted",
             "RUNNER_OS": "Linux",
             "GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT":
             "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY"},
            clear=True,
        ):
            with self.assertRaisesRegex(VM.LabError, "TPM state not in owned"):
                VM.rearm_disposable_swtpm_after_guest_reboot(
                    FakeProcess(), pathlib.Path(d),
                )

    def test_second_stage_rearms_same_tpm_state_only_when_setup_reboot_proven(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn("before_disk_boot()  # Reconnect TPM 2.0", source)
        self.assertIn("tpm = rearm_disposable_swtpm_after_guest_reboot(", source)
        self.assertIn("tpm, workspace,", source)
        self.assertIn('"--tpmstate", f"dir={state_dir}"', source)
        self.assertIn('"--ctrl", f"type=unixio,path={sock}"', source)
        self.assertIn("state_dir = workspace / \"swtpm-state\"", source)
        self.assertIn("if sock.exists() or sock.is_symlink():", source)
        self.assertIn("sock.is_socket() and not sock.is_symlink()", source)
        self.assertIn("return boot_vm(", source)
        self.assertIn("windowsClientBootVerified", source)

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
