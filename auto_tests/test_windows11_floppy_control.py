"""Win11-only KVM FAT12 control: no guest/ISO downloaded during these tests.

Probes the known Windows10 baseline route on Win11 without relaxing disk-only,
first-logon, WinRE, BCD, TPM2 or clean poweroff acceptance contracts.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "auto_tests" / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_tcg_firstboot.py"
SPEC = importlib.util.spec_from_file_location("windows11_floppy_control", SOURCE)
assert SPEC and SPEC.loader
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)

PROFILE = "win11_26h2_en_us_x64"
NS = {"u": "urn:schemas-microsoft-com:unattend"}


def qemu_win11_args(directory: str) -> list[str]:
    return [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm,smm=on",
        "-monitor", "unix:" + directory + "/qemu-hmp.sock,server,nowait",
        "-drive", "if=none,id=only_windows,format=qcow2,file=" + directory + "/only-windows.qcow2",
        "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
        "-drive", "if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file=" + directory + "/derived.iso",
        "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
        "-drive", "if=floppy,format=raw,file=" + directory + "/unattend-floppy.img",
        "-chardev", "socket,id=chrtpm,path=" + directory + "/swtpm.sock",
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-tis,tpmdev=tpm0",
        "-serial", "file:" + directory + "/windows-installed.log",
        "-boot", "order=dc",
    ]


class Windows11FloppyBaselineControl(unittest.TestCase):
    def test_windows11_profile_is_known_and_pinned(self):
        profile = VM.load_catalog()["profiles"][PROFILE]
        self.assertEqual(profile["expectedWindowsBuildPrefix"], "26300")
        self.assertIn("sha256", str(profile).lower())
        self.assertIn(PROFILE, VM.EXPECTED)

    def test_win11_unattend_winre_and_oobe_pass_are_not_weakened(self):
        xml = VM.generate_unattend(PROFILE, "26300")
        VM.validate_oobe_answer_pass(xml)
        root = ET.fromstring(xml)
        self.assertEqual(
            [n.text for n in root.findall(".//u:CreatePartition/u:Type", NS)],
            ["EFI", "MSR", "Primary", "Primary"],
        )
        commands = [
            n.text for n in root.findall(
                ".//u:FirstLogonCommands/u:SynchronousCommand/u:CommandLine", NS
            )
        ]
        self.assertEqual(len(commands), 1)
        self.assertIn("A:\\GASLUX.PS1", commands[0])

    def test_stage2_has_same_owned_disk_floppy_and_tpm_but_no_dvd(self):
        with tempfile.TemporaryDirectory() as folder:
            original = qemu_win11_args(folder)
            first, second = VM.build_two_stage_qemu_args(
                original, Path(folder) / "initial-dvd-guest-serial.log",
            )
            self.assertIn("-no-reboot", first)
            self.assertNotIn("-no-reboot", second)
            self.assertEqual(first[first.index("-boot") + 1], "order=d")
            self.assertEqual(second[second.index("-boot") + 1], "order=c")
            for args in (first, second):
                self.assertIn("-tpmdev", args)
                self.assertIn("emulator,id=tpm0,chardev=chrtpm", args)
                self.assertIn("tpm-tis,tpmdev=tpm0", args)
                self.assertIn("if=floppy,format=raw,file=" + folder + "/unattend-floppy.img", args)
                self.assertIn("only-windows.qcow2", " ".join(args))
                self.assertEqual(args[args.index("-monitor") + 1], "none")
            self.assertIn("verified_iso", " ".join(first))
            self.assertNotIn("verified_iso", " ".join(second))
            self.assertNotIn("ide-cd,", " ".join(second))

    def test_exact_win11_native_power_shell_audit_keeps_all_proofs(self):
        audit = VM.witness_powershell(PROFILE, "26300")
        self.assertIn("$os.BuildNumber.StartsWith('26300')", audit)
        self.assertIn("Get-Disk -Number 0", audit)
        self.assertIn("bcdedit /enum", audit)
        self.assertIn("reagentc /info", audit)
        self.assertIn("GASLUX_WINDOWS_X64_WINRE_ENABLED=1", audit)
        self.assertIn("GASLUX_WINDOWS_X64_BCD_ENUMERATED=1", audit)
        self.assertIn("shutdown.exe", audit)
        self.assertNotIn("bcdedit /set", audit)

    def test_win11_2nd_guest_requires_original_tpm_nv_state(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            'profile_key != "win11_26h2_en_us_x64" or restart_tpm is not None',
            source,
        )
        self.assertIn("restart_owned_swtpm_for_second_guest(tpm, workspace)", source)
        self.assertIn('f"dir={state_dir}"', source)
        self.assertIn("state_dir.stat().st_uid == os.getuid()", source)

    def test_matrix_does_not_claim_win10_reverification(self):
        yaml = (ROOT / ".github/workflows/windows-x64-two-stage-firstboot.yml").read_text()
        self.assertIn("- win11_26h2_en_us_x64", yaml)
        actual_matrix = yaml.split("matrix:", 1)[1].split("\n    env:", 1)[0]
        self.assertNotIn("- win10_22h2_en_us_x64", actual_matrix)
        self.assertIn("--derived-no-prompt --two-stage-install-only", yaml)
        self.assertIn("retention-days: 7", yaml)


if __name__ == "__main__":
    unittest.main()
