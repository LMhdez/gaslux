"""No-guest safety contracts for FAT12-vs-FAT32 WinPE response discovery.

No QEMU, Windows ISO, block device or private guest files are used by tests.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_winpe_answer_probe.py"
SPEC = importlib.util.spec_from_file_location("winpe_answer_probe_tests", SOURCE)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
NS = {"u": "urn:schemas-microsoft-com:unattend"}


class WindowsPEAnswerMediaTests(unittest.TestCase):
    def test_exact_windowspe_run_synchronous_marker_each_media(self):
        for mode in PROBE.MODES:
            with self.subTest(mode=mode):
                xml = PROBE.build_winpe_witness_xml(mode)
                root = ET.fromstring(xml)
                passes = root.findall("./u:settings", NS)
                setup = [c for x in passes
                         if x.attrib.get("pass") == "windowsPE"
                         for c in x.findall("u:component", NS)
                         if c.attrib.get("name") == "Microsoft-Windows-Setup"]
                self.assertEqual(len(setup), 1)
                cmds = setup[0].findall(
                    "u:RunSynchronous/u:RunSynchronousCommand", NS)
                self.assertEqual(len(cmds), 1)
                command = cmds[0]
                self.assertEqual(command.find("u:Order", NS).text, "1")
                self.assertEqual(command.find("u:WillReboot", NS).text, "Never")
                self.assertEqual(command.find("u:Path", NS).text,
                                 "cmd.exe /c echo GASLUX_WINPE_AUTOANSWER_ACTUALLY_CONSUMED=1>COM1")
                self.assertEqual(
                    setup[0].find("u:DiskConfiguration/u:Disk/u:WillWipeDisk", NS).text,
                    "true",
                )
                self.assertNotIn("dualBootVerified", xml.decode("utf-8"))

    def test_probe_persisted_only_as_vm_serial_never_release_state(self):
        source = SOURCE.read_text(encoding="utf-8")
        for expected in (
            '"windowsClientBootVerified": False',
            '"dualBootVerified": False',
            '"storageWritesAuthorized": False',
            'GASLUX_WINPE_ANSWER_A_B_NUMERIC=',
            'PROBE_SECONDS = 240',
            'require(result["fat12_floppy"]',
            'require(result["fat32_usb"]',
        ):
            self.assertIn(expected, source)
        for forbidden in ("shutil.rmtree('/dev", "sgdisk", "diskpart.exe",
                          "powershell.exe -File", "host-network", "mount -o rw"):
            self.assertNotIn(forbidden, source)

    def test_no_installed_disk_or_guest_network_attached_either_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for mode in PROBE.MODES:
                with self.subTest(mode=mode):
                    args = PROBE.build_no_target_qemu_args(
                        root / "lab-derived.iso", root / "answer.img",
                        root / "owned-ovmf-vars.fd", root / "guest-serial.log",
                        mode,
                    )
                    self.assertNotIn("ide-hd", " ".join(args))
                    self.assertNotIn("only_windows", " ".join(args))
                    self.assertNotIn("qcow2", " ".join(args))
                    self.assertNotIn("virtio", " ".join(args))
                    self.assertEqual(args[args.index("-net") + 1], "none")
                    self.assertEqual(args[args.index("-boot") + 1], "order=d")
                    self.assertEqual(args[args.index("-monitor") + 1], "none")
                    self.assertIn("-no-reboot", args)
                    if mode == "fat32_usb":
                        self.assertIn("usb-storage,drive=lab_unattend,bus=lab_usb.0", args)
                        self.assertIn(
                            "if=none,id=lab_unattend,format=raw,readonly=on,file="
                            + str(root / "answer.img"), args)
                    else:
                        self.assertIn("if=floppy,format=raw,readonly=on,file="
                                      + str(root / "answer.img"), args)

    def test_unexpected_media_rejected_before_qemu_or_disk_access(self):
        for value in ("", "linux", "WindowsHostDisk", "fat32-usb"):
            with self.subTest(media=value):
                with self.assertRaises(PROBE.LabError):
                    PROBE.build_winpe_witness_xml(value)
                with self.assertRaises(PROBE.LabError):
                    PROBE.build_no_target_qemu_args(
                        Path("/tmp/source.iso"), Path("/dev/sda"), Path("/tmp/vars"),
                        Path("/tmp/log"), value,
                    )

    def test_vm_is_never_allowed_to_use_a_physical_disk_target(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('all("only_windows" not in arg and "ide-hd" not in arg', source)
        self.assertIn('"qcow2" not in arg', source)
        self.assertIn("readonly=on,file=", source)
        self.assertIn('GASLUX_WINDOWS_WINPE_PROBE_CONSENT', source)
        self.assertIn('CI_CONSENT = "I_ACCEPT_DISPOSABLE_WINPE_NO_TARGET_DISK"', source)
        self.assertIn('validate_environment(root, "kvm")', source)

    def test_same_windows_10_profile_and_answer_label_in_both_controls(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('PROFILE = "win10_22h2_en_us_x64"', source)
        self.assertIn('BUILD = "19045"', source)
        self.assertIn('"-n", "GASLUXCI"', source)
        self.assertIn('"::/" + name', source)
        self.assertIn("source.read_bytes() == actual", source)


if __name__ == "__main__":
    unittest.main()
