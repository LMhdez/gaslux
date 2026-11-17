"""Real FAT32 readback regression for Windows two-stage answer media.

Creates only a sparse, temporary file-backed FAT32 USB image in an expressly
authorized GitHub-hosted runner. No Microsoft ISO, QEMU VM or host disk opened.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "windows_x64_tcg_firstboot.py"
spec = importlib.util.spec_from_file_location("gaslux_windows_usb_readback", SOURCE)
assert spec and spec.loader
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)

HOSTED_MEDIA_FIXTURE = (
    os.environ.get("GITHUB_ACTIONS") == "true"
    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    and os.environ.get("RUNNER_OS") == "Linux"
    and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
    and all(shutil.which(program) for program in ("mkfs.vfat", "mcopy", "mtype"))
)

XML = b'<?xml version="1.0"?><unattend>synthetic XML only</unattend>\n'
SCRIPT = b"# synthetic-only guest script; never executed\n"


@unittest.skipUnless(HOSTED_MEDIA_FIXTURE, "GitHub-hosted FAT32 media fixture only")
class WindowsAnswerUSBFAT32ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(
            prefix="gaslux-win-x64-", dir=os.environ["RUNNER_TEMP"]
        )
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name)
        self.assertEqual(self.workspace.stat().st_mode & 0o777, 0o700)
        self.image = self.workspace / "only-disposable-answer-usb.img"
        with self.image.open("xb") as stream:
            stream.truncate(64 * 1024**2)
        subprocess.run(
            ["mkfs.vfat", "-F", "32", "-n", "GASLUXCI", str(self.image)],
            check=True, stdout=subprocess.DEVNULL,
        )
        self._copy("Autounattend.xml", XML)
        self._copy("GASLUX.PS1", SCRIPT)

    def _copy(self, name: str, payload: bytes):
        source = self.workspace / ("source-" + name)
        source.write_bytes(payload)
        subprocess.run(
            ["mcopy", "-i", str(self.image), str(source), "::/" + name],
            check=True, stdout=subprocess.DEVNULL,
        )

    def test_real_fat32_media_readback_exact_bytes(self):
        vm.verify_owned_answer_usb_image(self.image, XML, SCRIPT)

    def test_real_generated_windows_10_and_11_unattend_payloads(self):
        # Exercise the actual lab-generated XML and Windows guest-script
        # bytes; no Windows guest or script execution is involved.
        for profile, build in (
            ("win10_22h2_en_us_x64", "19045"),
            ("win11_26h2_en_us_x64", "26300"),
        ):
            with self.subTest(profile=profile):
                xml = vm.generate_unattend(
                    profile, build, removable_answer=True,
                )
                script = (vm.witness_powershell(profile, build) + "\n").encode("utf-8")
                for filename, payload in (
                    ("Autounattend.xml", xml),
                    ("GASLUX.PS1", script),
                ):
                    source = self.workspace / ("real-generated-" + filename)
                    source.write_bytes(payload)
                    subprocess.run(
                        ["mcopy", "-o", "-i", str(self.image),
                         str(source), "::/" + filename],
                        check=True, stdout=subprocess.DEVNULL,
                    )
                vm.verify_owned_answer_usb_image(self.image, xml, script)

    def test_incorrect_xml_bytes_are_rejected(self):
        with self.assertRaisesRegex(vm.LabError, "Autounattend.xml"):
            vm.verify_owned_answer_usb_image(self.image, XML + b"extra", SCRIPT)

    def test_incorrect_guest_script_bytes_are_rejected(self):
        with self.assertRaisesRegex(vm.LabError, "GASLUX.PS1"):
            vm.verify_owned_answer_usb_image(self.image, XML, SCRIPT + b"change")

    def test_nonprivate_workspace_rejected_before_media_read(self):
        self.workspace.chmod(0o755)
        with self.assertRaisesRegex(vm.LabError, "unowned or malformed"):
            vm.verify_owned_answer_usb_image(self.image, XML, SCRIPT)

    def test_forged_image_basename_rejected(self):
        with self.assertRaisesRegex(vm.LabError, "unowned or malformed"):
            vm.verify_owned_answer_usb_image(
                self.workspace / "unrelated.raw", XML, SCRIPT
            )

    def test_symlinked_answer_image_rejected(self):
        link = self.workspace / "only-disposable-answer-usb.img"
        link.rename(self.workspace / "real-answer-usb.img")
        link.symlink_to(self.workspace / "real-answer-usb.img")
        with self.assertRaisesRegex(vm.LabError, "unowned or malformed"):
            vm.verify_owned_answer_usb_image(link, XML, SCRIPT)

    def test_truncated_image_rejected(self):
        with self.image.open("r+b") as stream:
            stream.truncate(4 * 1024**2)
        with self.assertRaisesRegex(vm.LabError, "unowned or malformed"):
            vm.verify_owned_answer_usb_image(self.image, XML, SCRIPT)


class WindowsAnswerUSBSourceContracts(unittest.TestCase):
    def test_media_readback_happens_before_qcow2_creation(self):
        source = SOURCE.read_text(encoding="utf-8")
        readback = source.index("verify_owned_answer_usb_image(\n                    answer, xml")
        target = source.index('disk = workspace / "only-disposable-windows-target.qcow2"')
        self.assertLess(readback, target)
        self.assertIn("if args.two_stage_install_only:", source[readback - 60:readback])
        self.assertIn("GASLUX_WINDOWS_ANSWER_USB_READBACK_VERIFIED=1", source)

    def test_media_reader_never_mounts_or_writes(self):
        source = SOURCE.read_text(encoding="utf-8")
        function = source.split("def verify_owned_answer_usb_image(", 1)[1].split(
            "\ndef witness_powershell(", 1
        )[0]
        self.assertIn('["mtype", "-i", str(image), "::/" + name]', function)
        for forbidden in ("mount(", "guestmount", "mkfs", '["mcopy"', "format(",
                          "open(\"wb", "subprocess.Popen("):
            self.assertNotIn(forbidden, function)

    def test_raw_host_device_is_not_a_valid_answer_image(self):
        with self.assertRaisesRegex(vm.LabError, "unowned or malformed"):
            vm.verify_owned_answer_usb_image(
                Path("/dev/sda"), XML, SCRIPT
            )


if __name__ == "__main__":
    unittest.main()
