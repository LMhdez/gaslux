"""No-prompt Windows ISO derivation is a disposable CI lab mechanism only.

The original independently SHA256-pinned Microsoft ISO remains immutable.
This suite never downloads Microsoft media, makes a VM, or writes a disk.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SRC = TOOLS / "windows_x64_tcg_firstboot.py"
spec = importlib.util.spec_from_file_location("gaslux_noprompt_test", SRC)
assert spec and spec.loader
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class NoPromptExperimentalMediaTests(unittest.TestCase):
    def test_probe_must_be_opted_in_to_derived_boot_media(self):
        program = subprocess.run(
            [sys.executable, str(SRC), "--profile", "win10_22h2_en_us_x64",
             "--boot-probe-only", "--fixture-only"],
            capture_output=True, text=True, timeout=12,
        )
        self.assertNotEqual(program.returncode, 0)
        self.assertIn("requires explicit lab-derived", program.stderr)

    def test_refuse_untrusted_host_and_missing_original(self):
        with tempfile.TemporaryDirectory() as p:
            root = Path(p)
            original = root / "not-a-real-official-iso.iso"
            derived = root / "derived.iso"
            with patch.dict(
                lab.os.environ,
                {"RUNNER_ENVIRONMENT": "self-hosted"},
                clear=True,
            ):
                with self.assertRaisesRegex(lab.LabError, "isolated hosted"):
                    lab.derive_no_prompt_uefi_lab_iso(original, derived, root)
            self.assertFalse(derived.exists())

    def test_derived_boot_media_must_not_overwrite_official_iso(self):
        src = SRC.read_text()
        self.assertIn('boot_iso = iso', src)
        self.assertIn('boot_iso = derived', src)
        self.assertIn('report["labDerivedIsoSha256"] = derived_sha256', src)
        self.assertIn('report["officialIsoUnmodified"] = True', src)
        self.assertIn('no-prompt derived ISO permitted only in isolated hosted KVM', src)
        self.assertIn('not derived.exists() and not derived.is_symlink()', src)

    def test_guest_boot_observation_does_not_certify_windows_installed(self):
        src = SRC.read_text()
        self.assertIn('report["windowsClientBootVerified"] = False', src)
        self.assertIn('report["labNoPromptDvdBootProbePassed"] = ok', src)
        self.assertIn('b"BdsDxe: failed to start Boot0001"', src)
        self.assertNotIn('report["stable"] = True', src)

    def test_empty_iso_probe_refuses_reused_serial(self):
        with tempfile.TemporaryDirectory() as p:
            serial = Path(p) / "serial.log"
            serial.write_bytes(b"fabricated evidence")
            with self.assertRaisesRegex(lab.LabError, "reused"):
                lab.probe_no_prompt_uefi_dvd(
                    ["qemu-system-x86_64"], serial
                )


if __name__ == "__main__":
    unittest.main()
