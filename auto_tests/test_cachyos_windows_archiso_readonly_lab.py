"""Issue #3: fail-closed read-only Windows COW / real Archiso integration guards.

These tests touch no disks, launch no QEMU guests and never invoke pacstrap.
"""
from __future__ import annotations
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "tools"))
import cachyos_windows_archiso_signed_plan_lab as lab


class WindowsArchisoReadOnlyContracts(unittest.TestCase):
    def test_missing_consent_refused_before_filesystem_or_subprocess(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(lab, "read_windows_file_hashes") as hashes, \
             patch.object(lab.subprocess, "run") as subprocess_run:
            with self.assertRaisesRegex(lab.ReadonlyLabError, "consent"):
                lab.prepare(
                    Path("/tmp/not-a-cow.qcow2"), Path("/tmp/not-signer"),
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222",
                    lab.ISO_SHA256, True,
                )
            hashes.assert_not_called()
            subprocess_run.assert_not_called()

    def test_no_windows_fourth_boot_never_authorizes_handoff(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "LMhdez/gaslux",
            "GASLUX_CACHYOS_ARCHISO_READONLY_CONSENT":
                "I_ACCEPT_PINNED_ARCHISO_READONLY_WINDOWS10_QCOW2_COW",
        }
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(lab, "read_windows_file_hashes") as hashes, \
             patch.object(lab.subprocess, "run") as subprocess_run:
            with self.assertRaisesRegex(lab.ReadonlyLabError, "fourth boot"):
                lab.prepare(
                    Path("/tmp/not-a-cow.qcow2"), Path("/tmp/not-signer"),
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222",
                    lab.ISO_SHA256, False,
                )
            hashes.assert_not_called()
            subprocess_run.assert_not_called()

    def test_wrong_cachyos_image_hash_never_authorizes_handoff(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "LMhdez/gaslux",
            "GASLUX_CACHYOS_ARCHISO_READONLY_CONSENT":
                "I_ACCEPT_PINNED_ARCHISO_READONLY_WINDOWS10_QCOW2_COW",
        }
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(lab, "read_windows_file_hashes") as hashes:
            with self.assertRaisesRegex(lab.ReadonlyLabError, "official ISO"):
                lab.prepare(
                    Path("/tmp/not-a-cow.qcow2"), Path("/tmp/not-signer"),
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222",
                    "0" * 64, True,
                )
            hashes.assert_not_called()

    def test_guest_and_host_do_not_install_or_format_windows_disk(self):
        host = (HERE / "tools/cachyos_windows_archiso_readonly_host.sh").read_text()
        guest = (HERE / "tools/cachyos_windows_archiso_live_guest_readonly.sh").read_text()
        module = (HERE / "tools/cachyos_windows_archiso_signed_plan_lab.py").read_text()
        entry = (HERE / "tools/windows_x64_tcg_firstboot.py").read_text()
        assert 'readonly=on' in host
        assert 'id=windows_cow,format=qcow2,file="$cow",readonly=on' in host
        assert '"windowsBootAfterExt4Verified"' in entry
        assert '"windowsBcdWinreEspAfterExt4Verified"' in entry
        assert "windows_fourth_verified is True" in module
        assert 'readonly=1' in module
        assert '"writeAuthority": False' in module
        assert 'inspect_bound_gpt_windows(front, back, plan)' in module
        assert "GASLUX_WIN10_ARCHISO_READONLY_PASS:" in guest
        for forbidden in ("sgdisk --clear", "pacstrap -K",
                          "grub-install", "efibootmgr -c"):
            self.assertNotIn(forbidden, host)
            self.assertNotIn(forbidden, guest)
            self.assertNotIn(forbidden, module)
        self.assertIn('mkfs.ext4 -q -F -U "$iso_uuid" "$w/iso.raw"', host)
        self.assertNotIn('mkfs.ext4 "$cow"', host)


if __name__ == "__main__":
    unittest.main()
