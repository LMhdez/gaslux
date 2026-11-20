"""Safety contracts for authentic Pop ISO on genuine Windows child QCOW2.

No ISO/network access, QEMU, host disks, GPT writing or distinst execution.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent/"tools"))

from windows_x64_installed_gpt_ro_audit import DiskAuditError
from windows10_popos_official_iso_signed_lab import (
    LAB_CONSENT, validate_signed_release_identity,
    require_hosted_iso_lab,
)
from windows10_popos_genuine_live_same_cow_vm import (
    LIVE_CONSENT, live_probe_on_windows,
)
from windows_x64_tcg_firstboot import main as windows_lab_main


class RealPopGenuineWindowsLabGateTests(unittest.TestCase):
    def setUp(self):
        self.release = {
            "version": "24.04", "channel": "intel",
            "url": "https://iso.pop-os.org/24.04/amd64/intel/20/pop-os_24.04_amd64_intel_20.iso",
            "size": 2_955_067_392,
            "sha_sum": "a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c",
        }
        self.manifest = (
            self.release["sha_sum"]+"  *pop-os_24.04_amd64_intel_20.iso\n"
        ).encode("ascii")

    def test_upstream_signed_manifest_identity(self):
        url, sha, size = validate_signed_release_identity(
            self.release, self.manifest,
        )
        self.assertEqual(url, self.release["url"])
        self.assertEqual(sha, "a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c")
        self.assertEqual(size, 2_955_067_392)

    def test_refuse_other_validly_shaped_upstream_build_even_if_manifest_matches(self):
        new = dict(self.release)
        new["url"] = (
            "https://iso.pop-os.org/24.04/amd64/intel/21/"
            "pop-os_24.04_amd64_intel_21.iso"
        )
        new["sha_sum"] = "b" * 64
        new["size"] = 2_955_067_393
        validly_shaped_manifest = (new["sha_sum"] +
                                   "  *pop-os_24.04_amd64_intel_21.iso\\n").encode("ascii")
        with self.assertRaises(DiskAuditError):
            validate_signed_release_identity(new, validly_shaped_manifest)

    def test_forged_api_version_channel_origin_digest_and_size_refused(self):
        altered = {
            "version": "25.04",
            "channel": "nvidia",
            "url": "https://evil.example/download.iso",
            "sha_sum": "0x"+("f"*64),
            "size": 19_000_000_000,
        }
        for key, value in altered.items():
            with self.subTest(key=key):
                source = dict(self.release)
                source[key] = value
                with self.assertRaises(DiskAuditError):
                    validate_signed_release_identity(source, self.manifest)

    def test_signed_manifest_absent_wrong_duplicate_and_foreign_path_refused(self):
        manifest = self.manifest.decode("ascii")
        for bad in (
            b"",
            manifest.replace(self.release["sha_sum"],"b"*64).encode(),
            (manifest+manifest).encode(),
            manifest.replace("20.iso", "21.iso").encode(),
            manifest.replace("*pop-os", "*/traversal/pop-os").encode(),
            manifest.encode("ascii")+b"\xff",
        ):
            with self.subTest(bad=bad[:28]):
                with self.assertRaises((DiskAuditError, ValueError)):
                    validate_signed_release_identity(self.release, bad)

    def test_refuse_host_without_explicit_vm_consent_before_network(self):
        with patch.dict(os.environ, {"GASLUX_POP_WINDOWS_COW_LIVE_ISO_CONSENT": ""},
                        clear=True):
            with self.assertRaises(DiskAuditError):
                require_hosted_iso_lab(Path("/tmp"))

    def test_live_vm_rejects_unowned_qcow2_before_isos(self):
        with patch.dict(os.environ, {
            "GASLUX_POP_WINDOWS_COW_LIVE_CONSENT": LIVE_CONSENT,
            "GASLUX_POP_WINDOWS_COW_LIVE_ISO_CONSENT": LAB_CONSENT,
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "LMhdez/gaslux",
        }):
            with self.assertRaises(DiskAuditError):
                live_probe_on_windows(
                    Path("/tmp/foreign-base.qcow2"),
                    Path("/tmp/foreign-child.qcow2"),
                    Path("/tmp"), Path("/tmp/evidence"), {},
                    windows_postboot_serial_verified=True,
                )

    def test_live_vm_rejects_missing_windows_third_boot_before_network(self):
        with self.assertRaises(DiskAuditError):
            live_probe_on_windows(
                Path("/tmp/foreign-base.qcow2"),
                Path("/tmp/foreign-child.qcow2"),
                Path("/tmp"), Path("/tmp/evidence"), {},
                windows_postboot_serial_verified=False,
            )

    def test_new_cli_requires_third_boot_and_two_separate_consents(self):
        for flags in (
            ["--probe-pop-live-on-six-gpt"],
            ["--probe-pop-live-on-six-gpt",
             "--verify-pop-post-pair-windows-reboot"],
        ):
            with self.subTest(flags=flags), self.assertRaises(SystemExit):
                windows_lab_main(
                    ["--profile", "win10_22h2_en_us_x64", "--fixture-only"]+flags,
                )


if __name__ == "__main__":
    unittest.main()
