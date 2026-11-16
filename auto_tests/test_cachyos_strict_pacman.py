"""Strict offline pacman configuration; no real guest, network or disk writes."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "assets/live/cachyos-strict-pacman.py"
SPEC = importlib.util.spec_from_file_location("gaslux_strict_pacman", FILE)
assert SPEC and SPEC.loader
STRICT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STRICT)

RUN_ID = "cachyos-strict-vm-260809"
ARCH = """
# Arch mirrors
Server = http://unused.invalid/arch/$repo/$arch
Server = https://arch.example.org/$repo/os/$arch
Server = https://arch.example.org/$repo/os/$arch
"""
CACHY = """
Server = https://cachy.example.org/repo/$arch/$repo
Server = ftp://not-used.invalid/repo/$repo
"""


class StrictPacmanConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "etc/pacman.d").mkdir(parents=True)
        (self.root / "etc/os-release").write_text(
            'ID=cachyos\nID_LIKE=arch\nIMAGE_ID=cachyos\nIMAGE_VERSION=2026.08.09\n'
        )
        (self.root / "etc/pacman.conf").write_text(
            "[options]\nSigLevel = Optional TrustAll\n[cachyos]\nSigLevel = Optional TrustAll\n"
        )
        (self.root / "etc/pacman.d/mirrorlist").write_text(ARCH)
        (self.root / "etc/pacman.d/cachyos-mirrorlist").write_text(CACHY)

    def render(self, **kwargs):
        return STRICT.render(kwargs.get("root", self.root), kwargs.get("run_id", RUN_ID))

    def test_weak_live_configuration_never_inherited(self):
        report = self.render()
        self.assertFalse(report["sourceLivePolicyTrusted"])
        self.assertTrue(report["packageSignaturesMandatory"])
        self.assertFalse(report["windowsInstallerStable"])
        self.assertFalse(report["installedBootVerified"])
        self.assertFalse(report["pacstrapExecuted"])
        self.assertEqual(report["generatedFromPinnedProfile"], "cachyos-260809")
        for label in ("installerConfig", "installedTargetConfig"):
            value = report[label]
            self.assertIn("SigLevel = Required DatabaseOptional TrustedOnly", value)
            self.assertIn("LocalFileSigLevel = Required TrustedOnly", value)
            self.assertNotIn("Optional TrustAll", value)
            self.assertNotIn("PackageNever", value)
            self.assertEqual(value.count("\n[core]\n"), 1)
            self.assertEqual(value.count("\n[extra]\n"), 1)
            self.assertEqual(value.count("\n[cachyos]\n"), 1)
            self.assertNotIn("\n[multilib]\n", value)
        self.assertIn("/run/gaslux-pacman-" + RUN_ID, report["installerConfig"])
        self.assertIn("/etc/pacman.d/mirrorlist", report["installedTargetConfig"])
        self.assertNotIn("/run/", report["installedTargetConfig"])

    def test_non_https_mirrors_removed_and_order_preserved(self):
        report = self.render()
        self.assertEqual(report["mirrorlist"], "Server = https://arch.example.org/$repo/os/$arch\n")
        self.assertEqual(report["cachyos-mirrorlist"],
                         "Server = https://cachy.example.org/repo/$arch/$repo\n")

    def test_run_id_injection_denied(self):
        for value in ("../x", "bad;reboot", "short", "", "/dev/sda", "a" * 101):
            with self.subTest(value=value), self.assertRaisesRegex(
                STRICT.StrictConfigError, "transaction identifier"
            ):
                self.render(run_id=value)

    def test_original_pacman_config_must_exist_but_is_never_copied(self):
        (self.root / "etc/pacman.conf").unlink()
        with self.assertRaisesRegex(STRICT.StrictConfigError, "untrusted source"):
            self.render()

    def test_unknown_os_and_wrong_release_rejected(self):
        (self.root / "etc/os-release").write_text("ID=cachyos\nIMAGE_ID=cachyos\n")
        with self.assertRaisesRegex(STRICT.StrictConfigError, "unsupported"):
            self.render()

    def test_missing_signed_repo_mirror_rejected(self):
        (self.root / "etc/pacman.d/cachyos-mirrorlist").unlink()
        with self.assertRaisesRegex(STRICT.StrictConfigError, "untrusted source"):
            self.render()

    def test_symlink_mirrorlist_rejected(self):
        mirror = self.root / "etc/pacman.d/mirrorlist"
        mirror.unlink()
        mirror.symlink_to("/etc/passwd")
        with self.assertRaisesRegex(STRICT.StrictConfigError, "untrusted source"):
            self.render()

    def test_weak_http_only_mirrors_rejected(self):
        (self.root / "etc/pacman.d/mirrorlist").write_text(
            "Server = http://unverified.invalid/$repo/os/$arch\n"
        )
        with self.assertRaisesRegex(STRICT.StrictConfigError, "no usable"):
            self.render()

    def test_shell_injected_server_is_rejected(self):
        for payload in (
            "Server = https://safe.example/';reboot",
            "Server = https://safe.example/$(evil)",
            "Server = https://a.example/repo?from=evil",
            "Server = https://a.example/repo#fragment",
            "Server = https://user:password@a.example/repo",
            "Server = ssh://mirror.example/repo",
            "Include = /etc/passwd",
        ):
            with self.subTest(payload=payload):
                (self.root / "etc/pacman.d/mirrorlist").write_text(payload + "\n")
                with self.assertRaises(STRICT.StrictConfigError):
                    self.render()

    def test_bad_port_refused(self):
        with self.assertRaisesRegex(STRICT.StrictConfigError, "invalid mirror port"):
            STRICT.require_https("https://arch.example.org:notaport/repo")

    def test_canonical_root_required(self):
        other = self.root.parent / (self.root.name + "-link")
        other.symlink_to(self.root)
        self.addCleanup(other.unlink)
        with self.assertRaisesRegex(STRICT.StrictConfigError, "canonical"):
            self.render(root=other)

    def test_config_path_injection_refused(self):
        for candidate in ("/run/../../etc", "/run/gaslux-pacman-abc;reboot", "/tmp"):
            with self.assertRaises(STRICT.StrictConfigError):
                STRICT.config_for(candidate)

    def test_prepare_vm_refuses_without_disposable_vm(self):
        with (
            patch.object(STRICT.os, "geteuid", return_value=0),
            patch.dict("os.environ", {"GASLUX_DISPOSABLE_VM": ""}),
            self.assertRaisesRegex(STRICT.StrictConfigError, "consent"),
        ):
            STRICT.check_vm_environment()

    def test_prepare_vm_never_runs_on_unverified_hardware(self):
        with (
            patch.object(STRICT.os, "geteuid", return_value=0),
            patch.dict("os.environ", {"GASLUX_DISPOSABLE_VM": "I_ACCEPT_DISPOSABLE_VM_ONLY"}),
            patch.object(STRICT.subprocess, "run") as cmd,
            self.assertRaisesRegex(STRICT.StrictConfigError, "QEMU"),
        ):
            cmd.return_value.returncode = 0
            cmd.return_value.stdout = "none\n"
            STRICT.check_vm_environment()

    def test_no_disk_installation_ever_executed_by_renderer(self):
        text = FILE.read_text(encoding="utf-8")
        for token in ("pacstrap -K", "mkfs.ext4", "efibootmgr", "parted ", "wipefs "):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
