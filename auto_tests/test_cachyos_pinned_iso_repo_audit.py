"""Tests for exact-source, read-only official CachyOS pacman security audit."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
FILE = HERE / "auto_tests/tools/cachyos_pinned_iso_repo_audit.py"
SPEC = importlib.util.spec_from_file_location("gaslux_iso_policy", FILE)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class PinnedIsoRepoAuditTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.w = Path(temp.name)
        self.iso = self.w / "cachyos.iso"
        self.iso.write_bytes(b"synthetic, NOT official ISO")
        self.pin = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        self.iso_root = self.w / "mounted"
        self.iso_root.mkdir()
        self.rootfs_image = self.iso_root / "arch/x86_64/airootfs.sfs"
        self.rootfs_image.parent.mkdir(parents=True)
        self.rootfs_image.write_bytes(b"synthetic, NOT rootfs")
        self.live = self.w / "live"
        (self.live / "etc").mkdir(parents=True)
        (self.live / "etc/pacman.conf").write_text(
            "[options]\nSigLevel = Required DatabaseOptional\n[core]\n", encoding="utf-8"
        )
        (self.live / "etc/os-release").write_text("ID=cachyos\nID_LIKE=arch\n", encoding="utf-8")
        self.commands = []

    def runner(self, argv, **kwargs):
        self.commands.append(tuple(argv))
        if argv[0] == "findmnt":
            is_iso = argv[3] == str(self.iso_root)
            mount = "/dev/loop1 iso9660 ro,nosuid" if is_iso else ("/dev/loop2 squashfs ro,nosuid")
            return subprocess.CompletedProcess(argv, 0, mount + "\n", "")
        if argv[0] == "losetup":
            backing = str(self.iso) if argv[-1] == "/dev/loop1" else str(self.rootfs_image)
            return subprocess.CompletedProcess(argv, 0, backing + "\n", "")
        if argv[0] == "chroot":
            return subprocess.CompletedProcess(argv, 0, "Required DatabaseOptional\n", "")
        raise AssertionError("unexpected command: " + repr(argv))

    def inspect(self, **params):
        values = {
            "iso": self.iso,
            "iso_root": self.iso_root,
            "live_root": self.live,
            "pinned_sha256": self.pin,
            "run": self.runner,
        }
        values.update(params)
        return AUDIT.audit(**values)

    def test_uses_actual_iso_pacman_conf_in_readonly_chroot(self):
        with patch.object(AUDIT._POLICY, "assess", side_effect=self.fake_guard):
            report = self.inspect()
        self.assertTrue(report["ok"])
        self.assertTrue(report["officialIsoSha256Verified"])
        self.assertTrue(report["readOnlySquashfsMountVerified"])
        self.assertTrue(report["actualIsoPacmanConfExecuted"])
        self.assertFalse(report["pacstrapExecuted"])
        self.assertFalse(report["installedCachyosBootVerified"])
        self.assertFalse(report["windowsDualBootVerified"])
        self.assertFalse(report["productionReady"])
        self.assertTrue(all(cmd[0] in {"findmnt", "losetup", "chroot"} for cmd in self.commands))
        self.assertTrue(any(cmd[0] == "chroot" for cmd in self.commands))

    def fake_guard(self, config, *, run):
        self.assertEqual(config, self.live / "etc/pacman.conf")
        response = run(
            ["pacman-conf", "--config", str(config), "SigLevel"],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        self.assertEqual(response.stdout.strip(), "Required DatabaseOptional")
        self.assertEqual(
            self.commands[-1][:4], ("chroot", str(self.live), "/usr/bin/pacman-conf", "--config")
        )
        return {"ok": True, "packageSignaturesMandatory": True}

    def test_wrong_iso_sha_rejected_before_any_mount_query(self):
        with self.assertRaisesRegex(AUDIT.AuditError, "SHA-256 mismatch"):
            self.inspect(pinned_sha256="0" * 64)
        self.assertEqual(self.commands, [])

    def test_invalid_sha_rejected(self):
        with self.assertRaisesRegex(AUDIT.AuditError, "pin is invalid"):
            self.inspect(pinned_sha256="../../")
        self.assertEqual(self.commands, [])

    def test_nonexistent_iso_refused(self):
        self.iso.unlink()
        with self.assertRaisesRegex(AUDIT.AuditError, "regular file"):
            self.inspect()

    def test_iso_symlink_refused(self):
        copy = self.w / "copy.iso"
        copy.write_bytes(self.iso.read_bytes())
        self.iso.unlink()
        self.iso.symlink_to(copy)
        with self.assertRaisesRegex(AUDIT.AuditError, "regular file"):
            self.inspect()

    def test_fake_live_os_rejected(self):
        (self.live / "etc/os-release").write_text("ID=debian\n")
        with self.assertRaisesRegex(AUDIT.AuditError, "not CachyOS"):
            self.inspect()

    def test_missing_pacman_config_rejected(self):
        (self.live / "etc/pacman.conf").unlink()
        with self.assertRaisesRegex(AUDIT.AuditError, "pacman.conf"):
            self.inspect()

    def test_missing_rootfs_image_rejected(self):
        self.rootfs_image.unlink()
        with self.assertRaisesRegex(AUDIT.AuditError, "rootfs"):
            self.inspect()

    def test_weak_repo_policy_rejected(self):
        def weak(_config, *, run):
            raise AUDIT._POLICY.PolicyError("repository cachyos: weak SigLevel")

        with (
            patch.object(AUDIT._POLICY, "assess", side_effect=weak),
            self.assertRaisesRegex(AUDIT.AuditError, "signature policy refused"),
        ):
            self.inspect()

    def test_writable_squashfs_mount_rejected(self):
        def writable(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if argv[0] == "findmnt" and argv[3] == str(self.live):
                return subprocess.CompletedProcess(argv, 0, "/dev/loop2 squashfs rw,nosuid\n", "")
            return result

        with self.assertRaisesRegex(AUDIT.AuditError, "read-only loop mount"):
            self.inspect(run=writable)

    def test_wrong_iso_loop_backing_rejected(self):
        def attacker(argv, **kwargs):
            if argv[0] == "losetup" and argv[-1] == "/dev/loop1":
                return subprocess.CompletedProcess(argv, 0, "/tmp/another.iso\n", "")
            return self.runner(argv, **kwargs)

        with self.assertRaisesRegex(AUDIT.AuditError, "loop backing"):
            self.inspect(run=attacker)

    def test_wrong_rootfs_loop_backing_rejected(self):
        def attacker(argv, **kwargs):
            if argv[0] == "losetup" and argv[-1] == "/dev/loop2":
                return subprocess.CompletedProcess(argv, 0, "/tmp/another.sfs\n", "")
            return self.runner(argv, **kwargs)

        with self.assertRaisesRegex(AUDIT.AuditError, "loop backing"):
            self.inspect(run=attacker)

    def test_no_file_write_or_network_setup_in_audit_source(self):
        text = FILE.read_text(encoding="utf-8")
        for forbidden in (
            "pacstrap(",
            "mkfs.",
            "parted ",
            "wipefs ",
            "--skippgpcheck",
            "SigLevel = Optional TrustAll",
            "efibootmgr ",
            "subprocess.Popen",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
