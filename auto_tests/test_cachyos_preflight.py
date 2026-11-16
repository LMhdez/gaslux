"""Tests for the read-only CachyOS Archiso identification stage."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "assets/live/libertix-cachyos-preflight.py"
spec = importlib.util.spec_from_file_location("libertix_cachyos_preflight", MODULE_PATH)
assert spec and spec.loader
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class CachyosPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = self.root / "arch/x86_64/airootfs.sfs"
        self.image.parent.mkdir(parents=True)
        self.image.touch()

    @staticmethod
    def runner(os_release='NAME="CachyOS Linux"\nID=cachyos\nID_LIKE=arch\nIMAGE_ID=cachyos\nIMAGE_VERSION=2026.08.09\n', inventory=None, *, returncode=0):
        if inventory is None:
            inventory = ('-rw-r--r-- root/root 123 2026-01-01 squashfs-root/etc/pacman.conf\n'
                         '-rwxr-xr-x root/root 456 2026-01-01 squashfs-root/usr/bin/pacman\n')
        def run(argv, **kwargs):
            assert argv[0] == "unsquashfs"
            assert kwargs["check"] is False
            value = os_release if "-cat" in argv else inventory
            return subprocess.CompletedProcess(argv, returncode, value, "")
        return run

    def test_good_image_recognized_but_not_installable(self):
        value = preflight.inspect_cachyos_iso_root(self.root, runner=self.runner())
        self.assertEqual(value["distribution"], "cachyos")
        self.assertEqual(value["live_os_release_id"], "cachyos")
        self.assertEqual(value["live_os_release_id_like"], "arch")
        self.assertFalse(value["libertix_installation_supported"])
        self.assertFalse(value["mutates_storage"])

    def test_missing_archiso_image_rejected(self):
        self.image.unlink()
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner())

    def test_symlink_squashfs_rejected(self):
        self.image.unlink()
        original = self.root / "data"
        original.touch()
        self.image.symlink_to(original)
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner())

    def test_different_arch_distro_rejected(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner('ID=arch\nNAME="EndeavourOS"\n'))

    def test_generic_arch_live_cannot_impersonate_cachyos(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner('NAME="CachyOS"\nID=arch\n'))

    def test_cachyos_name_only_is_not_enough(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner('NAME="CachyOS Linux"\nID=cachyos\n'))

    def test_missing_cachyos_image_id_is_rejected(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner('NAME="CachyOS Linux"\nID=cachyos\nID_LIKE=arch\n'))

    def test_fake_image_id_is_rejected(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner('NAME="CachyOS Linux"\nID=cachyos\nID_LIKE=arch\nIMAGE_ID=other\n'))

    def test_pacman_required(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner(inventory="squashfs-root/etc/pacman.conf\n"))

    def test_unsquashfs_failure(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root, runner=self.runner(returncode=2))

    def test_os_release_parser_does_not_evaluate_shell(self):
        parsed = preflight.parse_os_release('ID=arch\nNAME="CachyOS"\nURL="$(touch /tmp/unsafe)"\n')
        self.assertEqual(parsed["URL"], "$(touch /tmp/unsafe)")

    def test_invalid_os_release_duplicate(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.parse_os_release("ID=arch\nID=ubuntu\n")

    def test_missing_root(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.inspect_cachyos_iso_root(self.root / "nope")


if __name__ == "__main__":
    unittest.main()
