from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from cachyos_configure_installed import (
    InstalledConfigurationError, RUN_ID, configure, validate_profile,
)


class CachyOSInstalledConfigurationContractTests(unittest.TestCase):
    def make_root(self, root: Path, run_id: str = "gaslux-cachyos-test-20261119") -> None:
        for relative, content in {
            "etc/os-release": "NAME=CachyOS\nID=cachyos\nID_LIKE=arch\n",
            ".gaslux-lab-root-owner": run_id + "\n",
            "etc/locale.gen": "#en_US.UTF-8 UTF-8\n",
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "etc/shadow": "root:*:1::::::\n",
            "var/lib/pacman/local/ALPM_DB_VERSION": "9\n",
            "boot/vmlinuz-linux-cachyos-lts": "kernel",
            "boot/initramfs-linux-cachyos-lts.img": "initramfs",
        }.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def test_valid_owned_cachyos_root_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.make_root(root)
            validate_profile(root, "gaslux-cachyos-test-20261119")

    def test_foreign_transaction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.make_root(root)
            with self.assertRaisesRegex(InstalledConfigurationError, "another transaction"):
                validate_profile(root, "gaslux-cachyos-other-20261119")

    def test_non_cachyos_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.make_root(root)
            (root / "etc/os-release").write_text("ID=arch\nID_LIKE=arch\n")
            with self.assertRaisesRegex(InstalledConfigurationError, "not a native CachyOS"):
                validate_profile(root, "gaslux-cachyos-test-20261119")

    def test_invalid_transaction_id_is_rejected(self) -> None:
        self.assertIsNone(RUN_ID.fullmatch("../foreign"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.make_root(root)
            with self.assertRaisesRegex(InstalledConfigurationError, "invalid lab transaction"):
                validate_profile(root, "../foreign")

    def test_symlinked_os_release_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.make_root(root)
            (root / "etc/os-release").unlink()
            (root / "etc/os-release").symlink_to("/etc/os-release")
            with self.assertRaisesRegex(InstalledConfigurationError, "missing, linked or escaped"):
                validate_profile(root, "gaslux-cachyos-test-20261119")


    def test_short_command_failure_reports_original_command_not_index_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.make_root(root)

            def runner(argv, **kwargs):
                if argv[:3] == ["openssl", "passwd", "-6"]:
                    return subprocess.CompletedProcess(
                        argv, 0, "$6$salt$" + "A" * 86, "")
                if argv[0] == "arch-chroot" and argv[-1] == "locale-gen":
                    return subprocess.CompletedProcess(
                        argv, 17, "", "locale database unavailable")
                if argv[0] == "arch-chroot" and argv[2] == "useradd":
                    (root / "home/gaslux-lab").mkdir(parents=True)
                    with (root / "etc/passwd").open("a") as stream:
                        stream.write("gaslux-lab:x:1000:1000::/home/gaslux-lab:/bin/bash\\n")
                elif argv[0] == "arch-chroot" and argv[2] == "usermod":
                    with (root / "etc/shadow").open("a") as stream:
                        stream.write("gaslux-lab:" + argv[4] + ":1::::::\\n")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with self.assertRaises(InstalledConfigurationError) as caught:
                configure(root, "gaslux-cachyos-test-20261119", runner=runner)
            self.assertIn("configuration command failed: locale-gen", str(caught.exception))
            self.assertIn("exit 17", str(caught.exception))
            self.assertIn("locale database unavailable", str(caught.exception))

    def test_configure_creates_lab_account_locale_timezone_and_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.make_root(root)
            calls: list[tuple[list[str], dict[str, object]]] = []

            def runner(argv, **kwargs):
                calls.append((list(argv), kwargs))
                if argv[:3] == ["openssl", "passwd", "-6"]:
                    return subprocess.CompletedProcess(argv, 0, "$6$salt$" + "A" * 86, "")
                if argv[0] == "arch-chroot" and argv[2] == "useradd":
                    (root / "home/gaslux-lab").mkdir(parents=True)
                    with (root / "etc/passwd").open("a") as stream:
                        stream.write("gaslux-lab:x:1000:1000::/home/gaslux-lab:/bin/bash\n")
                elif argv[0] == "arch-chroot" and argv[2] == "usermod":
                    with (root / "etc/shadow").open("a") as stream:
                        stream.write("gaslux-lab:" + argv[4] + ":1::::::\n")
                elif argv[0] == "arch-chroot" and argv[2] == "ln":
                    (root / "etc/localtime").symlink_to(argv[4])
                return subprocess.CompletedProcess(argv, 0, "", "")

            result = configure(root, "gaslux-cachyos-test-20261119", runner=runner)
            self.assertTrue(result["configured"])
            self.assertFalse(result["passwordPlaintextRetained"])
            self.assertFalse(result["productionReady"])
            self.assertFalse(any("grub-install" in argv or "efibootmgr" in argv
                                 for argv, _ in calls))
            self.assertEqual(result["user"], "gaslux-lab")
            self.assertEqual(result["desktop"], "KDE Plasma")
            self.assertEqual((root / "etc/hostname").read_text(), "gaslux-cachyos-lab\n")
            self.assertIn("en_US.UTF-8 UTF-8", (root / "etc/locale.gen").read_text())
            self.assertEqual((root / "etc/localtime").readlink().as_posix(),
                             "/usr/share/zoneinfo/UTC")
            self.assertTrue(any("systemctl" in argv and "enable" in argv
                                for argv, _ in calls))


if __name__ == "__main__":
    unittest.main()
