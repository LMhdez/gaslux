from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from cachyos_configure_installed import (
    InstalledConfigurationError, RUN_ID, validate_profile,
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


if __name__ == "__main__":
    unittest.main()
