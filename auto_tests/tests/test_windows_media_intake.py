"""Negative and synthetic ISO fixtures; never authenticate mock data as Microsoft."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "tools/windows_media_intake.py"
SPEC = importlib.util.spec_from_file_location("gaslux_windows_media_intake", SOURCE)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def make_tiny_iso(path: Path) -> str:
    raw = bytearray(80 * 2048)
    off = 16 * 2048
    raw[off] = 1
    raw[off + 1:off + 6] = b"CD001"
    raw[off + 6] = 1
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class WindowsMediaIntakeTests(unittest.TestCase):
    def test_explicit_missing_media_blocks_guest(self):
        for product in mod.MEDIA:
            result = mod.intake(None, product)
            self.assertEqual(result["status"], "BLOCKED_MEDIA")
            self.assertFalse(result["file_verified"])
            self.assertFalse(result["guest_writer_admitted"])
            self.assertFalse(result["windows_guest_booted"])
            self.assertFalse(result["windows_license_verified"])
        with self.assertRaises(mod.MediaRefusal):
            mod.intake(None, "windows10-unofficial")

    def test_official_sha_pins_are_static_distinct_and_not_bypassable(self):
        self.assertEqual(mod.OFFICIAL_PAGE,
                         "https://www.microsoft.com/en-us/software-download/windows10ISO")
        self.assertEqual(set(mod.MEDIA), {
            "windows10-22h2-pt-pt-x64", "windows10-22h2-en-us-x64"})
        for sha, _ in mod.MEDIA.values():
            self.assertEqual(len(sha), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in sha))

    def test_readonly_iso_header_hash_and_rejection_of_spoofing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "sample.iso"
            sample_sha = make_tiny_iso(sample)
            actual = mod.inspect_file(sample, minimum=34816, maximum=128 * 2048)
            self.assertEqual(actual["sha256"], sample_sha)
            self.assertTrue(actual["iso9660_pvd_verified"])
            with self.assertRaisesRegex(mod.MediaRefusal, "size"):
                mod.inspect_file(sample)
            with self.assertRaisesRegex(mod.MediaRefusal, "published official"):
                with patch.object(mod, "inspect_file", return_value=actual):
                    mod.intake(sample, "windows10-22h2-pt-pt-x64")
            alias = root / "alias.iso"
            alias.symlink_to(sample)
            with self.assertRaisesRegex(mod.MediaRefusal, "symlinks"):
                mod.inspect_file(alias, minimum=34816, maximum=128 * 2048)
            sample.write_bytes(b"\0" * (80 * 2048))
            with self.assertRaisesRegex(mod.MediaRefusal, "descriptor"):
                mod.inspect_file(sample, minimum=34816, maximum=128 * 2048)
            with self.assertRaisesRegex(mod.MediaRefusal, "normalized"):
                mod.inspect_file(Path("sample.iso"))
            with self.assertRaisesRegex(mod.MediaRefusal, "Expected an ISO"):
                mod.inspect_file(root)

    def test_valid_published_hash_only_reports_bytes_not_windows_boot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake = root / "fake.iso"
            meta = {
                "size_bytes": 6 * 1024**3, "sha256": mod.MEDIA[
                    "windows10-22h2-pt-pt-x64"][0],
                "iso9660_pvd_verified": True,
            }
            with patch.object(mod, "inspect_file", return_value=meta):
                result = mod.intake(fake, "windows10-22h2-pt-pt-x64")
            self.assertEqual(result["status"], "PINNED_WINDOWS_ISO_BYTES_VERIFIED")
            self.assertTrue(result["official_pinned_hash_matched"])
            self.assertFalse(result["installer_executed"])
            self.assertFalse(result["windows_license_verified"])
            self.assertFalse(result["guest_writer_admitted"])
            self.assertFalse(result["windows_guest_booted"])
            self.assertFalse(result["dual_boot_verified"])
            self.assertFalse(result["windows_recovery_verified"])


if __name__ == "__main__":
    unittest.main()
