"""Offline private media transport adversarial cases."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_windows_media_preflight as media

URL = "https://media.example.org/windows.iso?token=private"
HOST = "media.example.org"
DATA = b"known media bytes"
SHA = hashlib.sha256(DATA).hexdigest()


class FakeResponse(io.BytesIO):
    status = 200
    headers = {}

    def geturl(self):
        return URL


class MediaTests(unittest.TestCase):
    def test_config(self):
        self.assertEqual(media.validate_config(URL, HOST, SHA, str(len(DATA)), "receipt"), len(DATA))
        for url in ("http://media.example.org/a", "https://other.example.org/a",
                    "https://user@media.example.org/a", URL + "#fragment",
                    "https://media.example.org:444/a", URL + "\n"):
            with self.assertRaises(ValueError):
                media.validate_config(url, HOST, SHA, str(len(DATA)), "receipt")

    def test_config_missing_or_invalid(self):
        for host, digest, size, receipt in [
            ("", SHA, "1", "receipt"), (HOST, "", "1", "receipt"),
            (HOST, SHA, "0", "receipt"), (HOST, SHA, "99999999999", "receipt"),
            (HOST, SHA, "1", "")]:
            with self.assertRaises(ValueError):
                media.validate_config(URL, host, digest, size, receipt)

    def test_redirect_refused(self):
        with self.assertRaises(ValueError):
            media.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example.org")

    def test_real_budget_math(self):
        result = media.capacity(100 * media.GIB, 6 * media.GIB)
        self.assertEqual(result["planned_lab_bytes"], 82 * media.GIB + media.MINT_BYTES)
        self.assertTrue(result["compact_lab_capacity_ready"])
        self.assertFalse(media.capacity(80 * media.GIB, 6 * media.GIB)["compact_lab_capacity_ready"])
        self.assertFalse(media.capacity(100 * media.GIB, 10 * media.GIB)["compact_lab_capacity_ready"])

    def test_verified_bytes_cleanup(self):
        with tempfile.TemporaryDirectory() as parent:
            with patch.object(media.urllib.request, "build_opener") as mock:
                mock.return_value.open.return_value = FakeResponse(DATA)
                self.assertEqual(media.download_verified(URL, SHA, len(DATA), parent), len(DATA))
            self.assertEqual(list(Path(parent).iterdir()), [])

    def test_bad_hash_short_and_oversized_cleanup(self):
        for data, digest in [(DATA, "0" * 64), (DATA[:-1], SHA), (DATA + b"x", SHA)]:
            with tempfile.TemporaryDirectory() as parent:
                with patch.object(media.urllib.request, "build_opener") as mock:
                    mock.return_value.open.return_value = FakeResponse(data)
                    with self.assertRaises(ValueError):
                        media.download_verified(URL, digest, len(DATA), parent)
                self.assertEqual(list(Path(parent).iterdir()), [])

    def test_no_secrets_fail_closed(self):
        report = media.preflight({})
        self.assertEqual(report["status"], "blocked")
        for key in ("windows_media_authorized", "windows_media_sha256_verified",
                    "virtual_disk_writer_authorized", "release_eligible"):
            self.assertFalse(report[key])


if __name__ == "__main__":
    unittest.main()
