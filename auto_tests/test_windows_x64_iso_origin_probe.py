"""Negative HTTP-origin tests; never make an actual external network request."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL_DIR = ROOT / "auto_tests/tools"
sys.path.insert(0, str(TOOL_DIR))
SOURCE = TOOL_DIR / "windows_x64_iso_origin_probe.py"
spec = importlib.util.spec_from_file_location("gaslux_win_iso_head", SOURCE)
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class OfficialOriginProbeContracts(unittest.TestCase):
    def test_two_official_profiles_exist_and_never_report_boot(self):
        catalog = probe.load_catalog()
        self.assertEqual(set(catalog["profiles"]), set(probe.EXPECTED))
        profile = catalog["profiles"]["win10_22h2_en_us_x64"]
        self.assertEqual(probe.validate_origin(profile["downloadUrl"],
                          probe.PERMITTED_START), "go.microsoft.com")

    def test_reject_fake_microsoft_lookalikes(self):
        bad = (
            "http://go.microsoft.com/fwlink/?LinkId=1",
            "https://go.microsoft.com.evil.test/fwlink/?LinkId=1",
            "https://evil.test/fwlink/",
            "https://user:pass@go.microsoft.com/fwlink/",
            "https://go.microsoft.com:1234/fwlink/",
        )
        for link in bad:
            with self.subTest(link=link), self.assertRaises(probe.LabError):
                probe.validate_origin(link, probe.PERMITTED_START)

    def test_http_content_length_bounds(self):
        min_len, max_len = probe.MIN_ISO_SIZE, probe.MAX_ISO_SIZE
        self.assertEqual(probe.parse_iso_length(
            {"Content-Length": str(min_len)}, 200), min_len)
        self.assertEqual(probe.parse_iso_length(
            {"Content-Range": f"bytes 0-0/{max_len}"}, 206), max_len)
        for size in (min_len - 1, max_len + 1):
            with self.assertRaises(probe.LabError):
                probe.parse_iso_length({"Content-Length": str(size)}, 200)
        with self.assertRaises(probe.LabError):
            probe.parse_iso_length({"Content-Length": "untrusted"}, 200)

    def test_guest_and_integrity_do_not_follow_from_http_success(self):
        class Response:
            status = 200
            headers = {"Content-Length": str(5 * 1024**3)}
            def geturl(self):
                return "https://software-static.download.prss.microsoft.com/file.iso?sig=PRIVATE"
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        class Opener:
            def open(self, request, timeout):
                assert request.get_method() == "HEAD"
                assert timeout <= 20
                return Response()

        cat = probe.load_catalog()["profiles"]["win11_26h2_en_us_x64"]
        with patch.object(probe.urllib.request, "build_opener", return_value=Opener()):
            result = probe.probe("win11_26h2_en_us_x64", cat)
        self.assertTrue(result["httpOriginProbePassed"])
        self.assertFalse(result["isoDigestVerified"])
        self.assertFalse(result["windowsClientInstalled"])
        self.assertFalse(result["dualBootVerified"])
        self.assertFalse(result["winReRecovered"])
        self.assertFalse(result["productionStable"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("sig=", json.dumps(result))

    def test_hostile_redirect_is_denied_before_reading(self):
        handler = probe.MicrosoftOnlyRedirect()
        for link in (
            "http://software-static.download.prss.microsoft.com/test.iso",
            "https://evil.example/test.iso",
            "https://software-static.download.prss.microsoft.com.evil.example/test.iso",
        ):
            with self.subTest(link=link), self.assertRaises(probe.LabError):
                handler.redirect_request(None, None, 302, "Found", {}, link)


if __name__ == "__main__":
    unittest.main()
