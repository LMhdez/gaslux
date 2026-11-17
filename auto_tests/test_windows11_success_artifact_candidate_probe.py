"""No-guest tests for the pinned historical Windows 10 candidate ZIP boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
import zipfile

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SRC = TOOLS / "windows11_success_artifact_candidate_probe.py"
spec = importlib.util.spec_from_file_location("windows11_archive_candidate", SRC)
assert spec and spec.loader
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

FIVE = {name: b"{}" if name.endswith(".json") else b"x"
        for name in P.EXPECTED}


def archive(files=None, symlink=None):
    files = dict(FIVE if files is None else files)
    sink = io.BytesIO()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as zipout:
        for name, value in files.items():
            if name == symlink:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                zipout.writestr(info, value)
            else:
                zipout.writestr(name, value)
    return sink.getvalue()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_result():
    out = {"candidateWindowsFirstbootDocumentsConsistent": True}
    out.update({name: False for name in (
        "windowsGuestOriginAuthenticated", "windowsBootVerified",
        "windowsBcdWinreRestorationVerified", "sameDiskDualBootVerified",
        "storageWritesAuthorized", "releaseEligible")})
    return out


class Windows11HistoricalCandidateZipTests(unittest.TestCase):
    def test_exact_pinned_sha256_required(self):
        with self.assertRaisesRegex(P.BaselineGateError, "differs from Actions"):
            P.inspect_archive(archive())

    def test_exact_member_set_required(self):
        files = dict(FIVE)
        files["../escape.txt"] = b"data"
        raw = archive(files)
        with self.assertRaisesRegex(P.BaselineGateError, "file count"):
            P.inspect_archive(raw, digest(raw))
        files.pop("../escape.txt")
        files.pop(next(iter(files)))
        raw = archive(files)
        with self.assertRaisesRegex(P.BaselineGateError, "file count"):
            P.inspect_archive(raw, digest(raw))

    def test_symlink_entry_refused_even_with_matching_zip_digest(self):
        raw = archive(symlink=next(iter(FIVE)))
        with self.assertRaisesRegex(P.BaselineGateError, "unsafe evidence member"):
            P.inspect_archive(raw, digest(raw))

    def test_oversized_json_refused_before_decompression_to_parser(self):
        files = dict(FIVE)
        files[P.PREFIX + "result.json"] = b"x" * (P.EXPECTED[P.PREFIX + "result.json"] + 1)
        raw = archive(files)
        with self.assertRaisesRegex(P.BaselineGateError, "unsafe evidence member"):
            P.inspect_archive(raw, digest(raw))

    def test_candidate_never_claims_guest_origin_or_storage_permission(self):
        raw = archive()
        with patch.object(P, "evaluate", return_value=safe_result()) as gate:
            result = P.inspect_archive(raw, digest(raw))
        self.assertTrue(result["candidateWindowsFirstbootDocumentsConsistent"])
        self.assertFalse(result["storageWritesAuthorized"])
        self.assertFalse(result["releaseEligible"])
        self.assertEqual(gate.call_count, 1)

    def test_any_unsupported_release_flag_rejected(self):
        raw = archive()
        for key in ("windowsBootVerified", "storageWritesAuthorized",
                    "windowsGuestOriginAuthenticated", "releaseEligible"):
            unsafe = safe_result()
            unsafe[key] = True
            with self.subTest(key=key):
                with patch.object(P, "evaluate", return_value=unsafe):
                    with self.assertRaisesRegex(P.BaselineGateError,
                                                "must not authorize"):
                        P.inspect_archive(raw, digest(raw))

    def test_original_real_run_identity_pinned(self):
        self.assertEqual(P.ACTIONS_RUN, 44094951108)
        self.assertEqual(P.ARTIFACT_ID, 14335490721)
        self.assertEqual(P.SOURCE_COMMIT, "35ef6de46b71524c6c05c8d9f3a9f87564529ce7")
        self.assertEqual(len(P.ZIP_SHA256), 64)


if __name__ == "__main__":
    unittest.main()
