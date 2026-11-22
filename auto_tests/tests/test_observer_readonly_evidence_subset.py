"""Offline adversarial tests for the isolated Observer evidence primitives.

No guest, QEMU, VNC, network, installed-system input or disk writer is used.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from auto_tests.installer_observer import evidence


class ObserverEvidenceReadOnlyTests(unittest.TestCase):
    def test_provenance_is_not_an_execution_grant(self) -> None:
        source = Path(evidence.__file__).read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket.socket", "send-key", "QEMU", "os.O_WRONLY"):
            self.assertNotIn(forbidden, source)
        # A checksum without an independent trust root is NOT authentication.
        self.assertTrue(evidence.unseal(evidence.sealed({"authorized": True}))["authorized"])

    def test_duplicate_json_keys_are_refused_at_any_depth(self) -> None:
        for raw in (
            b'{"action":"observe","action":"install"}',
            b'{"outer":{"mode":"safe","mode":"unsafe"}}',
        ):
            with self.subTest(raw=raw), self.assertRaises(evidence.Refusal):
                evidence.parse(raw)

    def test_non_object_and_invalid_json_are_refused(self) -> None:
        for raw in (b"[]", b"null", b"NaN", b'{"v":Infinity}', b"\xff", b'{"a":'):
            with self.subTest(raw=raw), self.assertRaises(evidence.Refusal):
                evidence.parse(raw)

    def test_canonical_digest_is_deterministic_but_not_signed(self) -> None:
        left = evidence.canonical({"a": 1, "b": 2})
        right = evidence.canonical({"b": 2, "a": 1})
        self.assertEqual(left, right)
        self.assertEqual(evidence.digest(left), evidence.digest(right))
        with self.assertRaises(ValueError):
            evidence.canonical({"nan": float("nan")})

    def test_manifest_tamper_refused_and_self_issued_envelope_not_trusted(self) -> None:
        report = {"kind": "untrusted-observation", "inputAuthorized": False}
        envelope = evidence.sealed(report)
        self.assertEqual(evidence.unseal(envelope), report)
        envelope["manifest"]["inputAuthorized"] = True
        with self.assertRaises(evidence.Refusal):
            evidence.unseal(envelope)
        forged = evidence.sealed({"inputAuthorized": True})
        self.assertTrue(evidence.unseal(forged)["inputAuthorized"])
        with self.assertRaises(evidence.Refusal):
            evidence.unseal({"manifest": {}, "sha256": "bad", "authorized": True})

    def test_unsafe_basenames_refused(self) -> None:
        for name in ("../boot", "/tmp/other", "bad\\name", "bad:name", "CON", "COM1",
                     "LPT9.txt", "x.", "", "white space"):
            with self.subTest(name=name), self.assertRaises(evidence.Refusal):
                evidence.basename(name)
        self.assertEqual(evidence.basename("evidence-file_1.json"), "evidence-file_1.json")

    @unittest.skipUnless(os.name == "posix", "Linux dirfd and nofollow checks")
    def test_valid_regular_file_and_bounded_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gaslux-evidence-") as directory:
            file = Path(directory) / "sample.json"
            file.write_bytes(b'{"action":"observe"}')
            self.assertEqual(evidence.parse(evidence.read(file))["action"], "observe")
            with self.assertRaises(evidence.Refusal):
                evidence.read(file, limit=3)

    @unittest.skipUnless(os.name == "posix", "Linux dirfd and nofollow checks")
    def test_symlinks_and_hardlinks_are_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gaslux-evidence-") as directory:
            root = Path(directory)
            file = root / "original"
            file.write_bytes(b"safe-evidence")
            sym = root / "alias"
            sym.symlink_to(file)
            hard = root / "hard"
            os.link(file, hard)
            for path in (sym, hard):
                with self.subTest(path=str(path)), self.assertRaises(evidence.Refusal):
                    evidence.read(path)
            external_dir = root / "subdir"
            external_dir.mkdir()
            alias_dir = root / "aliasdir"
            alias_dir.symlink_to(external_dir, target_is_directory=True)
            nested = external_dir / "data"
            nested.write_bytes(b"original-data")
            with self.assertRaises(evidence.Refusal):
                evidence.read(alias_dir / "data")

    @unittest.skipUnless(os.name == "posix", "Linux descriptor-bound post-read checks")
    def test_changed_file_during_read_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gaslux-evidence-") as directory:
            file = Path(directory) / "mutable"
            file.write_bytes(b"first")
            with self.assertRaises(evidence.Refusal), evidence.regular(file, 256) as stream:
                self.assertEqual(stream.read(), b"first")
                file.write_bytes(b"changed-and-longer")

    def test_no_authority_flags_are_produced_by_parser(self) -> None:
        payload = evidence.parse(b'{"qemuAuthorized":true,"diskWritesAuthorized":true}')
        self.assertEqual(payload, {"qemuAuthorized": True, "diskWritesAuthorized": True})
        # The parser faithfully returns untrusted input; caller must never grant rights.
        self.assertNotIn("authorize", dir(evidence))
        self.assertEqual(json.loads(evidence.canonical(payload)), payload)


if __name__ == "__main__":
    unittest.main()
