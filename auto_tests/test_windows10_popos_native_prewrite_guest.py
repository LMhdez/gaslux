"""Real OpenSSL Ed25519 roundtrip/negative lab handoff tests (no guest, disk)."""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent/"tools"))

import windows10_popos_native_prewrite_guest as native
from windows_x64_installed_gpt_ro_audit import DiskAuditError


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL not available")
class SignedNativeLabHandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gaslux-pop-ed25519-")
        root = Path(self.tmp.name)
        self.payload = root / "plan.json"
        self.key = root / "native-key.pem"
        self.pub = root / "native.pub"
        self.sig = root / "native.sig"
        self.payload.write_text('{"case":"VM-only","padding":"'+"a"*750+'"}\n',
                                encoding="ascii")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                        "-out", str(self.key)], check=True,
                       capture_output=True, timeout=10)
        subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout",
                        "-out", str(self.pub)], check=True,
                       capture_output=True, timeout=10)
        self.sign()
        self.patches = ExitStack()
        self.patches.enter_context(patch.object(native, "PLAN_FILE", self.payload))
        self.patches.enter_context(patch.object(native, "SIGNATURE_FILE", self.sig))
        self.patches.enter_context(patch.object(native, "PUBLIC_KEY_FILE", self.pub))

    def tearDown(self):
        self.patches.close()
        self.tmp.cleanup()

    def sign(self):
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey",
                        str(self.key), "-rawin", "-in", str(self.payload),
                        "-out", str(self.sig)], check=True,
                       capture_output=True, timeout=10)

    def audit(self):
        native.require_lab_plan_signature(self.payload, self.sig, self.pub)

    def test_actual_ed25519_signed_exact_lab_plan_accepted(self):
        self.assertEqual(self.sig.stat().st_size, 64)
        self.audit()

    def test_tampered_plan_refused_even_with_same_signature(self):
        self.payload.write_bytes(self.payload.read_bytes().replace(b"VM-only",b"HOST-WR"))
        with self.assertRaises(DiskAuditError):
            self.audit()

    def test_replaced_signature_or_key_refused(self):
        self.sig.write_bytes(b"\x00"*64)
        with self.assertRaises(DiskAuditError):
            self.audit()
        self.sign()
        self.pub.write_text("not a public Ed25519 key\n")
        with self.assertRaises(DiskAuditError):
            self.audit()

    def test_missing_signature_and_short_payload_refused(self):
        self.sig.unlink()
        with self.assertRaises(DiskAuditError):
            self.audit()
        self.sign()
        self.payload.write_text("{}")
        with self.assertRaises(DiskAuditError):
            self.audit()

    def test_native_guest_refuses_host_without_vm_consent_before_access(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(DiskAuditError):
                native.prewrite_check()


if __name__ == "__main__":
    unittest.main()
