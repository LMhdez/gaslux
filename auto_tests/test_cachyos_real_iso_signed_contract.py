"""Fail-closed tests for the pinned, test-key-only real ISO signed bridge.

No live ISO download and no disk modification occurs in these tests.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "auto_tests/tools/cachyos_real_iso_signed_contract.py"
SPEC = importlib.util.spec_from_file_location("gaslux_real_iso_signed_contract_tests", SOURCE)
assert SPEC and SPEC.loader
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)


class RealIsoSigningContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.iso = self.root / "cachyos.iso"
        self.iso.write_bytes(b"fake ISO - must be rejected before keys are created")
        self.mounted = self.root / "mount"
        self.mounted.mkdir()
        self.output = self.root / "evidence"

    def test_tiny_fake_iso_never_produces_signed_plan(self):
        with self.assertRaisesRegex(ValueError, "wrong size or SHA-256"):
            CONTRACT.bind_real_signed_iso(self.iso, self.mounted, self.output)
        self.assertFalse(self.output.exists())

    def test_unapproved_iso_name_is_rejected_before_hashing(self):
        renamed = self.root / "untrusted.iso"
        self.iso.rename(renamed)
        with self.assertRaisesRegex(ValueError, "official ISO file named"):
            CONTRACT.bind_real_signed_iso(renamed, self.mounted, self.output)
        self.assertFalse(self.output.exists())

    def test_symlink_source_iso_rejected(self):
        real = self.root / "real-cachyos.iso"
        real.write_bytes(self.iso.read_bytes())
        self.iso.unlink()
        self.iso.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "expected plain official ISO"):
            CONTRACT.bind_real_signed_iso(self.iso, self.mounted, self.output)
        self.assertFalse(self.output.exists())

    def test_sha256_is_independent_of_untrusted_plan(self):
        self.assertEqual(
            CONTRACT.PINNED_SHA256,
            "959f6577f45e25ee9fd8c220fd221b08e4ea79412c7315c0f922dd6d86d5e33c",
        )
        self.assertEqual(CONTRACT.PINNED_IMAGE_VERSION, "2026.08.09")

    def test_no_production_trust_root_is_embedded(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("tempfile.TemporaryDirectory", source)
        self.assertIn("openssl\", \"genpkey\"", source)
        self.assertIn('"stableForPhysicalDisks": False', source)
        self.assertIn('"windowsBootChainAuthenticated": False', source)
        self.assertIn('"sourceMountVerified": False', source)


if __name__ == "__main__":
    unittest.main()
