"""Read-only signed-to-GRUB handoff bridge tests.

Only uses synthetic ISO metadata; the actual ISO/mount checks are covered by
the independent CachyOS Archiso preflight and QEMU OVMF smoke tests.
"""
from __future__ import annotations

import hashlib
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "assets/live/cachyos-signed-grub-handoff.py"
SPEC = importlib.util.spec_from_file_location("gaslux_signed_grub_handoff", SOURCE)
assert SPEC and SPEC.loader
BOOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOT)

ISO_BYTES = b"synthetic-not-real-ISO"
ROOT = "01234567-89ab-cdef-0123-456789abcdef"
RUN = "signed-grub-run-2026"
NONCE = "b" * 32
ISO_PLAN = {
    "schemaVersion": 1,
    "firmware": "uefi",
    "secureBootEnabled": False,
    "runId": RUN,
    "isoStorageFilesystem": "ntfs",
    "isoStorageUuid": "A4F10E38BCD29475",
    "isoRelativePath": "/Gaslux/cachyos.iso",
    "isoSha256": hashlib.sha256(ISO_BYTES).hexdigest(),
    "isoSizeBytes": len(ISO_BYTES),
}
DOC = {
    "schemaVersion": 1,
    "backend": "archiso-cachyos",
    "distribution": "cachyos",
    "runId": RUN,
    "bootNonce": NONCE,
    "firmware": "uefi",
    "partitionStyle": "gpt",
    "secureBootEnabled": False,
    "isoSha256": ISO_PLAN["isoSha256"],
    "isoSizeBytes": ISO_PLAN["isoSizeBytes"],
    "isoStorageUuid": ISO_PLAN["isoStorageUuid"],
    "isoStorageFilesystem": ISO_PLAN["isoStorageFilesystem"],
    "isoRelativePath": ISO_PLAN["isoRelativePath"],
    "rootUuid": ROOT,
    "targetDiskId": "NVME-signed-test-2026",
    "windowsEspUuid": "AB12-CD34",
    "windowsLoaderSha256": "0" * 64,
}
GRUB = (
    "menuentry 'CachyOS Archiso (experimental)' {\n"
    "    linux (gaslux_iso)/arch/boot/x86_64/vmlinuz-linux-cachyos archisobasedir=arch img_dev=UUID=A4F10E38BCD29475 img_loop=/Gaslux/cachyos.iso\n"
    "    initrd (gaslux_iso)/arch/boot/x86_64/initramfs-linux-cachyos.img\n"
    "}\n"
)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL Ed25519 required")
class SignedGrubHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.private = self.dir / "signer.priv"
        self.public = self.dir / "signer.pub"
        self.envelope = self.dir / "handoff.json"
        self.signature = self.dir / "handoff.sig"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                        "-out", str(self.private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout",
                        "-out", str(self.public)], check=True, capture_output=True)
        self.doc = dict(DOC)
        self.plan = dict(ISO_PLAN)
        self.signer = hashlib.sha256(self.public.read_bytes()).hexdigest()
        self.sign()
        self.preflight = patch.object(BOOT.ISO, "prepare", return_value={
            "grubEntry": GRUB,
            "isoSha256Verified": True,
            "isoMountedFromVerifiedSource": False,
        })
        self.iso_mock = self.preflight.start()
        self.addCleanup(self.preflight.stop)

    def sign(self):
        self.envelope.write_bytes(BOOT.AUTH.canonical(self.doc))
        result = subprocess.run([
            "openssl", "pkeyutl", "-sign", "-inkey", str(self.private), "-rawin",
            "-in", str(self.envelope), "-out", str(self.signature)
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def render(self, **changes):
        args = dict(
            envelope=self.envelope, signature=self.signature,
            public_key=self.public,
            trusted_signer_sha256=self.signer,
            expected_run_id=RUN, expected_root_uuid=ROOT,
            storage_root=self.dir, iso_root=self.dir,
            require_mounted_iso=False,
        )
        args.update(changes)
        return BOOT.bind_archiso_entry(self.plan, **args)

    def test_signed_kernel_arguments_emitted_exactly_once(self):
        result = self.render()
        grub = result["grubEntry"]
        self.assertEqual(grub.count("gaslux.run=" + RUN), 1)
        self.assertEqual(grub.count("gaslux.nonce=" + NONCE), 1)
        self.assertEqual(grub.count("gaslux.plan_sha256="), 1)
        self.assertEqual(grub.count("gaslux.key_sha256="), 1)
        self.assertIn("gaslux.key_sha256=" + self.signer, grub)
        self.assertTrue(result["signedSourceVerified"])
        self.assertFalse(result["sourceMountVerified"])
        self.assertFalse(result["efiChainAuthenticated"])
        self.assertFalse(result["productionInstallerReady"])

    def test_unsigned_iso_plan_mutation_is_rejected(self):
        self.plan["isoRelativePath"] = "/Gaslux/another.iso"
        with self.assertRaisesRegex(BOOT.SignedBootError, "source plan differs"):
            self.render()
        self.iso_mock.assert_not_called()

    def test_iso_digest_must_match_signed_envelope(self):
        self.plan["isoSha256"] = "c" * 64
        with self.assertRaisesRegex(BOOT.SignedBootError, "isoSha256"):
            self.render()

    def test_signer_must_be_independently_approved(self):
        with self.assertRaisesRegex(BOOT.SignedBootError, "independently approved"):
            self.render(trusted_signer_sha256="c" * 64)

    def test_wrong_root_uuid_rejected(self):
        with self.assertRaisesRegex(BOOT.AUTH.AuthError, "target root"):
            self.render(expected_root_uuid="ffffffff-ffff-ffff-ffff-ffffffffffff")

    def test_wrong_transaction_rejected(self):
        with self.assertRaisesRegex(BOOT.AUTH.AuthError, "transaction differs"):
            self.render(expected_run_id="other-transaction-run")

    def test_signature_corruption_rejected_before_iso_access(self):
        self.signature.write_bytes(b"\0" * 64)
        with self.assertRaisesRegex(BOOT.AUTH.AuthError, "signature verification"):
            self.render()
        self.iso_mock.assert_not_called()

    def test_signed_iso_path_mismatch_rejected(self):
        self.doc["isoRelativePath"] = "/Gaslux/different.iso"
        self.sign()
        with self.assertRaisesRegex(BOOT.SignedBootError, "isoRelativePath"):
            self.render()

    def test_unsupported_firmware_rejected_before_iso_access(self):
        self.doc["firmware"] = "bios"
        self.sign()
        with self.assertRaisesRegex(BOOT.AUTH.AuthError, "firmware"):
            self.render()
        self.iso_mock.assert_not_called()

    def test_unexpected_grub_kernel_line_rejected(self):
        self.iso_mock.return_value["grubEntry"] = "menuentry 'bad' {}\n"
        with self.assertRaisesRegex(BOOT.SignedBootError, "unexpected GRUB"):
            self.render()

    def test_duplicate_grub_kernel_line_rejected(self):
        self.iso_mock.return_value["grubEntry"] = GRUB.replace(
            "    initrd", "    linux (gaslux_iso)/evil\n    initrd")
        with self.assertRaisesRegex(BOOT.SignedBootError, "unexpected GRUB"):
            self.render()

    def test_default_mounted_iso_validation_is_enabled(self):
        self.render(require_mounted_iso=True)
        self.assertTrue(self.iso_mock.call_args.kwargs["require_mounted_iso"])


if __name__ == "__main__":
    unittest.main()
