"""Laboratory-only tests for cryptographically authenticated CachyOS handoff.

The signing key in these tests is freshly generated and deliberately NOT a
production trust root. Passing tests does not authenticate a Windows boot.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "assets/live/cachyos-handoff-auth.py"
SPEC = importlib.util.spec_from_file_location("cachyos_handoff_auth", SOURCE)
assert SPEC and SPEC.loader
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)

ROOT_ID = "01234567-89ab-cdef-0123-456789abcdef"
RUN_ID = "verified-run-20261116"
NONCE = "1" * 32
PLAN = {
    "schemaVersion": 1, "backend": "archiso-cachyos",
    "distribution": "cachyos", "runId": RUN_ID,
    "bootNonce": NONCE, "firmware": "uefi",
    "partitionStyle": "gpt", "secureBootEnabled": False,
    "isoSha256": "2" * 64, "isoSizeBytes": 3_000_000_000,
    "isoStorageUuid": "F01A2299B12C348E",
    "rootUuid": ROOT_ID, "targetDiskId": "NVME-transaction-0001",
    "windowsEspUuid": "AB12-CD34",
    "windowsLoaderSha256": "3" * 64,
}


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL Ed25519 required")
class SignedHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.envelope = self.root / "envelope.json"
        self.sig = self.root / "envelope.sig"
        self.key = self.root / "handoff-public.pem"
        self.private = self.root / "handoff-private.pem"
        self.plan = dict(PLAN)
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519",
             "-out", str(self.private)],
            check=True, capture_output=True)
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.private),
             "-pubout", "-out", str(self.key)],
            check=True, capture_output=True)
        self.sign()

    def sign(self):
        self.envelope.write_bytes(AUTH.canonical(self.plan))
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.private),
             "-rawin", "-in", str(self.envelope), "-out", str(self.sig)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def cmdline(self):
        return (
            "BOOT_IMAGE=/vmlinuz-linux-cachyos archisobasedir=arch "
            + f"gaslux.run={RUN_ID} gaslux.nonce={NONCE} "
            + "gaslux.plan_sha256="
            + hashlib.sha256(self.envelope.read_bytes()).hexdigest()
            + " gaslux.key_sha256="
            + hashlib.sha256(self.key.read_bytes()).hexdigest()
        )

    def verify(self, cmdline=None, *, expected_run=RUN_ID, expected_root=ROOT_ID):
        return AUTH.verify(
            self.envelope, self.sig, self.key,
            self.cmdline() if cmdline is None else cmdline,
            expected_run_id=expected_run, expected_root_uuid=expected_root,
        )

    def test_signed_plan_bound_to_boot_cmdline(self):
        outcome = self.verify()
        self.assertTrue(outcome["verified"])
        self.assertEqual(outcome["runId"], RUN_ID)
        self.assertFalse(outcome["productionReady"])
        self.assertFalse(outcome["independentBootChainVerified"])
        self.assertFalse(outcome["windowsRecoveryVerified"])
        self.assertFalse(outcome["writesStorage"])

    def test_corrupted_signature_rejected(self):
        self.sig.write_bytes(b"\x00" * 64)
        with self.assertRaisesRegex(AUTH.AuthError, "signature verification"):
            self.verify()

    def test_wrong_public_key_fingerprint(self):
        with self.assertRaisesRegex(AUTH.AuthError, "fingerprint"):
            self.verify(self.cmdline().replace("gaslux.key_sha256=", "gaslux.key_sha256=" + "0" * 64 + " "))

    def test_plan_changed_after_signing(self):
        self.envelope.write_bytes(self.envelope.read_bytes().replace(
            b"NVME-transaction-0001", b"NVME-transaction-0002"))
        with self.assertRaisesRegex(AUTH.AuthError, "signature verification"):
            self.verify()

    def test_plan_digest_mismatch(self):
        cmd = self.cmdline().replace(
            "gaslux.plan_sha256=" + hashlib.sha256(self.envelope.read_bytes()).hexdigest(),
            "gaslux.plan_sha256=" + "0" * 64)
        with self.assertRaisesRegex(AUTH.AuthError, "handoff bytes differ"):
            self.verify(cmd)

    def test_nonce_replay_rejected(self):
        with self.assertRaisesRegex(AUTH.AuthError, "nonce differs"):
            self.verify(self.cmdline().replace("gaslux.nonce=" + NONCE,
                                              "gaslux.nonce=" + "a" * 32))

    def test_wrong_independent_run_id_rejected(self):
        with self.assertRaisesRegex(AUTH.AuthError, "installation transaction differs"):
            self.verify(expected_run="different-transaction")

    def test_wrong_independent_root_uuid_rejected(self):
        with self.assertRaisesRegex(AUTH.AuthError, "target root UUID"):
            self.verify(expected_root="ffffffff-ffff-ffff-ffff-ffffffffffff")

    def test_duplicate_boot_param_rejected(self):
        with self.assertRaisesRegex(AUTH.AuthError, "unexpected or repeated"):
            self.verify(self.cmdline() + " gaslux.run=" + RUN_ID)

    def test_unknown_gaslux_argument_rejected(self):
        with self.assertRaisesRegex(AUTH.AuthError, "unexpected or repeated"):
            self.verify(self.cmdline() + " gaslux.shell=1")

    def test_missing_boot_argument_rejected(self):
        cut = " gaslux.nonce=" + NONCE
        with self.assertRaisesRegex(AUTH.AuthError, "missing"):
            self.verify(self.cmdline().replace(cut, ""))

    def test_downgrade_to_bios_rejected(self):
        self.plan["firmware"] = "bios"
        self.sign()
        with self.assertRaisesRegex(AUTH.AuthError, "firmware"):
            self.verify()

    def test_secure_boot_enabled_rejected(self):
        self.plan["secureBootEnabled"] = True
        self.sign()
        with self.assertRaisesRegex(AUTH.AuthError, "Secure Boot"):
            self.verify()

    def test_wrong_distribution_rejected(self):
        self.plan["distribution"] = "mint"
        self.sign()
        with self.assertRaisesRegex(AUTH.AuthError, "distro/backend"):
            self.verify()

    def test_unknown_json_field_rejected(self):
        self.plan["shell"] = "reboot"
        self.sign()
        with self.assertRaisesRegex(AUTH.AuthError, "unexpected"):
            self.verify()

    def test_duplicate_target_uuid_rejected(self):
        self.plan["isoStorageUuid"] = ROOT_ID
        self.sign()
        with self.assertRaisesRegex(AUTH.AuthError, "must not share"):
            self.verify()

    def test_wrong_json_canonicalization_rejected(self):
        self.envelope.write_bytes(json.dumps(self.plan, indent=2).encode())
        # Signature is correctly calculated for the non-canonical bytes.
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.private),
             "-rawin", "-in", str(self.envelope), "-out", str(self.sig)],
            check=True, capture_output=True)
        with self.assertRaisesRegex(AUTH.AuthError, "not canonical"):
            self.verify()

    def test_symlinked_public_key_rejected(self):
        real_key = self.root / "original-public.pem"
        self.key.rename(real_key)
        self.key.symlink_to(real_key)
        with self.assertRaisesRegex(AUTH.AuthError, "missing or symlinked"):
            self.verify()

    def test_invalid_signature_size_rejected(self):
        self.sig.write_bytes(b"A" * 63)
        with self.assertRaisesRegex(AUTH.AuthError, "exactly 64"):
            self.verify()

    def test_no_implicit_boot_cmdline_override_in_cli(self):
        result = subprocess.run(
            ["python3", str(SOURCE), "--help"],
            check=False, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("--cmdline", result.stdout)

    def test_missing_real_kernel_parameters_cli_rejected(self):
        result = subprocess.run(
            ["python3", str(SOURCE), "--envelope", str(self.envelope),
             "--signature", str(self.sig), "--public-key", str(self.key),
             "--run-id", RUN_ID, "--root-uuid", ROOT_ID],
            check=False, text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["verified"])


if __name__ == "__main__":
    unittest.main()
