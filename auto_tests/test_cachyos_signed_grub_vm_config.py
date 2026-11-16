"""Contract tests for the signed-entry QEMU boot bridge; NO VM is booted here."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "auto_tests/tools/cachyos_signed_grub_vm_config.py"
SPEC = importlib.util.spec_from_file_location("gaslux_signed_grub_vm_config", SOURCE)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)
PINNED = "959f6577f45e25ee9fd8c220fd221b08e4ea79412c7315c0f922dd6d86d5e33c"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SignedRealIsoLabBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gaslux-signed-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = self.root / "private.pem"
        self.evidence = self.root / "signed"
        self.evidence.mkdir()
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                        "-out", str(self.key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout",
                        "-out", str(self.evidence / "test-only-public.pem")],
                       check=True, capture_output=True)
        self.doc = {
            "schemaVersion": 1, "backend": "archiso-cachyos",
            "distribution": "cachyos", "runId": LAB.LAB_RUN_ID,
            "bootNonce": "ab" * 16, "firmware": "uefi",
            "partitionStyle": "gpt", "secureBootEnabled": False,
            "isoSha256": PINNED, "isoSizeBytes": 4_000_000_000,
            "isoStorageUuid": LAB.LAB_ISO_UUID, "isoStorageFilesystem": "ext4",
            "isoRelativePath": "/cachyos.iso", "rootUuid": LAB.LAB_ROOT_UUID,
            "targetDiskId": LAB.LAB_DISK_ID, "windowsEspUuid": "AB12-CD34",
            "windowsLoaderSha256": "0" * 64,
        }
        env = self.evidence / "test-only-handoff.json"
        env.write_bytes(LAB.AUTH.canonical(self.doc))
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.key),
             "-rawin", "-in", str(env), "-out",
             str(self.evidence / "test-only-handoff.sig")],
            check=True, capture_output=True,
        )
        key_sha = sha((self.evidence / "test-only-public.pem").read_bytes())
        plan_sha = sha(env.read_bytes())
        self.bootargs = (
            f"gaslux.run={LAB.LAB_RUN_ID} gaslux.nonce={self.doc['bootNonce']} "
            f"gaslux.plan_sha256={plan_sha} gaslux.key_sha256={key_sha}"
        )
        self.entry = (
            "# Gaslux CachyOS Archiso handoff — lab-only, not a production installer\n"
            f"# Transaction {LAB.LAB_RUN_ID}\n"
            "menuentry 'CachyOS Archiso (experimental)' --id gaslux-cachyos-archiso {\n"
            "    insmod part_gpt\n"
            "    insmod ext2\n"
            "    insmod iso9660\n"
            f"    search --no-floppy --fs-uuid --set=gaslux_iso_dev {LAB.LAB_ISO_UUID}\n"
            "    set gaslux_iso_path='/cachyos.iso'\n"
            "    if [ ! -f ($gaslux_iso_dev)$gaslux_iso_path ]; then\n"
            "        echo 'Verified CachyOS ISO location is missing'\n"
            "        sleep 10\n"
            "        reboot\n"
            "    fi\n"
            "    loopback gaslux_iso ($gaslux_iso_dev)$gaslux_iso_path\n"
            "    if [ ! -f (gaslux_iso)/arch/boot/x86_64/vmlinuz-linux-cachyos-lts ]; then\n"
            "        echo 'CachyOS ISO kernel is missing'\n"
            "        sleep 10\n"
            "        reboot\n"
            "    fi\n"
            f"{LAB.KERNEL}archisobasedir=arch img_dev=UUID={LAB.LAB_ISO_UUID} "
            f"img_loop=/cachyos.iso cow_spacesize=10G copytoram=auto {self.bootargs}\n"
            f"{LAB.INITRD}\n"
            "}\n"
        )
        self.rebuild()

    def rebuild(self):
        (self.evidence / "test-only-grub.cfg").write_text(self.entry, encoding="utf-8")
        attestation = {
            "signedPlanVerified": True, "realOfficialIsoSha256Verified": True,
            "realOfficialIsoLayoutVerified": True,
            "officialIsoSha256": PINNED,
            "signedGrubEntrySha256": sha(self.entry.encode()),
            "ephemeralTestSignerPublicKeySha256":
                sha((self.evidence / "test-only-public.pem").read_bytes()),
            "windowsPhysicalDiskIdentityVerified": False,
            "windowsBootChainAuthenticated": False,
            "windowsRecoveryVerified": False,
            "installedLinuxBootVerified": False,
            "stableForPhysicalDisks": False,
        }
        (self.evidence / "attestation.json").write_text(
            json.dumps(attestation) + "\n", encoding="utf-8"
        )
        names = ("attestation.json", "test-only-grub.cfg", "test-only-handoff.json",
                 "test-only-handoff.sig", "test-only-public.pem")
        (self.evidence / "SHA256SUMS").write_text("".join(
            sha((self.evidence / x).read_bytes()) + "  " + x + "\n" for x in names
        ))

    def test_authentic_lab_entry_becomes_observable_vm_boot_config(self):
        uuid, grub, proof = LAB.prepare(self.evidence, PINNED)
        self.assertEqual(uuid, LAB.LAB_ISO_UUID)
        self.assertIn(self.entry.replace(
            self.bootargs + "\n",
            self.bootargs + LAB.LAB_CONSOLE_FLAGS + "\n"
        ), grub)
        self.assertIn(LAB.LAB_CONSOLE_FLAGS, grub)
        self.assertEqual(json.loads(proof)["gaslux.run"], LAB.LAB_RUN_ID)
        self.assertEqual(json.loads(proof)["gaslux.plan_sha256"],
                         sha((self.evidence / "test-only-handoff.json").read_bytes()))

    def test_tampering_grub_hash_refused(self):
        (self.evidence / "test-only-grub.cfg").write_text("menuentry 'fake' {}\n")
        with self.assertRaisesRegex(LAB.LabBootError, "checksum mismatch"):
            LAB.prepare(self.evidence, PINNED)

    def test_repacked_grub_injection_refused_even_with_updated_hashes(self):
        self.entry = self.entry.replace("    insmod iso9660\n",
                                        "    insmod iso9660\n    set root=(hd0)\n")
        self.rebuild()
        with self.assertRaisesRegex(LAB.LabBootError, "pinned lab template"):
            LAB.prepare(self.evidence, PINNED)

    def test_wrong_pinned_hash_refused(self):
        with self.assertRaisesRegex(LAB.LabBootError, "pinned official ISO"):
            LAB.prepare(self.evidence, "1" * 64)

    def test_broken_signature_refused_even_after_repacking_checksums(self):
        (self.evidence / "test-only-handoff.sig").write_bytes(b"0" * 64)
        names = ("attestation.json", "test-only-grub.cfg", "test-only-handoff.json",
                 "test-only-handoff.sig", "test-only-public.pem")
        (self.evidence / "SHA256SUMS").write_text("".join(
            sha((self.evidence / x).read_bytes()) + "  " + x + "\n" for x in names
        ))
        with self.assertRaises(LAB.AUTH.AuthError):
            LAB.prepare(self.evidence, PINNED)

    def test_symlinked_signed_entry_refused(self):
        cfg = self.evidence / "test-only-grub.cfg"
        cfg.unlink()
        cfg.symlink_to(self.evidence / "test-only-handoff.json")
        with self.assertRaisesRegex(LAB.LabBootError, "linked lab evidence"):
            LAB.prepare(self.evidence, PINNED)


if __name__ == "__main__":
    unittest.main()
