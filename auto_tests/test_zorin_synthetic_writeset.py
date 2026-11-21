"""Real-byte adversarial tests for the Zorin synthetic-only write-set policy.

All writes occur exclusively in private tempfile raw files. The canonical
Safety #265 GPT reader is imported unmodified from a PINNED sibling checkout.
"""
from __future__ import annotations

from copy import deepcopy
import errno
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
import uuid
import zlib
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from libertix_disk_identity_gate import inspect_gpt_image
from zorin_synthetic_writeset import (
    SyntheticPolicy,
    WriteSetRefused,
    tree_digest,
    verify_private_synthetic,
)

SECTOR = 512
BYTES = 16 * 1024 * 1024
N = BYTES // SECTOR
DISK_GUID = "a2f2f5ab-370d-4c54-b15e-903c29ea1e31"
ESP_GUID = "be77eb0d-af64-4a01-aa73-25cb7cb5f6a0"
ROOT_GUID = "d96e592b-22ad-4a07-8970-59e16cef4e7e"
PROTECTED_GUID = "78ae7635-4a81-44e3-a61d-e1f493273232"
GPT_TYPES = (
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "0fc63daf-8483-4772-8e79-3d69d8477de4",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
)
PARTS = ((ESP_GUID, 2048, 4095), (ROOT_GUID, 4096, 8191), (PROTECTED_GUID, 8192, 10239))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generated_valid_gpt(*, root_guid: str = ROOT_GUID) -> bytes:
    """Fixture creator, NOT a GPT inspector or production partitioning engine."""
    image = bytearray(BYTES)
    image[446 + 4] = 0xEE
    struct.pack_into("<II", image, 446 + 8, 1, N - 1)
    image[510:512] = b"\x55\xaa"
    image[2048 * SECTOR : 2048 * SECTOR + len(b"EFI-SYNTHETIC")] = b"EFI-SYNTHETIC"
    image[8192 * SECTOR : 8192 * SECTOR + 9] = b"PROTECTED"
    array = bytearray(128 * 128)
    for i, ((guid_str, start, end), type_guid) in enumerate(zip(PARTS, GPT_TYPES)):
        chosen = root_guid if i == 1 else guid_str
        begin = i * 128
        array[begin : begin + 16] = uuid.UUID(type_guid).bytes_le
        array[begin + 16 : begin + 32] = uuid.UUID(chosen).bytes_le
        struct.pack_into("<QQQ", array, begin + 32, start, end, 0)
    crc_array = zlib.crc32(array)
    image[2 * SECTOR : 2 * SECTOR + len(array)] = array
    image[(N - 33) * SECTOR : (N - 33) * SECTOR + len(array)] = array
    for current, alternate, array_lba in ((1, N - 1, 2), (N - 1, 1, N - 33)):
        header = bytearray(SECTOR)
        header[:8] = b"EFI PART"
        struct.pack_into("<IIII", header, 8, 0x10000, 92, 0, 0)
        struct.pack_into("<QQQQ", header, 24, current, alternate, 34, N - 34)
        header[56:72] = uuid.UUID(DISK_GUID).bytes_le
        struct.pack_into("<QIII", header, 72, array_lba, 128, 128, crc_array)
        struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
        image[current * SECTOR : (current + 1) * SECTOR] = header
    return bytes(image)


def make_policy(root: Path) -> dict:
    snap = inspect_gpt_image(root / "baseline.raw", logical_sector_size=SECTOR)
    parts = {p["number"]: p for p in snap["partitions"]}
    def zone(number: int, role: str):
        p = parts[number]
        return {
            "role": role,
            "number": number,
            "partGuid": p["partGuid"],
            "offsetBytes": p["offsetBytes"],
            "sizeBytes": p["sizeBytes"],
        }
    disk_hash = sha((root / "baseline.raw").read_bytes())
    return {
        "schemaVersion": 1,
        "kind": "ZORIN_SYNTHETIC_WRITESET_V1",
        "transactionId": "f" * 32,
        "checkpointId": "zorin-cp-" + "a" * 16,
        "ownerLabel": "GASLUX-ZORIN-SYNTHETIC",
        "diskBytes": BYTES,
        "logicalSectorBytes": SECTOR,
        "diskSha256": disk_hash,
        "checkpointSha256": disk_hash,
        "espTreeSha256": tree_digest(root, "esp-base"),
        "ovmfVarsSha256": sha((root / "ovmf-base.fd").read_bytes()),
        "diskIdentity": snap,
        "esp": zone(1, "ESP"),
        "linux": zone(2, "LINUX_ROOT"),
        "writeSet": ["LINUX_ROOT_BYTES_ONLY"],
        "writeOperations": [],
        "authorization": "DENY_NO_WRITER",
        "syntheticOnly": True,
        "transactionOwned": False,
        "externalAttestationVerified": False,
        "windowsRollbackVerified": False,
        "nativeInstallerInvoked": False,
    }


class ZorinSyntheticWriteSetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gaslux-zorin-writeset-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        content = generated_valid_gpt()
        for name in ("baseline.raw", "trial.raw", "checkpoint.raw"):
            (self.root / name).write_bytes(content)
        for name in ("baseline.raw", "checkpoint.raw"):
            (self.root / name).chmod(0o400)
        for name in ("ovmf-base.fd", "ovmf-trial.fd"):
            (self.root / name).write_bytes(b"SYNTHETIC-OVMF-NO-USER-DATA" + b"\x03" * 200)
        for folder in ("esp-base", "esp-trial"):
            (self.root / folder / "EFI/Microsoft/Boot").mkdir(parents=True)
            (self.root / folder / "EFI/Foreign").mkdir(parents=True)
            (self.root / folder / "EFI/Microsoft/Boot/bootmgfw.efi").write_bytes(
                b"synthetic-windows"
            )
            (self.root / folder / "EFI/Foreign/loader.efi").write_bytes(b"synthetic-foreign")
        self.policy = make_policy(self.root)
        self.receipt = {
            "transactionId": self.policy["transactionId"],
            "checkpointId": self.policy["checkpointId"],
            "baselineSha256": self.policy["diskSha256"],
            "provenance": "SYNTHETIC_UNATTESTED",
        }
        (self.root / "receipt.json").write_text(json.dumps(self.receipt))
        (self.root / "policy.json").write_text(json.dumps(self.policy))

    def check(self):
        return verify_private_synthetic(self.root, self.policy)

    def mutate(self, name: str, offset: int):
        with (self.root / name).open("r+b") as fd:
            fd.seek(offset)
            old = fd.read(1)
            fd.seek(offset)
            fd.write(bytes([old[0] ^ 0xFF]))

    def refused(self, code: str):
        with self.assertRaises(WriteSetRefused) as context:
            self.check()
        self.assertEqual(context.exception.code, code)

    def test_positive_no_change(self):
        value = self.check()
        self.assertEqual(value["result"], "SYNTHETIC_NO_CHANGE")
        self.assertFalse(value["productionWriteAuthorized"])

    def test_positive_root_bytes_only(self):
        self.mutate("trial.raw", PARTS[1][1] * SECTOR + 77)
        value = self.check()
        self.assertEqual(value["result"], "SYNTHETIC_ONLY_WITHIN_ROOT")
        self.assertEqual(value["changedLinuxBytes"], 1)
        self.assertEqual(value["authorization"], "DENY_NO_WRITER")
        self.assertFalse(value["windowsRollbackVerified"])

    def test_primary_gpt_sector_refused(self):
        self.mutate("trial.raw", 1 * SECTOR + 11)
        self.refused("E_GPT_INVALID")

    def test_backup_gpt_sector_refused(self):
        self.mutate("trial.raw", (N - 1) * SECTOR + 80)
        self.refused("E_GPT_INVALID")

    def test_valid_recalculated_partuuid_change_refused(self):
        (self.root / "trial.raw").write_bytes(
            generated_valid_gpt(root_guid="8a98e4fc-37fa-4b34-8017-52d7e4bff9d1")
        )
        self.refused("E_PARTUUID_CHANGED")

    def test_unallocated_free_sector_refused(self):
        self.mutate("trial.raw", 15000 * SECTOR + 33)
        self.refused("E_OUTSIDE_LINUX_CHANGED")

    def test_protected_partition_refused(self):
        self.mutate("trial.raw", PARTS[2][1] * SECTOR + 90)
        self.refused("E_OUTSIDE_LINUX_CHANGED")

    def test_raw_esp_sector_refused(self):
        self.mutate("trial.raw", PARTS[0][1] * SECTOR + 22)
        self.refused("E_ESP_PARTITION_CHANGED")

    def test_modified_microsoft_efi_file_refused(self):
        path = self.root / "esp-trial/EFI/Microsoft/Boot/bootmgfw.efi"
        path.write_bytes(b"tampered")
        self.refused("E_ESP_FILES_CHANGED")

    def test_added_foreign_efi_file_refused(self):
        (self.root / "esp-trial/EFI/Foreign/unapproved.efi").write_bytes(b"new EFI")
        self.refused("E_ESP_FILES_CHANGED")

    def test_ovmf_vars_mutation_refused(self):
        self.mutate("ovmf-trial.fd", 20)
        self.refused("E_OVMF_CHANGED")

    def test_checkpoint_replaced_refused(self):
        ref = self.root / "checkpoint.raw"
        ref.chmod(0o600)
        self.mutate("checkpoint.raw", PARTS[1][1] * SECTOR + 8)
        ref.chmod(0o400)
        self.refused("E_CHECKPOINT_CHANGED")

    def test_baseline_changed_refused(self):
        ref = self.root / "baseline.raw"
        ref.chmod(0o600)
        self.mutate("baseline.raw", PARTS[1][1] * SECTOR + 8)
        ref.chmod(0o400)
        self.refused("E_BASELINE_CHANGED")

    def test_writable_checkpoint_denied(self):
        (self.root / "checkpoint.raw").chmod(0o600)
        self.refused("E_REFERENCE_WRITABLE")

    def test_foreign_transaction_receipt_refused(self):
        self.receipt["transactionId"] = "1" * 32
        (self.root / "receipt.json").write_text(json.dumps(self.receipt))
        self.refused("E_FOREIGN_TRANSACTION")

    def test_wrong_checkpoint_id_refused(self):
        self.receipt["checkpointId"] = "zorin-cp-" + "b" * 16
        (self.root / "receipt.json").write_text(json.dumps(self.receipt))
        self.refused("E_FOREIGN_TRANSACTION")

    def test_historical_cachyos_owner_stays_denied(self):
        bad = deepcopy(self.policy)
        bad["ownerLabel"] = "GASLUX-CACHYOS-ROOT"
        with self.assertRaises(WriteSetRefused) as cm:
            verify_private_synthetic(self.root, bad)
        self.assertIn(cm.exception.code, ("E_POLICY_SCHEMA", "E_FOREIGN_OWNER"))

    def test_permission_escalation_schema_refused(self):
        for key, value in (
            ("authorization", "ACCEPT_NO_WRITER"),
            ("transactionOwned", True),
            ("externalAttestationVerified", True),
            ("writeOperations", ["mkfs.ext4"]),
        ):
            bad = deepcopy(self.policy)
            bad[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(WriteSetRefused, "E_POLICY_SCHEMA"):
                verify_private_synthetic(self.root, bad)

    def test_symlink_disk_source_refused(self):
        (self.root / "trial.raw").unlink()
        (self.root / "trial.raw").symlink_to("baseline.raw")
        self.refused("E_FOREIGN_FILE")

    def test_hardlinked_disk_source_refused(self):
        (self.root / "trial.raw").unlink()
        os.link(self.root / "baseline.raw", self.root / "trial.raw")
        self.refused("E_FOREIGN_FILE")

    def test_symlink_esp_refused(self):
        entry = self.root / "esp-trial/EFI/Microsoft/Boot/bootmgfw.efi"
        entry.unlink()
        entry.symlink_to(self.root / "esp-base/EFI/Microsoft/Boot/bootmgfw.efi")
        self.refused("E_ESP_FOREIGN")

    def test_foreign_private_root_refused(self):
        other = Path(self.tmp.name).parent
        with self.assertRaisesRegex(WriteSetRefused, "E_FOREIGN_WORKSPACE"):
            verify_private_synthetic(other, self.policy)

    def test_schema_draft202012_and_target_structure(self):
        from jsonschema import Draft202012Validator
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/zorin-synthetic-writeset-v1.schema.json"
            ).read_text()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.policy)
        self.assertEqual(SyntheticPolicy.parse(self.policy).linux.part_guid, ROOT_GUID)

    def test_snapshot_clone_is_independent_file_and_no_shared_inode(self):
        a = (self.root / "baseline.raw").stat()
        b = (self.root / "checkpoint.raw").stat()
        c = (self.root / "trial.raw").stat()
        self.assertEqual(len({a.st_ino, b.st_ino, c.st_ino}), 3)
        self.assertEqual(a.st_nlink, b.st_nlink)
        self.assertEqual(b.st_nlink, c.st_nlink)

    def restore_synthetic_arm(self, inject_enospc=False):
        """Test-only atomic restore; no production API or Windows rollback."""
        staging = self.root / "test-owned-restore.pending"
        assert not staging.exists()
        try:
            with (self.root / "checkpoint.raw").open("rb") as source, staging.open("xb") as target:
                while True:
                    block = source.read(65536)
                    if not block:
                        break
                    target.write(block)
                    if inject_enospc and target.tell() > 131072:
                        raise OSError(errno.ENOSPC, "synthetic ENOSPC injection")
                target.flush()
                os.fsync(target.fileno())
            if sha(staging.read_bytes()) != self.policy["diskSha256"]:
                raise ValueError("E_RESTORE_DIGEST")
            os.replace(staging, self.root / "trial.raw")
            if sha((self.root / "trial.raw").read_bytes()) != self.policy["diskSha256"]:
                raise ValueError("E_RESTORE_VERIFY")
            return self.check()
        finally:
            if staging.exists():
                staging.unlink()

    def test_synthetic_copy_restore_verified(self):
        other = self.root / "foreign-transaction-canary"
        other.write_bytes(b"another-owner")
        self.mutate("trial.raw", PARTS[2][1] * SECTOR + 90)
        self.refused("E_OUTSIDE_LINUX_CHANGED")
        result = self.restore_synthetic_arm()
        self.assertEqual(result["result"], "SYNTHETIC_NO_CHANGE")
        self.assertEqual(other.read_bytes(), b"another-owner")
        self.assertFalse(result["independentRecoveryAttested"])

    def test_injected_enospc_is_not_restore_success(self):
        self.mutate("trial.raw", PARTS[2][1] * SECTOR + 90)
        with self.assertRaises(OSError) as err:
            self.restore_synthetic_arm(inject_enospc=True)
        self.assertEqual(err.exception.errno, errno.ENOSPC)
        self.refused("E_OUTSIDE_LINUX_CHANGED")
        self.assertFalse((self.root / "test-owned-restore.pending").exists())

    def test_invalid_reference_prevents_restore_claim(self):
        checkpoint = self.root / "checkpoint.raw"
        checkpoint.chmod(0o600)
        self.mutate("checkpoint.raw", PARTS[1][1] * SECTOR + 40)
        checkpoint.chmod(0o400)
        self.mutate("trial.raw", PARTS[2][1] * SECTOR + 90)
        with self.assertRaisesRegex(ValueError, "E_RESTORE_DIGEST"):
            self.restore_synthetic_arm()
        self.refused("E_CHECKPOINT_CHANGED")

    def test_truncated_disk_refused(self):
        with (self.root / "trial.raw").open("r+b") as handle:
            handle.truncate(1024 * 1024)
        self.refused("E_DISK_SIZE_CHANGED")

    def test_missing_receipt_is_rejected(self):
        (self.root / "receipt.json").unlink()
        self.refused("E_FOREIGN_FILE")

    def test_hardlinked_esp_file_is_rejected(self):
        original = self.root / "esp-trial/EFI/Microsoft/Boot/bootmgfw.efi"
        original.unlink()
        os.link(self.root / "esp-base/EFI/Microsoft/Boot/bootmgfw.efi", original)
        self.refused("E_ESP_FOREIGN")

    def test_explicit_unallocated_canary_is_protected(self):
        canary = self.root / "trial.raw"
        with canary.open("r+b") as output:
            output.seek(25000 * SECTOR)
            output.write(b"CANARY")
        self.refused("E_OUTSIDE_LINUX_CHANGED")

    def test_no_unapproved_writer_exists_in_verifier(self):
        code = (Path(__file__).parent / "tools/zorin_synthetic_writeset.py").read_text()
        for token in (
            "mkfs.ext4",
            "grub-install",
            "efibootmgr --create",
            "qemu-system",
            "wipefs",
            "os.O_WRONLY",
            "os.O_RDWR",
        ):
            self.assertNotIn(token, code)


if __name__ == "__main__":
    unittest.main()
