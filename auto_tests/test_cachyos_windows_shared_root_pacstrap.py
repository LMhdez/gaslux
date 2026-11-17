"""Signed Archiso lab pacstrap scope: synthetic GPT and deny-by-default tests.

Never opens a real disk; GPT windows are bytes from the existing fixture.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import struct
from types import SimpleNamespace
from unittest.mock import patch
import unittest
import uuid
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "tools"))
import cachyos_windows_shared_root_pacstrap as shared
from test_windows_cachyos_qcow2_gpt_readonly import create_disk_windows
from tools.windows_cachyos_qcow2_gpt_readonly import TYPES

LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"


def fixture():
    front, back = create_disk_windows(part_types=list(TYPES) + [LINUX])
    data = front[2*512:34*512]
    parts = []
    for i in range(5):
        entry = data[i*128:(i+1)*128]
        lo, hi = struct.unpack_from("<QQ", entry, 32)
        parts.append({
            "index": i+1,
            "typeGuid": str(uuid.UUID(bytes_le=entry[:16])),
            "uniqueGuid": str(uuid.UUID(bytes_le=entry[16:32])),
            "firstLba": lo, "lastLba": hi,
        })
    return front, back, {
        "diskGuidSha256": hashlib.sha256(front[512+56:512+72]).hexdigest(),
        "gptWindowsSha256": hashlib.sha256(data[:4*128]).hexdigest(),
        "partitions": parts,
    }


def check(front, back, plan):
    # Only /dev/null is opened; the mock replaces every read with fixture bytes.
    # No block device is ever accessed or mutated.
    def pread(_fd, _count, offset):
        return front if offset == 0 else back
    with patch.object(Path, "is_block_device", return_value=True), \
         patch("os.pread", side_effect=pread), \
         patch("os.fstat", return_value=SimpleNamespace(st_mode=stat.S_IFBLK)):
        return shared.strict_gpt_evidence(Path("/dev/null"), plan)


class SharedRootOnlySafety(unittest.TestCase):
    def test_both_gpt_crcs_and_five_signed_entries(self):
        front, back, plan = fixture()
        proof = check(front, back, plan)
        self.assertTrue(proof["bothGptCopiesCrcVerified"])
        self.assertTrue(proof["allWindowsAndOwnedLinuxEntriesIdenticalToSignedPlan"])
        self.assertFalse(proof["productionWritesAuthorized"])

    def test_foreign_fifth_guid_rejected(self):
        front, back, plan = fixture()
        plan["partitions"][4]["uniqueGuid"] = "10000000-0000-4000-8000-000000000001"
        with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                    "GPT entry disagrees"):
            check(front, back, plan)

    def test_signed_windows_partition_record_bytes_are_binding(self):
        front, back, plan = fixture()
        plan["gptWindowsSha256"] = "a" * 64
        with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                    "Windows GPT entry bytes differ"):
            check(front, back, plan)

    def test_missing_backup_crc_or_modified_primary_rejected(self):
        front, back, plan = fixture()
        damaged = bytearray(back)
        damaged[-512+20] ^= 1
        with self.assertRaises(ValueError):
            check(front, bytes(damaged), plan)
        damaged = bytearray(front)
        damaged[2*512+20] ^= 1
        with self.assertRaises(ValueError):
            check(bytes(damaged), back, plan)

    def test_hybrid_mbr_refused(self):
        front, back, plan = fixture()
        damaged = bytearray(front)
        damaged[446+16+4] = 0x07
        with self.assertRaisesRegex(shared.SharedDiskHandoffRejected, "hybrid"):
            check(bytes(damaged), back, plan)

    def test_noncanonical_windows_pmbr_only_reported_not_authorized(self):
        front, back, plan = fixture()
        changed = bytearray(front)
        struct.pack_into("<I", changed, 446+12, 0xffffffff)
        observed = check(bytes(changed), back, plan)
        self.assertTrue(observed["protectiveMbrWindowsLabOversized"])
        self.assertFalse(observed["productionWritesAuthorized"])

    def test_no_disk_actions_from_non_archiso_user(self):
        with patch.object(shared, "require_live_archiso",
                          side_effect=shared.SharedDiskHandoffRejected("not Archiso")), \
             patch.object(shared, "protected_files_readonly") as files, \
             patch.object(shared, "execute") as commands:
            with self.assertRaisesRegex(shared.SharedDiskHandoffRejected, "not Archiso"):
                shared.guest_plan(SimpleNamespace())
            files.assert_not_called()
            commands.assert_not_called()

    def test_backend_writes_only_native_root_never_installs_bootloader(self):
        source = (HERE / "tools/cachyos_windows_shared_root_pacstrap.py").read_text()
        self.assertIn('"pacstrap", "-K", str(ROOT)', source)
        self.assertIn('protected_files_readonly(disk, plan)', source)
        self.assertIn('strict_gpt_evidence(disk, plan)', source)
        self.assertIn('GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED', source)
        for command in ("sgdisk --clear", "mkfs.vfat", "mkfs.ext4",
                        "grub-install", "efibootmgr -c", "part_add(",
                        "part_del(", "BootOrder", "BootNext"):
            self.assertNotIn(command, source)


if __name__ == "__main__":
    unittest.main()
