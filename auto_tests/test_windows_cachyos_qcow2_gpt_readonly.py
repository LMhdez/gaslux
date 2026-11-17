"""Synthetic, no-disk GPT CRC/geometry regressions for Windows+CachyOS labs."""
from __future__ import annotations

import binascii
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import uuid

SRC = Path(__file__).resolve().parent / "tools/windows_cachyos_qcow2_gpt_readonly.py"
spec = importlib.util.spec_from_file_location("windows_gpt_disk_baseline", SRC)
assert spec is not None and spec.loader is not None
gpt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gpt)
TOTAL = gpt.VIRTUAL_BYTES // gpt.SECTOR
LAST = TOTAL - 1
GUID = uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-synthetic-disposable-gpt").bytes_le


def create_disk_windows(part_types=None, overlap=False, small_free=False,
                        duplicate_partition_guid=False):
    types = list(part_types or gpt.TYPES)
    data = bytearray(128 * 128)
    sizes = (260, 16, 73728, 1536, 2048)
    start = 2048
    for i, typ in enumerate(types):
        first = start
        length = sizes[i] * 2048
        if overlap and i == 2:
            first -= 2048
        if small_free and i == 3:
            first = TOTAL - (15 * 1024**3 // 512)
        last = first + length - 1
        off = i * 128
        data[off:off+16] = uuid.UUID(typ).bytes_le
        identity = 0 if duplicate_partition_guid and i == 1 else i
        data[off+16:off+32] = uuid.uuid5(
            uuid.NAMESPACE_URL, "gaslux synthetic partition " + str(identity)
        ).bytes_le
        struct.pack_into("<QQ", data, off+32, first, last)
        start = last + 1
    entries_crc = binascii.crc32(data) & 0xffffffff

    def header(this, other, array_lba):
        raw = bytearray(512)
        raw[:8] = b"EFI PART"
        struct.pack_into("<I", raw, 8, 0x10000)
        struct.pack_into("<I", raw, 12, 92)
        struct.pack_into("<QQQQ", raw, 24, this, other, 34, TOTAL-34)
        raw[56:72] = GUID
        struct.pack_into("<QIII", raw, 72, array_lba, 128, 128, entries_crc)
        struct.pack_into("<I", raw, 16, binascii.crc32(raw[:92]) & 0xffffffff)
        return raw

    front = bytearray(gpt.WINDOW_BYTES)
    back = bytearray(gpt.WINDOW_BYTES)
    front[510:512] = b"\x55\xaa"
    front[446+4] = 0xee
    # Full valid 128-GiB Windows protective MBR: LBA 1 through final LBA.
    struct.pack_into("<II", front, 446+8, 1, TOTAL-1)
    front[512:1024] = header(1, LAST, 2)
    front[2*512:34*512] = data
    back[(2048-33)*512:(2048-1)*512] = data
    back[-512:] = header(LAST, 1, TOTAL-33)
    return bytes(front), bytes(back)


class WindowsQcow2GptCandidateTests(unittest.TestCase):
    def test_qemu_img_dd_uses_count_only_for_primary_gpt_window(self):
        disk = Path("/tmp/synthetic-only.qcow2")
        front = gpt.bounded_qcow2_dd_command(
            disk, Path("/tmp/front.raw"), "front"
        )
        back = gpt.bounded_qcow2_dd_command(
            disk, Path("/tmp/back.raw"), "back"
        )
        self.assertIn("count=2048", front)
        self.assertIn("skip=0", front)
        self.assertNotIn("count=2048", back)
        self.assertIn(
            f"skip={TOTAL - gpt.WINDOW_SECTORS}", back,
        )
        self.assertEqual(front[0:5], back[0:5])
        with self.assertRaisesRegex(gpt.GeometryError, "unknown GPT window"):
            gpt.bounded_qcow2_dd_command(
                disk, Path("/tmp/sentinel.raw"), "middle"
            )

    @unittest.skipUnless(
        shutil.which("qemu-img") and shutil.which("qemu-io"),
        "native file-backed qemu-img/qemu-io test needs qemu-utils",
    )
    def test_qemu_img_dd_reads_actual_last_sector_of_sparse_qcow2(self):
        # A disposable sparse 128-GiB VIRTUAL QCOW2 has tiny host allocation.
        # No VM, host block device, network or Windows installation is used.
        with tempfile.TemporaryDirectory(prefix="gaslux-gpt-qemu-dd-") as tmp:
            root = Path(tmp)
            disk = root / "only-disposable-windows-target.qcow2"
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", str(disk), "128G"],
                check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                ["qemu-io", "-f", "qcow2",
                 "-c", "write -P 0xa5 0 512",
                 "-c", f"write -P 0x5a {gpt.VIRTUAL_BYTES - 512} 512",
                 str(disk)],
                check=True, capture_output=True, timeout=30,
            )
            raw = {}
            for suffix in ("front", "back"):
                dest = root / (suffix + ".raw")
                subprocess.run(
                    gpt.bounded_qcow2_dd_command(disk, dest, suffix),
                    check=True, capture_output=True, timeout=60,
                )
                self.assertEqual(dest.stat().st_size, gpt.WINDOW_BYTES)
                raw[suffix] = dest.read_bytes()
            self.assertEqual(raw["front"][:512], b"\xa5" * 512)
            self.assertEqual(raw["back"][-512:], b"\x5a" * 512)
            self.assertEqual(raw["back"][:512], b"\x00" * 512)

    def test_qcow2_identity_guard_accepts_unchanged_owned_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "synthetic.qcow2"
            disk.write_bytes(b"synthetic owned bytes")
            before = gpt.qcow2_file_identity(disk)
            gpt.require_unchanged_qcow2(disk, before)

    def test_qcow2_identity_guard_rejects_mutation_between_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "synthetic.qcow2"
            disk.write_bytes(b"synthetic owned bytes")
            before = gpt.qcow2_file_identity(disk)
            disk.write_bytes(b"different length and contents")
            with self.assertRaisesRegex(gpt.GeometryError, "changed during GPT audit"):
                gpt.require_unchanged_qcow2(disk, before)

    def test_qcow2_identity_guard_rejects_replacement_same_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "synthetic.qcow2"
            replacement = Path(tmp) / "replacement"
            disk.write_bytes(b"original")
            before = gpt.qcow2_file_identity(disk)
            replacement.write_bytes(b"replaced")
            replacement.replace(disk)
            with self.assertRaisesRegex(gpt.GeometryError, "changed during GPT audit"):
                gpt.require_unchanged_qcow2(disk, before)

    def test_qcow2_identity_guard_rejects_extra_hardlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "synthetic.qcow2"
            disk.write_bytes(b"original")
            before = gpt.qcow2_file_identity(disk)
            os.link(disk, Path(tmp) / "foreign-hardlink")
            with self.assertRaisesRegex(gpt.GeometryError, "exclusive regular file"):
                gpt.require_unchanged_qcow2(disk, before)

    def test_qcow2_identity_guard_rejects_symlink_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "synthetic.qcow2"
            target = Path(tmp) / "foreign"
            disk.write_bytes(b"original")
            before = gpt.qcow2_file_identity(disk)
            target.write_bytes(b"foreign")
            disk.unlink()
            disk.symlink_to(target)
            with self.assertRaisesRegex(gpt.GeometryError, "exclusive regular file"):
                gpt.require_unchanged_qcow2(disk, before)

    def test_clean_windows_gpt_and_free_extent_are_document_only(self):
        front, back = create_disk_windows()
        result = gpt.inspect_gpt_windows(front, back)
        self.assertEqual(len(result["windowsPartitions"]), 4)
        self.assertGreater(result["unallocatedAfterWindowsBytes"], 40*1024**3)
        self.assertTrue(result["candidateWindowsGptPrimaryAndBackupConsistent"])
        for key in ("windowsBootVerified", "sameDiskDualBootVerified",
                    "storageWritesAuthorized", "releaseEligible",
                    "windowsBcdWinreRestorationVerified"):
            self.assertIs(result[key], False)

    def test_primary_header_crc_tamper_refused(self):
        front, back = create_disk_windows()
        b = bytearray(front)
        b[512+48] ^= 1
        with self.assertRaisesRegex(gpt.GeometryError, "CRC mismatch"):
            gpt.inspect_gpt_windows(bytes(b), back)

    def test_backup_header_crc_tamper_refused(self):
        front, back = create_disk_windows()
        b = bytearray(back)
        b[-512+48] ^= 1
        with self.assertRaisesRegex(gpt.GeometryError, "CRC mismatch"):
            gpt.inspect_gpt_windows(front, bytes(b))

    def test_primary_array_corruption_refused(self):
        front, back = create_disk_windows()
        b = bytearray(front)
        b[2*512+36] ^= 1
        with self.assertRaisesRegex(gpt.GeometryError, "array CRC mismatch"):
            gpt.inspect_gpt_windows(bytes(b), back)

    def test_backup_array_corruption_refused(self):
        front, back = create_disk_windows()
        b = bytearray(back)
        b[-512-16384+36] ^= 1
        with self.assertRaisesRegex(gpt.GeometryError, "array CRC mismatch"):
            gpt.inspect_gpt_windows(front, bytes(b))

    def test_foreign_fifth_gpt_partition_refused_even_with_valid_crc(self):
        front, back = create_disk_windows(part_types=list(gpt.TYPES) + [gpt.TYPES[2]])
        with self.assertRaisesRegex(gpt.GeometryError, "foreign fifth"):
            gpt.inspect_gpt_windows(front, back)

    def test_duplicate_partition_guid_refused_despite_valid_crc(self):
        front, back = create_disk_windows(duplicate_partition_guid=True)
        with self.assertRaisesRegex(gpt.GeometryError, "duplicate Windows GPT"):
            gpt.inspect_gpt_windows(front, back)

    def test_protective_mbr_wrong_start_lba_refused(self):
        front, back = create_disk_windows()
        changed = bytearray(front)
        struct.pack_into("<I", changed, 446 + 8, 2)
        with self.assertRaisesRegex(gpt.GeometryError, "protective MBR geometry"):
            gpt.inspect_gpt_windows(bytes(changed), back)

    def test_protective_mbr_diagnostic_records_only_safe_structural_fields(self):
        front, back = create_disk_windows()
        changed = bytearray(front)
        struct.pack_into("<I", changed, 446 + 8, 2)
        with self.assertRaisesRegex(
            gpt.GeometryError,
            r"start_lba=2, span_lba=268435455, expected_span_lba=268435455",
        ):
            gpt.inspect_gpt_windows(bytes(changed), back)

    def test_hybrid_mbr_diagnostic_identifies_extra_slot(self):
        front, back = create_disk_windows()
        changed = bytearray(front)
        changed[446 + 16 + 4] = 0x07
        with self.assertRaisesRegex(
            gpt.GeometryError, r"unexpected_entry_slots=\\(2,\\)"
        ):
            gpt.inspect_gpt_windows(bytes(changed), back)

    def test_protective_mbr_wrong_size_refused(self):
        front, back = create_disk_windows()
        changed = bytearray(front)
        struct.pack_into("<I", changed, 446 + 12, TOTAL - 4096)
        with self.assertRaisesRegex(gpt.GeometryError, "protective MBR geometry"):
            gpt.inspect_gpt_windows(bytes(changed), back)

    def test_protective_mbr_active_flag_refused(self):
        front, back = create_disk_windows()
        changed = bytearray(front)
        changed[446] = 0x80
        with self.assertRaisesRegex(gpt.GeometryError, "protective MBR geometry"):
            gpt.inspect_gpt_windows(bytes(changed), back)

    def test_first_usable_gpt_lba_shift_refused_with_valid_crc(self):
        front, back = create_disk_windows()
        changed = bytearray(front)
        struct.pack_into("<Q", changed, 512 + 40, 2048)
        changed[512 + 16:512 + 20] = b"\x00" * 4
        crc = binascii.crc32(changed[512:512 + 92]) & 0xffffffff
        struct.pack_into("<I", changed, 512 + 16, crc)
        with self.assertRaisesRegex(gpt.GeometryError, "header addresses"):
            gpt.inspect_gpt_windows(bytes(changed), back)

    def test_last_usable_gpt_lba_truncated_with_valid_crc(self):
        front, back = create_disk_windows()
        changed = bytearray(back)
        struct.pack_into("<Q", changed, len(changed) - 512 + 48, TOTAL - 2048)
        changed[-512 + 16:-512 + 20] = b"\x00" * 4
        crc = binascii.crc32(changed[-512:-512 + 92]) & 0xffffffff
        struct.pack_into("<I", changed, len(changed) - 512 + 16, crc)
        with self.assertRaisesRegex(gpt.GeometryError, "header addresses"):
            gpt.inspect_gpt_windows(front, bytes(changed))

    def test_mbr_hybrid_partition_refused(self):
        front, back = create_disk_windows()
        b = bytearray(front)
        b[446+16+4] = 0x07
        with self.assertRaisesRegex(gpt.GeometryError, "hybrid"):
            gpt.inspect_gpt_windows(bytes(b), back)

    def test_partition_overlap_refused_even_with_matching_crc(self):
        front, back = create_disk_windows(overlap=True)
        with self.assertRaisesRegex(gpt.GeometryError, "missing, overlapping"):
            gpt.inspect_gpt_windows(front, back)

    def test_recovery_not_last_or_insufficient_free_space_refused(self):
        front, back = create_disk_windows(small_free=True)
        with self.assertRaises(gpt.GeometryError):
            gpt.inspect_gpt_windows(front, back)

    def test_ambiguity_wrong_windows_partition_type_refused(self):
        t = list(gpt.TYPES)
        t[2] = t[0]
        front, back = create_disk_windows(part_types=t)
        with self.assertRaisesRegex(gpt.GeometryError, "type/order"):
            gpt.inspect_gpt_windows(front, back)

    def test_no_real_device_or_host_escape_for_qcow2_probes(self):
        with tempfile.TemporaryDirectory() as p:
            x = Path(p) / "only-disposable-windows-target.qcow2"
            x.write_bytes(b"NOT A DISK")
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(gpt.GeometryError, "authorized hosted"):
                    gpt.inspect_owned_qcow2(x)

    def test_truncated_primary_or_backup_windows_refused(self):
        front, back = create_disk_windows()
        for value in ((front[:-1], back), (front, back[:-1])):
            with self.subTest(trunc=value[0] is front):
                with self.assertRaisesRegex(gpt.GeometryError, "missing primary or backup"):
                    gpt.inspect_gpt_windows(*value)


if __name__ == "__main__":
    unittest.main()
