"""Synthetic GPT header/partition array CRC gates for the Windows+Pop COW lab."""
from __future__ import annotations

import binascii
import struct
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "tools"))
from windows10_popos_gpt_mirror_gate import (  # noqa: E402
    LINUX_TYPE,
    ROOT_LABEL,
    SECTOR,
    TOTAL_BYTES,
    WINDOW_BYTES,
    WINDOWS_TYPES,
    DiskAuditError,
    parse_windows_pop_gpt,
    reconcile_windows_and_root,
)

TOTAL_LBA = TOTAL_BYTES // SECTOR
DISK_GUID = uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-ci-windows-pop-disk")


def make_pair(*, linux: bool) -> tuple[bytes, bytes, dict]:
    entries = bytearray(128 * 128)
    start = 2048
    sections = [(WINDOWS_TYPES[i], mb * 2048) for i, mb in
                enumerate((260, 16, 73728, 1536))]
    if linux:
        root_start = start + sum(n for _, n in sections) + 4096
        root_start = ((root_start + 2047) // 2048) * 2048
        sections.append((LINUX_TYPE, 24 * 1024**3 // SECTOR))
    else:
        root_start = None
    for i, (typ, size) in enumerate(sections):
        if i == 4:
            start = root_start
        end = start + size - 1
        row = bytearray(128)
        row[:16] = uuid.UUID(typ).bytes_le
        row[16:32] = uuid.uuid5(uuid.NAMESPACE_URL, f"gaslux-ci-part-{i}").bytes_le
        struct.pack_into("<QQQ", row, 32, start, end, 0)
        name = ROOT_LABEL if i == 4 else f"Windows-CI-{i+1}"
        row[56 : 56 + len(name.encode("utf-16-le"))] = name.encode("utf-16-le")
        entries[i * 128 : (i + 1) * 128] = row
        start = end + 1
    crc = binascii.crc32(entries) & 0xFFFFFFFF

    def header(current, alternate, array_lba):
        h = bytearray(SECTOR)
        h[:8] = b"EFI PART"
        struct.pack_into("<II", h, 8, 0x10000, 92)
        struct.pack_into("<QQQQ", h, 24, current, alternate, 34, TOTAL_LBA - 34)
        h[56:72] = DISK_GUID.bytes_le
        struct.pack_into("<QIII", h, 72, array_lba, 128, 128, crc)
        struct.pack_into("<I", h, 16, binascii.crc32(h[:92]) & 0xFFFFFFFF)
        return h

    front = bytearray(WINDOW_BYTES)
    back = bytearray(WINDOW_BYTES)
    front[510:512] = b"\x55\xaa"
    front[446 + 4] = 0xEE
    struct.pack_into("<II", front, 446 + 8, 1, min(TOTAL_LBA - 1, 0xFFFFFFFF))
    front[SECTOR : 2 * SECTOR] = header(1, TOTAL_LBA-1, 2)
    front[2*SECTOR : 34*SECTOR] = entries
    back[WINDOW_BYTES-33*SECTOR : WINDOW_BYTES-SECTOR] = entries
    back[-SECTOR:] = header(TOTAL_LBA-1, 1, TOTAL_LBA-33)
    plan = {
        "startSector": root_start,
        "endSector": start-1 if linux else None,
        "sizeBytes": 24 * 1024**3,
    }
    return bytes(front), bytes(back), plan


def with_foreign_utf16_label(
    front: bytes, back: bytes, *, index: int,
) -> tuple[bytes, bytes]:
    """Change one GPT label to a lone surrogate, fixing both table/header CRCs."""
    assert 1 <= index <= 5
    primary, backup = bytearray(front), bytearray(back)
    entries = bytearray(primary[2*SECTOR:34*SECTOR])
    # UTF-16LE lone high surrogate in a validly mirrored, CRC-protected row.
    off = (index-1)*128 + 56 + 48
    entries[off:off+2] = b"\x00\xd8"
    crc = binascii.crc32(entries) & 0xFFFFFFFF
    primary[2*SECTOR:34*SECTOR] = entries
    backup[WINDOW_BYTES-33*SECTOR:WINDOW_BYTES-SECTOR] = entries
    for page, offset in ((primary, SECTOR), (backup, WINDOW_BYTES-SECTOR)):
        struct.pack_into("<I", page, offset+88, crc)
        struct.pack_into("<I", page, offset+16, 0)
        struct.pack_into("<I", page, offset+16,
                         binascii.crc32(page[offset:offset+92]) & 0xFFFFFFFF)
    return bytes(primary), bytes(backup)


class TestGptCrcReconciliation(unittest.TestCase):
    def test_foreign_windows_name_is_opaque_but_crc_and_raw_entry_are_bound(self):
        front, back, _ = make_pair(linux=False)
        modified_front, modified_back = with_foreign_utf16_label(
            front, back, index=3,
        )
        original = parse_windows_pop_gpt(front, back, expected_count=4)
        altered = parse_windows_pop_gpt(
            modified_front, modified_back, expected_count=4,
        )
        self.assertTrue(altered["primaryAndBackupCrcVerified"])
        self.assertNotEqual(
            altered["windowsEntryHex"][2], original["windowsEntryHex"][2],
        )
        self.assertIs(altered["productionInstallationAuthorized"], False)
        next_front, next_back, plan = make_pair(linux=True)
        next_stage = parse_windows_pop_gpt(
            next_front, next_back, expected_count=5,
        )
        with self.assertRaisesRegex(DiskAuditError, "foreign GPT identity"):
            reconcile_windows_and_root(altered, next_stage, plan)

    def test_invalid_owned_pop_root_label_is_rejected_even_with_valid_crc(self):
        front, back, _ = make_pair(linux=True)
        modified_front, modified_back = with_foreign_utf16_label(
            front, back, index=5,
        )
        with self.assertRaisesRegex(DiskAuditError, "invalid owned Pop GPT label"):
            parse_windows_pop_gpt(
                modified_front, modified_back, expected_count=5,
            )


    def test_before_and_after_two_headers_and_crc_are_valid(self):
        front, back, _ = make_pair(linux=False)
        prior = parse_windows_pop_gpt(front, back, expected_count=4)
        f2, b2, plan = make_pair(linux=True)
        staged = parse_windows_pop_gpt(f2, b2, expected_count=5)
        reconcile_windows_and_root(prior, staged, plan)
        self.assertTrue(staged["primaryAndBackupCrcVerified"])
        self.assertIs(staged["productionInstallationAuthorized"], False)

    def test_reject_header_primary_backup_and_array_crc_corruption(self):
        f, b, _ = make_pair(linux=True)
        for region, offset in (("front", SECTOR + 48), ("back", WINDOW_BYTES - SECTOR + 48),
                               ("front", 2*SECTOR + 40),
                               ("back", WINDOW_BYTES - 33*SECTOR + 40)):
            with self.subTest(region=region, offset=offset):
                x, y = bytearray(f), bytearray(b)
                if region == "front":
                    x[offset] ^= 1
                else:
                    y[offset] ^= 1
                with self.assertRaisesRegex(DiskAuditError, "CRC mismatch"):
                    parse_windows_pop_gpt(bytes(x), bytes(y), expected_count=5)

    def test_exact_real_windows_oversized_pmbr_is_lab_only(self):
        before_front, before_back, _ = make_pair(linux=False)
        after_front, after_back, plan = make_pair(linux=True)
        modified = []
        for source in (before_front, after_front):
            mbr = bytearray(source)
            struct.pack_into("<I", mbr, 446+12, 0xFFFFFFFF)
            modified.append(bytes(mbr))
        before = parse_windows_pop_gpt(modified[0], before_back, expected_count=4)
        after = parse_windows_pop_gpt(modified[1], after_back, expected_count=5)
        reconcile_windows_and_root(before, after, plan)
        self.assertFalse(before["protectiveMbrCanonical"])
        self.assertTrue(before["oversizedWindowsPmbrLabOnly"])
        self.assertIs(before["productionInstallationAuthorized"], False)
        for damaged_count in (0xFFFFFFFE, 12345, 0):
            with self.subTest(count=damaged_count):
                invalid = bytearray(before_front)
                struct.pack_into("<I", invalid, 446+12, damaged_count)
                with self.assertRaises(DiskAuditError):
                    parse_windows_pop_gpt(bytes(invalid), before_back, expected_count=4)

    def test_reject_hybrid_mbr_and_truncated_windows(self):
        f, b, _ = make_pair(linux=False)
        x = bytearray(f)
        x[446 + 16 + 4] = 7
        with self.assertRaises(DiskAuditError):
            parse_windows_pop_gpt(bytes(x), b, expected_count=4)
        with self.assertRaises(DiskAuditError):
            parse_windows_pop_gpt(f[:-1], b, expected_count=4)

    def test_reject_unplanned_fifth_and_unknown_windows_mutation(self):
        f, b, _ = make_pair(linux=True)
        with self.assertRaises(DiskAuditError):
            parse_windows_pop_gpt(f, b, expected_count=4)
        f0, b0, _ = make_pair(linux=False)
        before = parse_windows_pop_gpt(f0, b0, expected_count=4)
        after = parse_windows_pop_gpt(f, b, expected_count=5)
        with self.assertRaises(DiskAuditError):
            reconcile_windows_and_root(before, after,
                                       {"startSector": after["linuxRoot"]["startLba"] + 2048,
                                        "endSector": after["linuxRoot"]["endLba"],
                                        "sizeBytes": 24*1024**3})
        altered = dict(after)
        altered["windowsEntryHex"] = list(after["windowsEntryHex"])
        altered["windowsEntryHex"][1] = "z" * 256
        with self.assertRaises(DiskAuditError):
            reconcile_windows_and_root(before, altered,
                                       {"startSector": after["linuxRoot"]["startLba"],
                                        "endSector": after["linuxRoot"]["endLba"],
                                        "sizeBytes": 24*1024**3})


if __name__ == "__main__":
    unittest.main()
