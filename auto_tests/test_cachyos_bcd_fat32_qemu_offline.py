"""Adversarial offline FAT32/BCD/QEMU geometry tests; synthetic bytes only."""
from __future__ import annotations

import copy
import hashlib
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import cachyos_bcd_fat32_offline as fat
import cachyos_bcd_qemu_trace_offline as trace

TOTAL_SECTORS = 69300
RESERVED = 32
FAT_SECTORS = 545
FIRST_DATA = RESERVED + 2 * FAT_SECTORS
ESP_LBA = 2048
DISK_BYTES = 128 * 1024**3
ESP_END = ESP_LBA + TOTAL_SECTORS - 1


def p16(data: bytearray, off: int, value: int) -> None:
    struct.pack_into("<H", data, off, value)


def p32(data: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", data, off, value)


def short_entry(name: str, clus: int, *, directory: bool,
                size: int = 0) -> bytes:
    assert len(name) == 11
    buf = bytearray(32)
    buf[:11] = name.encode("ascii")
    buf[11] = 0x10 if directory else 0x20
    p16(buf, 20, clus >> 16)
    p16(buf, 26, clus & 0xFFFF)
    p32(buf, 28, size)
    return bytes(buf)


def checksum(name: bytes) -> int:
    result = 0
    for byte in name:
        result = (((result & 1) << 7) | (result >> 1)) + byte
        result &= 255
    return result


def lfn_entry(text: str, alias: bytes) -> bytes:
    units = [ord(c) for c in text] + [0]
    units += [0xFFFF] * (13 - len(units))
    e = bytearray(32)
    e[0] = 0x41
    e[11] = 0x0F
    e[13] = checksum(alias)
    for field, portion in ((1, units[:5]), (14, units[5:11]),
                           (28, units[11:13])):
        struct.pack_into("<" + "H" * len(portion), e, field, *portion)
    return bytes(e)


def cluster_sector(cluster: int) -> int:
    return FIRST_DATA + cluster - 2


def make_fat32(*, fragmented: bool = False) -> bytes:
    """Create a spec-shaped >=65,525-cluster FAT32 ESP, never an installed disk."""
    volume = bytearray(TOTAL_SECTORS * fat.SECTOR)
    boot = bytearray(512)
    boot[:3] = b"\xeb\x58\x90"
    p16(boot, 11, 512)
    boot[13] = 1
    p16(boot, 14, RESERVED)
    boot[16] = 2
    p32(boot, 32, TOTAL_SECTORS)
    p32(boot, 36, FAT_SECTORS)
    p32(boot, 44, 2)
    p16(boot, 48, 1)
    p16(boot, 50, 6)
    boot[510:512] = b"\x55\xaa"
    volume[:512] = boot
    volume[6 * 512:7 * 512] = boot
    fsinfo = bytearray(512)
    p32(fsinfo, 0, 0x41615252)
    p32(fsinfo, 484, 0x61417272)
    p32(fsinfo, 488, 0xFFFFFFFF)
    p32(fsinfo, 492, 0xFFFFFFFF)
    p32(fsinfo, 508, 0xAA550000)
    volume[512:1024] = fsinfo
    volume[7 * 512:8 * 512] = fsinfo

    chain = [6,15,7,16,8,17,9,18] if fragmented else list(range(6, 14))
    table = bytearray(FAT_SECTORS * 512)
    p32(table, 0, 0x0FFFFFF8)
    p32(table, 4, 0x0FFFFFFF)
    for cluster in (2, 3, 4, 5):
        p32(table, cluster * 4, 0x0FFFFFFF)
    for i, clus in enumerate(chain):
        p32(table, clus * 4,
            chain[i + 1] if i + 1 < len(chain) else 0x0FFFFFFF)
    for start in (RESERVED, RESERVED + FAT_SECTORS):
        volume[start * 512:(start + FAT_SECTORS) * 512] = table

    def dir_at(cluster: int, entries: list[bytes]) -> None:
        base = cluster_sector(cluster) * 512
        for i, e in enumerate(entries):
            volume[base + 32 * i:base + 32 * (i + 1)] = e

    dir_at(2, [short_entry("EFI        ", 3, directory=True)])
    alias = b"MICROS~1   "
    dir_at(3, [lfn_entry("Microsoft", alias),
               short_entry("MICROS~1   ", 4, directory=True)])
    dir_at(4, [short_entry("BOOT       ", 5, directory=True)])
    dir_at(5, [short_entry("BCD        ", chain[0],
                           directory=False, size=4096)])
    for i, clus in enumerate(chain):
        base = cluster_sector(clus) * 512
        volume[base:base + 512] = bytes([65 + i]) * 512
    return bytes(volume)


def mapping(image: bytes) -> dict:
    return fat.map_bcd_fat32(
        image, esp_start_lba=ESP_LBA, esp_end_lba=ESP_END,
        disk_bytes=DISK_BYTES,
    )


class Fat32OfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contiguous = make_fat32()
        cls.fragmented = make_fat32(fragmented=True)

    def test_contiguous_bcd_map(self):
        m = mapping(self.contiguous)
        self.assertEqual(m["status"], "FAT32_STRUCTURAL_MAP_ONLY")
        self.assertFalse(m["imageProvenanceAuthenticated"])
        self.assertFalse(m["bcdFragmented"])
        self.assertEqual(len(m["bcdDataExtents"]), 8)
        self.assertEqual(m["bcdSizeBytes"], 4096)
        self.assertEqual(m["bcdDataExtents"][0]["cluster"], 6)
        self.assertEqual(m["bcdDataExtents"][0]["fileOffset"], 0)
        self.assertEqual(
            m["bcdDataExtents"][0]["diskOffset"],
            (ESP_LBA + cluster_sector(6)) * 512,
        )
        self.assertTrue(all(ESP_LBA * 512 <= e["diskOffset"]
                            < (ESP_END + 1) * 512
                            for e in m["bcdDataExtents"]))

    def test_fragmented_bcd_map(self):
        m = mapping(self.fragmented)
        self.assertTrue(m["bcdFragmented"])
        self.assertEqual([e["cluster"] for e in m["bcdDataExtents"]],
                         [6,15,7,16,8,17,9,18])

    def test_fat_cycle_fails_closed(self):
        b = bytearray(self.contiguous)
        for start in (RESERVED, RESERVED + FAT_SECTORS):
            p32(b, start * 512 + 7 * 4, 6)
        with self.assertRaisesRegex(fat.Fat32MapError, "cycle"):
            mapping(bytes(b))

    def test_out_of_range_fat_cluster_refused(self):
        b = bytearray(self.contiguous)
        for start in (RESERVED, RESERVED + FAT_SECTORS):
            p32(b, start * 512 + 6 * 4, 0x0FFFFFF7)
        with self.assertRaisesRegex(fat.Fat32MapError, "bad"):
            mapping(bytes(b))

    def test_bcd_truncated_chain_refused(self):
        b = bytearray(self.contiguous)
        for start in (RESERVED, RESERVED + FAT_SECTORS):
            p32(b, start * 512 + 7 * 4, 0x0FFFFFFF)
        with self.assertRaisesRegex(fat.Fat32MapError, "truncated"):
            mapping(bytes(b))

    def test_fat_copies_disagree_refused(self):
        b = bytearray(self.contiguous)
        b[(RESERVED + FAT_SECTORS) * 512 + 6 * 4] ^= 1
        with self.assertRaisesRegex(fat.Fat32MapError, "FAT copies differ"):
            mapping(bytes(b))

    def test_invalid_fsinfo_and_bpb_refused(self):
        b = bytearray(self.contiguous)
        b[512] ^= 1
        with self.assertRaisesRegex(fat.Fat32MapError, "FSInfo"):
            mapping(bytes(b))
        b = bytearray(self.contiguous)
        p16(b, 11, 4096)
        with self.assertRaisesRegex(fat.Fat32MapError, "boot sector"):
            mapping(bytes(b))

    def test_volume_truncation_and_wrong_partition_geometry(self):
        with self.assertRaisesRegex(fat.Fat32MapError, "length"):
            mapping(self.contiguous[:-512])
        with self.assertRaisesRegex(fat.Fat32MapError, "geometry"):
            fat.map_bcd_fat32(self.contiguous, esp_start_lba=ESP_LBA,
                             esp_end_lba=ESP_END, disk_bytes=1024)

    def test_ambiguous_bcd_names_are_refused(self):
        b = bytearray(self.contiguous)
        base = cluster_sector(5) * 512
        b[base + 32:base + 64] = short_entry(
            "BCD        ", 6, directory=False, size=4096)
        with self.assertRaisesRegex(fat.Fat32MapError, "ambiguous"):
            mapping(bytes(b))

    def test_bad_vfat_checksum_refused(self):
        b = bytearray(self.contiguous)
        base = cluster_sector(3) * 512
        b[base + 13] ^= 1
        with self.assertRaisesRegex(fat.Fat32MapError, "checksum"):
            mapping(bytes(b))

    def test_absent_authenticated_esp_is_unavailable(self):
        self.assertEqual(
            fat.historical_mapping_unavailable()["status"],
            "BCD_PHYSICAL_MAPPING_UNAVAILABLE",
        )

    def test_qemu_partial_bcd_and_fat_metadata_separate(self):
        m = mapping(self.fragmented)
        bcd = m["bcdDataExtents"][0]["diskOffset"]
        fat_offset = (ESP_LBA + RESERVED) * 512
        other = (ESP_LBA + FIRST_DATA + 400) * 512
        rows = [
            "blk_co_pwritev blk 0xa1 bs 0xbb offset " +
            str(bcd + 120) + " bytes 28 flags 0x0",
            "blk_co_pwritev blk 0xa1 bs 0xbb offset " +
            str(fat_offset + 16) + " bytes 64 flags 0x0",
            "blk_co_pwritev blk 0xa1 bs 0xbb offset " +
            str(other) + " bytes 512 flags 0x0",
            "blk_co_pwritev blk 0xc2 bs 0xbb offset " +
            str(bcd) + " bytes 512 flags 0x0",
            "qcow2_writev_done_req co 0xdd ret 0",
        ]
        raw = ("\n".join(rows) + "\n").encode("ascii")
        parsed = trace.parse_qemu_trace(raw)
        synthetic = {
            "scope": "SYNTHETIC_FIXTURE_ONLY",
            "blkPointer": "0xa1",
            "traceSha256": hashlib.sha256(raw).hexdigest(),
        }
        result = trace.correlate_qemu_writes(
            parsed, disk_bytes=DISK_BYTES,
            esp_start_lba=ESP_LBA, esp_end_lba=ESP_END,
            fat32_map=m, synthetic_fixture_binding=synthetic,
        )
        self.assertEqual(result["status"],
                         "SYNTHETIC_GEOMETRY_CLASSIFIED_NOT_ATTESTED")
        self.assertEqual(result["espCandidateWriteCount"], 4)
        counts = result["classificationCounts"]
        self.assertEqual(counts["BCD_DATA_SECTOR_OVERLAP"], 1)
        self.assertEqual(counts["FAT32_METADATA_OVERLAP"], 1)
        self.assertEqual(counts["ESP_OTHER_SECTOR_OVERLAP"], 1)
        self.assertEqual(counts["UNMAPPED_ESP_WRITE"], 1)
        self.assertEqual(counts["PROCESS_UNATTRIBUTED"], 4)
        self.assertFalse(result["bcdModificationConfirmed"])
        self.assertFalse(result["processAttributionProven"])
        no_identity = trace.correlate_qemu_writes(
            parsed, disk_bytes=DISK_BYTES,
            esp_start_lba=ESP_LBA, esp_end_lba=ESP_END, fat32_map=m,
        )
        self.assertEqual(no_identity["classificationCounts"],
                         {"PROCESS_UNATTRIBUTED": 4, "UNMAPPED_ESP_WRITE": 4})
        self.assertFalse(no_identity["qemuBlkNodeToDiskAuthenticated"])

    def test_trace_invalid_offset_malformed_line_and_missing_newline(self):
        good = b"blk_co_pwritev blk 0x1 bs 0x2 offset 1024 bytes 512 flags 0x0\n"
        for sample in (
            good[:-1],
            b"blk_co_pwritev blk 0x1 bs 0x2 offset -1 bytes 512 flags 0x0\n",
            b"blk_co_pwritev blk 0x1 bs 0x2 offset 0 bytes 0 flags 0x0\n",
            b"blk_co_pwritev blk 0x1 bs 0x2 offset 0 bytes 99999999 flags 0x0\n",
            b"not_a_qemu_event something\n",
        ):
            with self.subTest(raw=sample[:50]):
                with self.assertRaises(trace.QemuTraceError):
                    trace.parse_qemu_trace(sample)

    def test_untrusted_node_binding_rejected_and_timestamps_absent(self):
        raw = b"blk_co_pwritev blk 0x1 bs 0x2 offset 1048576 bytes 512 flags 0x0\n"
        parsed = trace.parse_qemu_trace(raw)
        self.assertFalse(parsed["timestampsPresent"])
        with self.assertRaisesRegex(trace.QemuTraceError, "binding"):
            trace.correlate_qemu_writes(
                parsed, disk_bytes=DISK_BYTES,
                esp_start_lba=ESP_LBA, esp_end_lba=ESP_END,
                synthetic_fixture_binding={
                    "scope": "TRUST_ME", "blkPointer": "0x1",
                    "traceSha256": parsed["traceSha256"],
                },
            )
        unknown = trace.correlate_qemu_writes(
            parsed, disk_bytes=DISK_BYTES,
            esp_start_lba=ESP_LBA, esp_end_lba=ESP_END,
        )
        self.assertEqual(unknown["status"], "UNMAPPED_ESP_WRITE")

    def test_fatmap_esp_identity_mismatch_rejected(self):
        m = mapping(self.contiguous)
        bad = copy.deepcopy(m)
        bad["espStartLba"] += 1
        p = trace.parse_qemu_trace(
            b"blk_co_pwritev blk 0x1 bs 0x2 offset 1048576 bytes 512 flags 0x0\n")
        with self.assertRaisesRegex(trace.QemuTraceError, "geometry"):
            trace.correlate_qemu_writes(
                p, disk_bytes=DISK_BYTES,
                esp_start_lba=ESP_LBA, esp_end_lba=ESP_END,
                fat32_map=bad,
            )


if __name__ == "__main__":
    unittest.main()
