"""No-media safety tests for disposable FAT32 MBR Windows answer USB.

Tests do not create or partition a disk. The separate Actions smoke explicitly
creates an owned ordinary *file* and uses mkfs/mtools only on that path.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
SPEC = importlib.util.spec_from_file_location(
    "only_partitioned_usb_builder",
    TOOLS / "windows_x64_partitioned_answer_usb.py",
)
assert SPEC and SPEC.loader
USB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(USB)


def fake_bpb():
    header = bytearray(512)
    header[510:512] = b"\x55\xaa"
    header[82:90] = b"FAT32   "
    header[71:82] = b"GASLUXCI   "
    struct.pack_into("<H", header, 11, 512)
    struct.pack_into("<I", header, 28, 2048)
    struct.pack_into("<I", header, 32, USB.PART_LBAS)
    return bytes(header)


class PartitionedUsbContracts(unittest.TestCase):
    def test_single_exact_0c_partition_at_one_megabyte(self):
        sector = USB.mbr_sector()
        self.assertEqual(len(sector), 512)
        self.assertEqual(sector[510:512], b"\x55\xaa")
        self.assertEqual(sector[446], 0)
        self.assertEqual(sector[450], 0x0c)
        self.assertEqual(struct.unpack_from("<II", sector, 454),
                         (2048, 129024))
        self.assertEqual(sector[462:510], b"\x00" * 48)
        self.assertEqual(sector[:446], b"\x00" * 446)

    def test_exact_mbr_and_fat32_bpb_pass_synthetic_bytes(self):
        USB.validate_mbr_and_bpb(USB.mbr_sector(), fake_bpb())

    def test_injected_host_drive_or_additional_partition_rejected(self):
        for at, value in ((446, 0x80), (450, 0x07),
                          (462 + 4, 0x83), (510, 0)):
            with self.subTest(byte=at):
                broken = bytearray(USB.mbr_sector())
                broken[at] = value
                with self.assertRaisesRegex(USB.PartitionedUsbError, "MBR"):
                    USB.validate_mbr_and_bpb(bytes(broken), fake_bpb())

    def test_ambiguous_partition_geometry_refused(self):
        for at, value in ((454, 1), (458, 0),
                          (458, 129025), (454, 0)):
            with self.subTest(offset=at, value=value):
                broken = bytearray(USB.mbr_sector())
                struct.pack_into("<I", broken, at, value)
                with self.assertRaises(USB.PartitionedUsbError):
                    USB.validate_mbr_and_bpb(bytes(broken), fake_bpb())

    def test_bpb_hidden_offset_label_filesystem_size_and_sector_guards(self):
        for off, payload in ((510, b"\x00\x00"),
                             (82, b"FAT16   "),
                             (71, b"FOREIGN    "),
                             (11, b"\x00\x08"),
                             (28, b"\x00\x00\x00\x00"),
                             (32, b"\x00\x00\x00\x00")):
            with self.subTest(offset=off):
                broken = bytearray(fake_bpb())
                broken[off:off + len(payload)] = payload
                with self.assertRaisesRegex(
                    USB.PartitionedUsbError, "FAT32 BPB"
                ):
                    USB.validate_mbr_and_bpb(USB.mbr_sector(), bytes(broken))

    def test_refuse_any_host_block_image_or_foreign_path_before_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml = Path(tmp) / "Autounattend.xml"
            ps = Path(tmp) / "GASLUX.PS1"
            xml.write_text("synthetic", encoding="utf-8")
            ps.write_text("synthetic", encoding="utf-8")
            for target in (
                Path("/dev/sda"),
                Path("/tmp/only-disposable-answer-usb.img"),
                Path(tmp) / "only-disposable-answer-usb.img",
            ):
                with self.subTest(target=str(target)):
                    with patch.dict(os.environ, {}, clear=True):
                        with patch.object(USB.subprocess, "run") as spawn:
                            with self.assertRaisesRegex(
                                USB.PartitionedUsbError, "hosted-runner"
                            ):
                                USB.build_partitioned_answer(target, xml, ps)
                            spawn.assert_not_called()

    def test_no_host_mount_or_unbounded_disk_operation_in_source(self):
        source = (TOOLS / "windows_x64_partitioned_answer_usb.py").read_text()
        self.assertIn('os.O_CREAT | os.O_EXCL | os.O_WRONLY', source)
        self.assertIn('stat.S_IMODE(workspace.stat().st_mode) == 0o700', source)
        self.assertIn('image.stat().st_nlink == 1', source)
        self.assertIn('"--offset=2048"', source)
        self.assertIn('str(image) + "@@1M"', source)
        self.assertIn('mbr == mbr_sector()', source)
        self.assertNotIn('"losetup"', source)
        self.assertNotIn('"mount"', source)
        self.assertNotIn('"parted"', source)


if __name__ == "__main__":
    unittest.main()
