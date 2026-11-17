"""Synthetic Windows-like GPT only; negative tests before hosted COW writes."""
import binascii
import importlib.util
import os
from pathlib import Path
import struct
import sys
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "tools"))
from test_windows_cachyos_qcow2_gpt_readonly import create_disk_windows
import windows_cachyos_overlay_gpt_stage as stage
import windows_cachyos_qcow2_gpt_readonly as gpt

GUID = uuid.UUID("48a33c62-c391-486f-b0f8-b6637f0bced0")


class OverlayOnlyLinuxPartitionTests(unittest.TestCase):
    def test_stage_fifth_unformatted_24gib_after_windows_recovery(self):
        front, back = create_disk_windows()
        updated_front, updated_back, part = stage.build_linux_root_entry(
            front, back, GUID,
        )
        self.assertEqual(part["index"], 5)
        self.assertEqual(part["typeGuid"], stage.LINUX_TYPE)
        self.assertEqual(part["uniqueGuid"], str(GUID))
        self.assertEqual(part["lengthBytes"], 24*1024**3)
        self.assertEqual(part["firstLba"] % 2048, 0)
        self.assertGreaterEqual(
            part["remainingUnallocatedAfterLinuxBytes"], 16*1024**3,
        )
        self.assertEqual(updated_front[:512], front[:512])
        self.assertEqual(updated_front[2048*512:], front[2048*512:])
        self.assertEqual(updated_back[:(2048-33)*512], back[:(2048-33)*512])
        self.assertEqual(updated_front[1024:1024+4*128],
                         front[1024:1024+4*128])
        self.assertNotEqual(updated_front, front)
        self.assertNotEqual(updated_back, back)
        stage.verify_linux_root_layout(
            front, back, updated_front, updated_back,
            part["firstLba"], part["lastLba"], GUID,
        )

    def test_zero_uuid_or_invalid_identity_refused(self):
        front, back = create_disk_windows()
        for guid in (uuid.UUID(int=0), str(GUID), None):
            with self.subTest(guid=guid):
                with self.assertRaisesRegex(stage.OverlayLayoutError,
                                            "GUID required"):
                    stage.build_linux_root_entry(front, back, guid)

    def test_duplicate_linux_partition_must_fail_closed(self):
        front, back = create_disk_windows()
        staged_front, staged_back, _ = stage.build_linux_root_entry(
            front, back, GUID,
        )
        with self.assertRaises(gpt.GeometryError):
            stage.build_linux_root_entry(staged_front, staged_back, GUID)

    def test_modified_mbr_rejected_even_with_valid_gpt(self):
        front, back = create_disk_windows()
        tampered = bytearray(front)
        tampered[446 + 16 + 4] = 0x07
        with self.assertRaisesRegex(gpt.GeometryError, "hybrid"):
            stage.build_linux_root_entry(bytes(tampered), back, GUID)

    def test_crc_mismatch_rejected_before_any_write(self):
        front, back = create_disk_windows()
        tampered = bytearray(back)
        tampered[-512+42] ^= 1
        with self.assertRaisesRegex(gpt.GeometryError, "CRC mismatch"):
            stage.build_linux_root_entry(front, bytes(tampered), GUID)

    def test_outside_gpt_windows_changes_refused_after_stage(self):
        front, back = create_disk_windows()
        nf, nb, partition = stage.build_linux_root_entry(front, back, GUID)
        changed = bytearray(nf)
        changed[524288] ^= 1
        with self.assertRaisesRegex(stage.OverlayLayoutError,
                                    "outside GPT metadata"):
            stage.verify_linux_root_layout(
                front, back, bytes(changed), nb,
                partition["firstLba"], partition["lastLba"], GUID,
            )

    def test_windows_record_mutation_refused(self):
        front, back = create_disk_windows()
        nf, nb, partition = stage.build_linux_root_entry(front, back, GUID)
        changed = bytearray(nf)
        changed[2*512+4*128-1] ^= 1
        with self.assertRaises((stage.OverlayLayoutError, gpt.GeometryError)):
            stage.verify_linux_root_layout(
                front, back, bytes(changed), nb,
                partition["firstLba"], partition["lastLba"], GUID,
            )

    def test_backup_entry_crc_mutation_refused(self):
        front, back = create_disk_windows()
        nf, nb, partition = stage.build_linux_root_entry(front, back, GUID)
        changed = bytearray(nb)
        changed[-512-16*1024+400] ^= 1
        with self.assertRaisesRegex(gpt.GeometryError, "array CRC mismatch"):
            stage.verify_linux_root_layout(
                front, back, nf, bytes(changed),
                partition["firstLba"], partition["lastLba"], GUID,
            )

    def test_guid_mismatch_is_rejected(self):
        front, back = create_disk_windows()
        nf, nb, partition = stage.build_linux_root_entry(front, back, GUID)
        with self.assertRaisesRegex(stage.OverlayLayoutError, "identity"):
            stage.verify_linux_root_layout(
                front, back, nf, nb,
                partition["firstLba"], partition["lastLba"], uuid.uuid4(),
            )

    def test_not_enough_unallocated_space_refused(self):
        front, back = create_disk_windows(small_free=True)
        with self.assertRaises((gpt.GeometryError, stage.OverlayLayoutError)):
            stage.build_linux_root_entry(front, back, GUID)

    def test_saturated_protective_mbr_is_read_only_compatible(self):
        front, back = create_disk_windows()
        modified = bytearray(front)
        struct.pack_into("<I", modified, 446+12, 0xffffffff)
        nf, nb, info = stage.build_linux_root_entry(bytes(modified), back, GUID)
        self.assertEqual(nf[446+12:446+16], b"\xff"*4)
        self.assertEqual(info["lengthBytes"], stage.LINUX_SIZE_BYTES)

    def test_never_open_guestfs_if_not_explicitly_authorized(self):
        front, back = create_disk_windows()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(stage.OverlayLayoutError,
                                        "separate explicit"):
                stage.stage_overlay_gpt(
                    Path("/tmp/foreign.qcow2"),
                    Path("/tmp/ovmf-variables.fd"), {},
                    {}, GUID,
                )

    def test_no_host_storage_calls_or_fs_format_operations(self):
        code = (HERE/"tools/windows_cachyos_overlay_gpt_stage.py").read_text()
        for token in ("mkfs.", "mkfs_", "parted", "sgdisk", "qemu-nbd",
                      "subprocess.Popen", "mount_local", "mount(", "wipefs"):
            with self.subTest(forbidden=token):
                self.assertNotIn(token, code)
        self.assertIn("guest.pwrite_device", code)
        self.assertIn("guest.blockdev_getsize64", code)
        self.assertIn("qcow2_file_identity", code)


if __name__ == "__main__":
    unittest.main()
