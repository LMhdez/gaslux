"""Actual raw primary/backup GPT byte contracts from synthetic Windows COW.

Uses only two in-memory 1 MiB windows. No block devices, installer or pacstrap.
"""
from __future__ import annotations

import binascii
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock
import uuid
import stat

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/"tools"))
from test_windows_cachyos_qcow2_gpt_readonly import create_disk_windows
from test_cachyos_windows_shared_archiso_handoff import fixture
import cachyos_windows_shared_gpt_raw_audit as inspect
import windows_cachyos_qcow2_gpt_readonly as gpt
import windows_cachyos_overlay_gpt_stage as stage


LINUX_GUID=uuid.UUID("48a33c62-c391-486f-b0f8-b6637f0bced0")


def real_gpt_windows():
    front,back=create_disk_windows()
    final_front,final_back,entry=stage.build_linux_root_entry(
        front,back,LINUX_GUID)
    plan=fixture()
    p=[]
    entries=final_front[1024:1024+5*128]
    for n in range(5):
        raw=entries[n*128:(n+1)*128]
        first,last=struct.unpack_from("<QQ",raw,32)
        p.append({
            "index":n+1,"role":inspect_order(n),
            "typeGuid":str(uuid.UUID(bytes_le=raw[:16])),
            "uniqueGuid":str(uuid.UUID(bytes_le=raw[16:32])),
            "firstLba":first,"lastLba":last,
        })
    plan["partitions"]=p
    plan["diskGuidSha256"]=hashlib.sha256(
        final_front[512+56:512+72]).hexdigest()
    plan["gptWindowsSha256"]=hashlib.sha256(
        final_front+final_back).hexdigest()
    return final_front,final_back,plan


def inspect_order(n):
    return ("esp","msr","windows","recovery","cachyos-root")[n]


def rewrite_array(front,back,index,payload):
    primary=bytearray(front)
    backup=bytearray(back)
    offset=1024+index*128
    primary[offset:offset+128]=payload
    arr=primary[1024:1024+128*128]
    back_start=gpt.WINDOW_BYTES-33*512
    backup[back_start:back_start+128*128]=arr
    crc=binascii.crc32(arr)&0xffffffff
    primary[512:1024]=stage.update_crc(primary[512:1024],crc)
    backup[-512:]=stage.update_crc(backup[-512:],crc)
    return bytes(primary),bytes(backup)


class RealReadOnlyGptWindowsTests(unittest.TestCase):
    def test_byte_exact_shared_gpt_and_mirrored_crc_valid(self):
        first,last,plan=real_gpt_windows()
        output=inspect.inspect_bound_gpt_windows(first,last,plan)
        self.assertTrue(output["actualPrimaryBackupGptCrcAndWindowsPartitionsVerified"])
        self.assertTrue(output["actualGptWindowsBoundToSignedWindowSha256"])
        for key in ("pacstrapAuthorized","storageWritesAuthorized",
                    "sameDiskDualBootVerified","releaseEligible"):
            self.assertFalse(output[key])

    def test_each_window_is_bound_beyond_crc_checked_metadata(self):
        first,last,plan=real_gpt_windows()
        for target in ("front","back"):
            a,b=bytearray(first),bytearray(last)
            if target=="front":
                a[-1]^=1
            else:
                b[0]^=1
            with self.subTest(target=target), self.assertRaisesRegex(
                    inspect.SharedDiskHandoffRejected,"window bytes"):
                inspect.inspect_bound_gpt_windows(bytes(a),bytes(b),plan)

    def test_recomputed_window_hash_cannot_hide_primary_header_crc_error(self):
        front,back,plan=real_gpt_windows()
        altered=bytearray(front)
        altered[512+40]^=1
        plan["gptWindowsSha256"]=hashlib.sha256(bytes(altered)+back).hexdigest()
        with self.assertRaises(gpt.GeometryError):
            inspect.inspect_bound_gpt_windows(bytes(altered),back,plan)

    def test_fifth_guid_mutation_with_valid_both_crc_still_rejected(self):
        front,back,plan=real_gpt_windows()
        original=bytearray(front[1024+4*128:1024+5*128])
        original[16:32]=uuid.UUID(
            "11111111-2222-4333-8444-555555555555").bytes_le
        modified_front,modified_back=rewrite_array(front,back,4,original)
        plan["gptWindowsSha256"]=hashlib.sha256(
            modified_front+modified_back).hexdigest()
        with self.assertRaisesRegex(
                inspect.SharedDiskHandoffRejected,"GPT entry differs"):
            inspect.inspect_bound_gpt_windows(modified_front,modified_back,plan)

    def test_sixth_partition_with_valid_mirror_crc_is_always_rejected(self):
        front,back,plan=real_gpt_windows()
        extra=bytearray(128)
        extra[:16]=uuid.UUID(stage.LINUX_TYPE).bytes_le
        extra[16:32]=uuid.UUID(
            "11111111-2222-4333-8444-555555555555").bytes_le
        struct.pack_into("<QQ",extra,32,plan["partitions"][4]["lastLba"]+2048,
                         plan["partitions"][4]["lastLba"]+4095)
        a,b=rewrite_array(front,back,5,extra)
        plan["gptWindowsSha256"]=hashlib.sha256(a+b).hexdigest()
        with self.assertRaisesRegex(
                inspect.SharedDiskHandoffRejected,"sixth"):
            inspect.inspect_bound_gpt_windows(a,b,plan)

    def test_hybrid_mbr_rejected_even_if_signed_window_digest_updated(self):
        front,back,plan=real_gpt_windows()
        first=bytearray(front)
        first[446+16+4]=0x07
        plan["gptWindowsSha256"]=hashlib.sha256(bytes(first)+back).hexdigest()
        with self.assertRaisesRegex(
                inspect.SharedDiskHandoffRejected,"hybrid"):
            inspect.inspect_bound_gpt_windows(bytes(first),back,plan)

    def test_readonly_raw_audit_never_accepts_a_partition_device_path(self):
        # Reject before stat/open/ioctl, even if lsblk claims the device exists.
        for forbidden in ("/dev/vdb1", "/dev/vda5", "/dev/vdaa1",
                          "/dev/vdb-1", "/dev/nvme0n1"):
            with self.subTest(device=forbidden), self.assertRaisesRegex(
                    inspect.SharedDiskHandoffRejected, "virtio"):
                inspect.read_guest_disk_windows_readonly(Path(forbidden))

    def test_raw_disk_geometry_must_match_before_any_gpt_read(self):
        # All kernel responses are mocked. No /dev node is opened in this test.
        for size, sector in ((64 * 1024**3, 512),
                             (128 * 1024**3, 4096)):
            def ioctl(_fd, command, _buffer):
                if command == 0x80081272:
                    return struct.pack("=Q", size)
                if command == 0x1268:
                    return struct.pack("=I", sector)
                raise AssertionError("unexpected ioctl")

            with self.subTest(size=size, sector=sector), \
                 mock.patch.object(Path, "stat", return_value=mock.Mock(
                     st_mode=stat.S_IFBLK, st_rdev=123)), \
                 mock.patch.object(inspect.os, "open", return_value=9), \
                 mock.patch.object(inspect.os, "fstat", return_value=mock.Mock(
                     st_rdev=123)), \
                 mock.patch.object(inspect.os, "close"), \
                 mock.patch.object(inspect.fcntl, "ioctl", side_effect=ioctl), \
                 mock.patch.object(inspect.os, "pread") as pread:
                with self.assertRaisesRegex(
                        inspect.SharedDiskHandoffRejected,
                        "size or logical sector"):
                    inspect.read_guest_disk_windows_readonly(Path("/dev/vdb"))
                pread.assert_not_called()

    def test_matching_geometry_allows_two_bounded_read_only_windows(self):
        # This verifies the Linux ioctl contract without a host block device.
        payload = b"X" * gpt.WINDOW_BYTES
        def ioctl(_fd, command, _buffer):
            return (struct.pack("=Q", 128 * 1024**3)
                    if command == 0x80081272
                    else struct.pack("=I", 512))
        with mock.patch.object(Path, "stat", return_value=mock.Mock(
                 st_mode=stat.S_IFBLK, st_rdev=123)), \
             mock.patch.object(inspect.os, "open", return_value=9) as opener, \
             mock.patch.object(inspect.os, "fstat", return_value=mock.Mock(
                 st_rdev=123)), \
             mock.patch.object(inspect.os, "close"), \
             mock.patch.object(inspect.fcntl, "ioctl", side_effect=ioctl), \
             mock.patch.object(inspect.os, "pread", return_value=payload) as pread:
            front, back = inspect.read_guest_disk_windows_readonly(Path("/dev/vdb"))
            self.assertEqual((front, back), (payload, payload))
            self.assertEqual(pread.call_count, 2)
            self.assertEqual(opener.call_args.args[0], Path("/dev/vdb"))
            flags = opener.call_args.args[1]
            self.assertEqual(flags & (inspect.os.O_WRONLY | inspect.os.O_RDWR), 0)
            self.assertNotEqual(flags & inspect.os.O_NOFOLLOW, 0)

    def test_real_host_files_and_character_devices_not_accepted(self):
        with self.assertRaisesRegex(
                inspect.SharedDiskHandoffRejected,"virtio"):
            inspect.read_guest_disk_windows_readonly(Path("/tmp/disposable.img"))
        with self.assertRaisesRegex(
                inspect.SharedDiskHandoffRejected,"virtio"):
            inspect.read_guest_disk_windows_readonly(Path("/dev/null"))


if __name__=="__main__":
    unittest.main()
