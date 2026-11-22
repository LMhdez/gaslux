"""Disposable RAW-only ESP capture/GPT and QEMU process contract regressions.

The 128-GiB test disk is SPARSE and temporary. No installed Windows/QEMU,
real disk, ESP image, TPM state, guest or signed metadata is used.
"""
from __future__ import annotations

import binascii
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock
import uuid

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import cachyos_bcd_esp_provenance_offline as source
import cachyos_bcd_fat32_offline as fat
import cachyos_bcd_qemu_trace_offline as trace
import windows_cachyos_qcow2_gpt_readonly as gpt
from test_cachyos_bcd_fat32_qemu_offline import (
    make_fat32, ESP_LBA, ESP_END, TOTAL_SECTORS,
)
from test_windows_cachyos_qcow2_gpt_readonly import (
    create_disk_windows, GUID,
)


def fixture_gpt(esp_last: int) -> tuple[bytes, bytes]:
    front, back = map(bytearray, create_disk_windows())
    entries = bytearray(front[2 * 512:34 * 512])
    struct.pack_into("<Q", entries, 40, esp_last)
    crc = binascii.crc32(entries) & 0xffffffff
    front[2 * 512:34 * 512] = entries
    back[-33 * 512:-512] = entries
    for header in (front, back):
        position = 512 if header is front else len(header) - 512
        struct.pack_into("<I", header, position + 88, crc)
        struct.pack_into("<I", header, position + 16, 0)
        struct.pack_into("<I", header, position + 16,
                         binascii.crc32(header[position:position + 92]) & 0xffffffff)
    return bytes(front), bytes(back)


def probe_descriptor(fd: int) -> dict:
    st = os.fstat(fd)
    return {
        "dev": st.st_dev, "ino": st.st_ino, "nlink": st.st_nlink,
        "size": st.st_size, "mtimeNs": st.st_mtime_ns,
        "ctimeNs": st.st_ctime_ns,
    }


class EspSourceOfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fat = make_fat32(fragmented=True)
        assert len(cls.fat) == TOTAL_SECTORS * 512
        cls.front, cls.back = fixture_gpt(ESP_END)
        entries = cls.front[2 * 512:34 * 512]
        cls.esp_uuid = str(uuid.UUID(bytes_le=entries[16:32]))
        cls.disk_uuid = str(uuid.UUID(bytes_le=GUID))
        cls.gpt_hash = hashlib.sha256(cls.front + cls.back).hexdigest()
        cls.fat_hash = hashlib.sha256(cls.fat).hexdigest()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gaslux-synthetic-esp-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic-owned.raw"
        with self.path.open("xb") as disk:
            disk.truncate(gpt.VIRTUAL_BYTES)
            disk.seek(0)
            disk.write(self.front)
            disk.seek(gpt.VIRTUAL_BYTES - gpt.WINDOW_BYTES)
            disk.write(self.back)
            disk.seek(ESP_LBA * 512)
            disk.write(self.fat)
        self.path.chmod(0o400)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)
        self.expected = {
            "scope": "DISPOSABLE_SYNTHETIC_RAW_ONLY",
            "transactionId": "a" * 32,
            "checkpointSha256": "b" * 64,
            "sectorBytes": 512,
            "diskBytes": gpt.VIRTUAL_BYTES,
            "diskGuid": self.disk_uuid,
            "espPartuuid": self.esp_uuid,
            "espStartLba": ESP_LBA,
            "espEndLba": ESP_END,
            "espSha256": self.fat_hash,
            "gptWindowsSha256": self.gpt_hash,
            "sourceIdentity": probe_descriptor(self.fd),
        }

    def capture(self, *, expected=None, path=None, fd=None):
        return source.measure_esp_from_pinned_raw_fd(
            self.fd if fd is None else fd,
            self.path if path is None else path,
            self.expected if expected is None else expected,
        )

    def test_synthetic_fragmented_bcd_map_bound_to_pinned_fd(self):
        report, mapped = self.capture()
        self.assertEqual(report["status"], "SYNTHETIC_RAW_FD_MEASURED_DENY_ONLY")
        self.assertTrue(report["twoPassEspBytesEqual"])
        self.assertTrue(report["primaryBackupGptConsistent"])
        self.assertTrue(mapped["bcdFragmented"])
        self.assertEqual(mapped["bcdSizeBytes"], 4096)
        self.assertEqual(report["espSha256"], self.fat_hash)
        self.assertEqual(report["transactionId"], "a" * 32)
        for key in ("historicalEspProvenanceAuthenticated",
                    "qemuBlkNodeToDiskAuthenticated",
                    "approvedMutation", "productionStorageWritesAuthorized",
                    "releaseEligible"):
            self.assertFalse(report[key])
        self.assertNotIn("path", repr(report).lower())

    def test_wrong_disk_identical_esp_offset_rejected(self):
        # Sparse 128-GiB *virtual* file. Never copy all logical zeroes:
        # copyfile may physically allocate 128 GiB on a hosted runner.
        second = Path(self.temp.name) / "second.raw"
        with second.open("xb") as disk:
            disk.truncate(gpt.VIRTUAL_BYTES)
            disk.write(self.front)
            disk.seek(gpt.VIRTUAL_BYTES - gpt.WINDOW_BYTES)
            disk.write(self.back)
            disk.seek(ESP_LBA * 512)
            disk.write(self.fat)
        second.chmod(0o400)
        with os.fdopen(os.open(second, os.O_RDONLY | os.O_CLOEXEC |
                              os.O_NOFOLLOW), "rb", closefd=True) as cloned:
            with self.assertRaisesRegex(source.EspProvenanceError,
                                         "identity"):
                self.capture(fd=cloned.fileno(), path=second)

    def test_mismatched_expected_partuuid_and_disk_guid_rejected(self):
        for field in ("espPartuuid", "diskGuid"):
            with self.subTest(field=field):
                expected = dict(self.expected)
                expected[field] = str(uuid.uuid5(uuid.NAMESPACE_DNS, field))
                with self.assertRaisesRegex(source.EspProvenanceError,
                                             "GUID|PARTUUID"):
                    self.capture(expected=expected)

    def test_gpt_geometry_and_hash_tampering_rejected(self):
        for field, value in (
            ("espStartLba", ESP_LBA + 1),
            ("espEndLba", ESP_END + 1),
            ("diskBytes", gpt.VIRTUAL_BYTES - 512),
            ("sectorBytes", 4096),
            ("gptWindowsSha256", "c" * 64),
        ):
            with self.subTest(field=field):
                expected = dict(self.expected)
                expected[field] = value
                with self.assertRaises(source.EspProvenanceError):
                    self.capture(expected=expected)

    def test_esp_capture_hash_difference_and_truncation_refused(self):
        expected = dict(self.expected)
        expected["espSha256"] = "c" * 64
        with self.assertRaisesRegex(source.EspProvenanceError,
                                     "ESP.*hash"):
            self.capture(expected=expected)
        expected = dict(self.expected)
        expected["espEndLba"] = ESP_END - 1
        with self.assertRaises(source.EspProvenanceError):
            self.capture(expected=expected)

    def test_replaced_path_same_size_refused_after_open(self):
        replacement = Path(self.temp.name) / "replacement.raw"
        replacement.write_bytes(b"replaced")
        self.path.chmod(0o600)
        self.path.rename(Path(self.temp.name) / "old.raw")
        replacement.replace(self.path)
        with self.assertRaisesRegex(source.EspProvenanceError,
                                     "identity"):
            self.capture()

    def test_symlink_and_hardlink_refused(self):
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.path)
        with self.assertRaisesRegex(source.EspProvenanceError, "identity|symlink"):
            self.capture(path=alias)
        alias.unlink()
        os.link(self.path, alias)
        with self.assertRaisesRegex(source.EspProvenanceError,
                                     "link|identity"):
            self.capture()

    def test_fd_write_mode_rejected(self):
        self.path.chmod(0o600)
        with self.path.open("r+b") as rw:
            with self.assertRaisesRegex(source.EspProvenanceError,
                                         "read-only"):
                self.capture(fd=rw.fileno())

    def test_backing_or_disk_container_cannot_be_claimed_as_raw(self):
        fake = Path(self.temp.name) / "fake.qcow2"
        fake.write_bytes(b"QFI\xfb" + b"\x00" * 2048)
        with fake.open("rb") as fd:
            with self.assertRaises(source.EspProvenanceError):
                self.capture(fd=fd.fileno(), path=fake)

    def test_source_changed_inplace_during_readback_rejected(self):
        orig = source.os.pread
        counter = 0

        def mutate_on_second_read(fd: int, length: int, offset: int) -> bytes:
            nonlocal counter
            counter += 1
            if counter == 4:
                self.path.chmod(0o600)
                with self.path.open("r+b") as writable:
                    writable.seek(ESP_LBA * 512 + 1200)
                    writable.write(b"REPLACED!")
            return orig(fd, length, offset)

        with mock.patch.object(source.os, "pread",
                               side_effect=mutate_on_second_read):
            with self.assertRaises(source.EspProvenanceError):
                self.capture()


class QemuSourceClaimTests(unittest.TestCase):
    def setUp(self):
        self.trace = trace.parse_qemu_trace(
            b"blk_co_pwritev blk 0xa1 bs 0xb2 offset 1056768 bytes 512 flags 0x0\n"
        )
        self.record = {
            "scope": "HOST_OBSERVATION_UNVERIFIED",
            "transactionId": "a" * 32,
            "checkpointSha256": "b" * 64,
            "traceSha256": self.trace["traceSha256"],
            "blkPointer": "0xa1",
            "qemuProcesses": [
                {"pid": 100, "startTicks": 310, "uid": 1000,
                 "executableSha256": "c" * 64},
            ],
            "processAtEnd": {"pid": 100, "startTicks": 310, "uid": 1000,
                             "executableSha256": "c" * 64},
            "openFdAtStart": {"dev": 4, "ino": 5, "size": gpt.VIRTUAL_BYTES,
                              "nlink": 1, "mtimeNs": 1, "ctimeNs": 1},
            "openFdAtEnd": {"dev": 4, "ino": 5, "size": gpt.VIRTUAL_BYTES,
                            "nlink": 1, "mtimeNs": 1, "ctimeNs": 1},
            "selectedDiskIdentity": {"dev": 4, "ino": 5,
                                     "size": gpt.VIRTUAL_BYTES,
                                     "nlink": 1, "mtimeNs": 1, "ctimeNs": 1},
            "backingSha256Before": "d" * 64,
            "backingSha256After": "d" * 64,
            "qmpNodeNames": ["windows-disk"],
        }

    def check(self, value=None):
        return source.evaluate_untrusted_qemu_claim(
            self.trace, self.record if value is None else value,
        )

    def test_perfectly_matching_claim_does_not_authenticate_blk(self):
        result = self.check()
        self.assertEqual(result["status"],
                         "QEMU_PROCESS_FD_CONSISTENT_BLK_POINTER_UNBOUND")
        self.assertFalse(result["qemuBlkNodeToDiskAuthenticated"])
        self.assertFalse(result["qmpNodeToProcFdAuthenticated"])
        self.assertFalse(result["processAttributionProven"])

    def test_wrong_blk_pointer_refused(self):
        r = dict(self.record, blkPointer="0xc2")
        with self.assertRaises(source.EspProvenanceError):
            self.check(r)

    def test_two_concurrent_qemu_instances_refused(self):
        r = dict(self.record, qemuProcesses=[
            *self.record["qemuProcesses"],
            {"pid": 200, "startTicks": 400, "uid": 1000,
             "executableSha256": "e" * 64},
        ])
        with self.assertRaisesRegex(source.EspProvenanceError,
                                     "QEMU"):
            self.check(r)

    def test_reused_pid_with_different_start_ticks_refused(self):
        r = dict(self.record, processAtEnd=dict(
            self.record["processAtEnd"], startTicks=999))
        with self.assertRaisesRegex(source.EspProvenanceError,
                                     "process|PID"):
            self.check(r)

    def test_swapped_fd_backing_and_inode_refused(self):
        variants = [
            dict(self.record, backingSha256After="e" * 64),
            dict(self.record, openFdAtEnd=dict(
                self.record["openFdAtEnd"], ino=999)),
            dict(self.record, selectedDiskIdentity=dict(
                self.record["selectedDiskIdentity"], ino=999)),
        ]
        for candidate in variants:
            with self.subTest(record=candidate):
                with self.assertRaises(source.EspProvenanceError):
                    self.check(candidate)

    def test_missing_trace_or_unbounded_graph_refused(self):
        for candidate in (
            dict(self.record, traceSha256="e" * 64),
            dict(self.record, traceSha256=None),
            dict(self.record, qmpNodeNames=["windows-disk", "another"]),
        ):
            with self.assertRaises(source.EspProvenanceError):
                self.check(candidate)

    def test_trace_incomplete_refused(self):
        incomplete = dict(self.trace, records=[])
        with self.assertRaises(source.EspProvenanceError):
            source.evaluate_untrusted_qemu_claim(incomplete, self.record)


if __name__ == "__main__":
    unittest.main()
