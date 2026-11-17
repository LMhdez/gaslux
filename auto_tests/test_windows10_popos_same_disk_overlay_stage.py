"""No-ISO no-guest negative regressions for Windows10+Pop COW root staging."""
from __future__ import annotations

import copy
import importlib.util
import os
import pathlib
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).parent / "tools"
SPEC = importlib.util.spec_from_file_location(
    "win10_pop_cow", TOOLS / "windows10_popos_same_disk_overlay_stage.py"
)
assert SPEC and SPEC.loader
import sys

sys.path.insert(0, str(TOOLS))
COW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COW)
GIB = 1024**3
MIB = 1024**2


def report() -> dict:
    off = MIB
    found = []
    for n, (kind, size) in enumerate(zip(
        COW.WINDOWS_TYPES, (260*MIB, 16*MIB, 72*GIB, 1536*MIB),
    ), 1):
        found.append({
            "number": n, "typeGuid": kind, "offsetBytes": off,
            "sizeBytes": size,
        })
        off += size
    return {
        "schemaVersion": 1, "profile": "win10_22h2_en_us_x64",
        "partitionCount": 4, "diskVirtualSizeBytes": 128*GIB,
        "storageWritesAuthorized": False, "partitions": found,
    }


class DummyG:
    def __init__(self, plan: dict, *, after: bool = True):
        baseline = report()["partitions"]
        self.parts = [
            {"part_num": p["number"], "part_start": p["offsetBytes"],
             "part_size": p["sizeBytes"]} for p in baseline
        ]
        if after:
            self.parts.append({
                "part_num": 5, "part_start": plan["startSector"]*COW.SECTOR,
                "part_size": plan["sizeBytes"],
            })
        self.types = list(COW.WINDOWS_TYPES) + ([COW.LINUX_GPT] if after else [])
        self.uuids = [f"0000000{i}-1111-2222-3333-444444444444" for i in range(1, 6)]
        self.files = {
            "/dev/sda1": set(COW.WINDOWS_FILES["/dev/sda1"]),
            "/dev/sda3": set(COW.WINDOWS_FILES["/dev/sda3"]),
        }
        self.mount = None
        self.label = COW.ROOT_LABEL
        self.disk_guid = "11111111-2222-3333-4444-555555555555"

    def list_devices(self):
        return ["/dev/sda"]

    def part_get_parttype(self, device):
        return "gpt"

    def blockdev_getsize64(self, device):
        return 128*GIB

    def blockdev_getss(self, device):
        return 512

    def part_list(self, device):
        return self.parts

    def part_get_disk_guid(self, device):
        return self.disk_guid

    def part_get_gpt_type(self, device, num):
        return self.types[num-1]

    def part_get_gpt_guid(self, device, num):
        return self.uuids[num-1]

    def part_get_name(self, device, num):
        return self.label

    def vfs_type(self, device):
        return {"/dev/sda1": "vfat", "/dev/sda3": "ntfs",
                "/dev/sda4": "ntfs"}.get(device, "")

    def mount_ro(self, device, target):
        assert target == "/"
        self.mount = device

    def is_file(self, path):
        return path in self.files.get(self.mount, set())

    def checksum(self, algorithm, path):
        assert algorithm == "sha256"
        return ("1" if path.endswith("BCD") else "a")*64

    def umount_all(self):
        self.mount = None


class CandidatePlanTests(unittest.TestCase):
    def test_windows10_tail_plans_exactly_one_unformatted_owned_root(self):
        plan = COW.candidate_plan(report())
        self.assertEqual(plan["sizeBytes"], 24*GIB)
        self.assertEqual(plan["index"], 5)
        self.assertEqual(plan["name"], COW.ROOT_LABEL)
        self.assertFalse(plan["formatLinuxFilesystem"])
        self.assertTrue(plan["sharedWindowsEspUntouched"])
        self.assertEqual(plan["startSector"] % 2048, 0)

    def test_reject_unaudited_or_other_windows(self):
        for key, value in (
            ("schemaVersion", 0), ("profile", "win11_26h2_en_us_x64"),
            ("partitionCount", 5), ("storageWritesAuthorized", True),
            ("diskVirtualSizeBytes", 96*GIB),
        ):
            with self.subTest(field=key):
                bad = report()
                bad[key] = value
                with self.assertRaises(COW.DiskAuditError):
                    COW.candidate_plan(bad)

    def test_reject_foreign_or_relocated_windows_partition(self):
        for index, key, value in (
            (0, "typeGuid", COW.BASIC),
            (1, "offsetBytes", 10),
            (3, "offsetBytes", 200*MIB),
            (3, "sizeBytes", 80*GIB),
        ):
            with self.subTest(index=index, field=key):
                bad = report()
                bad["partitions"][index][key] = value
                with self.assertRaises(COW.DiskAuditError):
                    COW.candidate_plan(bad)

    def test_refuse_non_host_owned_paths_without_touching_disk(self):
        with patch.dict(os.environ, {"GASLUX_WIN10_POP_OVERLAY_CONSENT": COW.CONSENT}):
            with self.assertRaises(COW.DiskAuditError):
                COW.require_lab_owned(
                    pathlib.Path("/dev/sda"),
                    pathlib.Path("/tmp/gaslux-pop-stage.qcow2"),
                    pathlib.Path("/tmp"),
                )


class OverlayReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.plan = COW.candidate_plan(report())
        self.g = DummyG(self.plan)
        before_g = DummyG(self.plan, after=False)
        self.before = COW._windows_witness(before_g, 4)

    def test_accept_one_extra_unformatted_linux_partition_but_not_boot(self):
        proof = COW.validate_after(self.g, self.before, self.plan)
        self.assertTrue(proof["sameDiskLinuxPartitionCreatedInCOWOverlay"])
        self.assertTrue(proof["windowsOfflineGptEspBcdNtfsReconciled"])
        for k in ("windowsBootAfterPartitionStageVerified", "popFirstbootOnWindowsDiskVerified",
                  "linuxSystemInstalled", "dualBootVerified",
                  "productionInstallationAuthorized", "stable"):
            self.assertFalse(proof[k])

    def test_reject_windows_guid_and_disk_guid_change(self):
        for change in ("disk_guid", "guid"):
            g = DummyG(self.plan)
            if change == "disk_guid":
                g.disk_guid = "22222222-2222-3333-4444-555555555555"
            else:
                g.uuids[0] = g.uuids[1]
            with self.subTest(change=change), self.assertRaises(COW.DiskAuditError):
                COW.validate_after(g, self.before, self.plan)

    def test_reject_corrupted_windows_loader_and_missing_bcd(self):
        for changed in ("absent", "hash"):
            g = DummyG(self.plan)
            if changed == "absent":
                g.files["/dev/sda1"].remove("/EFI/Microsoft/Boot/BCD")
            else:
                g.checksum = lambda algorithm, path: "b"*64
            with self.subTest(change=changed), self.assertRaises(COW.DiskAuditError):
                COW.validate_after(g, self.before, self.plan)

    def test_reject_linux_root_wrong_size_type_and_label(self):
        for attr in ("size", "type", "label"):
            g = DummyG(self.plan)
            if attr == "size":
                g.parts[4]["part_size"] -= 512
            elif attr == "type":
                g.types[4] = COW.BASIC
            else:
                g.label = "FOREIGN"
            with self.subTest(change=attr), self.assertRaises(COW.DiskAuditError):
                COW.validate_after(g, self.before, self.plan)

    def test_reject_disks_and_extra_partitions(self):
        for attr in ("disk", "sixth"):
            g = DummyG(self.plan)
            if attr == "disk":
                g.list_devices = lambda: ["/dev/sda", "/dev/sdb"]
            else:
                g.parts.append({"part_num": 6, "part_start": 98*GIB,
                                "part_size": GIB})
            with self.subTest(change=attr), self.assertRaises(COW.DiskAuditError):
                COW.validate_after(g, self.before, self.plan)



class DummyPmbrDisk:
    def __init__(self, pmbr):
        self.pmbr = bytearray(pmbr)
        self.writes = []

    def pread_device(self, device, length, offset):
        assert (device, length, offset) == ("/dev/sda", 512, 0)
        return bytes(self.pmbr)

    def pwrite_device(self, device, payload, offset):
        assert device == "/dev/sda"
        self.writes.append((offset, bytes(payload)))
        self.pmbr[offset:offset+len(payload)] = payload
        return len(payload)

    def sync(self):
        pass


class PmbrCompensationTests(unittest.TestCase):
    def setUp(self):
        import struct

        base = bytearray(512)
        base[510:512] = b"\x55\xaa"
        base[446+4] = 0xEE
        struct.pack_into("<I", base, 446+8, 1)
        struct.pack_into("<I", base, 446+12, 0xFFFFFFFF)
        self.base = bytes(base)

    def test_reject_all_other_mutations_before_any_write(self):
        import struct

        for variant in ("bad_size", "foreign_byte", "wrong_before_policy"):
            case = bytearray(self.base)
            if variant == "bad_size":
                struct.pack_into("<I", case, 458, 0xFFFFFFFE)
            else:
                struct.pack_into("<I", case, 458, 268435455)
                if variant == "foreign_byte":
                    case[442] ^= 1
            g = DummyPmbrDisk(case)
            with self.subTest(variant=variant):
                with self.assertRaises(COW.DiskAuditError):
                    COW._compensate_normalized_pmbr(
                        g, self.base,
                        {"oversizedWindowsPmbrLabOnly": variant != "wrong_before_policy"}
                    )
                self.assertEqual(g.writes, [])

    def test_accept_exact_normalized_span_and_restore_original_4_bytes(self):
        import struct

        case = bytearray(self.base)
        struct.pack_into("<I", case, 458, 268435455)
        g = DummyPmbrDisk(case)
        applied = COW._compensate_normalized_pmbr(
            g, self.base, {"oversizedWindowsPmbrLabOnly": True}
        )
        self.assertTrue(applied)
        self.assertEqual(g.writes, [(458, b"\xff\xff\xff\xff")])
        self.assertEqual(g.pread_device("/dev/sda", 512, 0), self.base)

    def test_mbr_refusal_reports_bounded_offsets_without_writing(self):
        import contextlib
        import io
        import json
        import struct

        candidate = bytearray(self.base)
        struct.pack_into("<I", candidate, 458, 268435455)
        candidate[440] ^= 1  # A foreign Windows disk-signature mutation.
        disk = DummyPmbrDisk(candidate)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(COW.DiskAuditError, "unexpected MBR mutation"):
                COW._compensate_normalized_pmbr(
                    disk, self.base, {"oversizedWindowsPmbrLabOnly": True}
                )
        self.assertEqual(disk.writes, [])
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        prefix = "GASLUX_POP_PMBR_COMPENSATION_REFUSAL="
        self.assertTrue(lines[0].startswith(prefix))
        details = json.loads(lines[0][len(prefix):])
        self.assertEqual(details["changedByteOffsetsFirst32"], [440, 461])
        self.assertEqual(details["changedByteCount"], 2)
        self.assertEqual(details["baselineProtectiveEntry"], self.base[446:462].hex())
        self.assertEqual(details["stagedProtectiveEntry"], candidate[446:462].hex())
        self.assertNotIn(self.base.hex(), output.getvalue())

    def test_untouched_pmbr_needs_no_compensation(self):
        g = DummyPmbrDisk(self.base)
        self.assertFalse(COW._compensate_normalized_pmbr(
            g, self.base, {"oversizedWindowsPmbrLabOnly": True}
        ))
        self.assertEqual(g.writes, [])


if __name__ == "__main__":
    unittest.main()
