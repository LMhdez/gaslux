"""Synthetic-only GPT mirror and Pop-owned pair-stage negative contracts."""
from __future__ import annotations

import binascii
import copy
import pathlib
import struct
import sys
import unittest
import uuid

TOOLS = pathlib.Path(__file__).parent / "tools"
sys.path.insert(0, str(TOOLS))

from windows10_popos_gpt_mirror_gate import (  # noqa: E402
    SECTOR, WINDOW_BYTES, ESP, LINUX_TYPE, DiskAuditError,
    parse_windows_pop_gpt,
)
from windows10_popos_independent_esp_plan import propose_owned_esp_root  # noqa: E402
from windows10_popos_independent_esp_root_stage import reconcile_owned_pair  # noqa: E402
from test_windows10_popos_gpt_mirror_gate import make_pair  # noqa: E402
from test_windows10_popos_independent_esp_plan import fixture  # noqa: E402

ESP_GUID = uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-pair-owned-esp")
ROOT_GUID = uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-pair-owned-root")


def staged_fixture():
    """Build six-entry *bytes in memory*, with CRC-verified GPT mirrors."""
    front, back, _ = make_pair(linux=False)
    windows, original = fixture()
    plan = propose_owned_esp_root(windows, original, ESP_GUID, ROOT_GUID)
    entries = bytearray(front[2*SECTOR:34*SECTOR])
    for part in plan["partitions"]:
        n = part["index"]
        offset = (n-1)*128
        row = bytearray(128)
        row[:16] = uuid.UUID(part["typeGuid"]).bytes_le
        row[16:32] = uuid.UUID(part["uniqueGuid"]).bytes_le
        struct.pack_into("<QQQ", row, 32, part["startSector"],
                         part["endSector"], 0)
        label = part["name"].encode("utf-16-le")
        row[56:56+len(label)] = label
        entries[offset:offset+128] = row
    crc = binascii.crc32(entries) & 0xFFFFFFFF
    f, b = bytearray(front), bytearray(back)
    f[2*SECTOR:34*SECTOR] = entries
    b[WINDOW_BYTES-33*SECTOR:WINDOW_BYTES-SECTOR] = entries
    for data, offset in ((f, SECTOR), (b, WINDOW_BYTES-SECTOR)):
        head = bytearray(data[offset:offset+SECTOR])
        struct.pack_into("<I", head, 88, crc)
        struct.pack_into("<I", head, 16, 0)
        struct.pack_into("<I", head, 16, binascii.crc32(head[:92]) & 0xFFFFFFFF)
        data[offset:offset+SECTOR] = head
    after = parse_windows_pop_gpt(bytes(f), bytes(b), expected_count=6)
    return front, back, bytes(f), bytes(b), original, after, plan


class DummyOwnedPartitionGuest:
    def __init__(self):
        self.entries = {}
        self.calls = []

    def part_add(self, device, kind, start, end):
        assert (device, kind) == ("/dev/sda", "p")
        self.calls.append(("part_add", start, end))

    def part_set_gpt_type(self, device, n, value):
        self.entries.setdefault(n, {})["type"] = value
        self.calls.append(("part_set_gpt_type", n, value))

    def part_set_gpt_guid(self, device, n, value):
        self.entries.setdefault(n, {})["guid"] = value
        self.calls.append(("part_set_gpt_guid", n, value))

    def part_set_name(self, device, n, value):
        self.entries.setdefault(n, {})["name"] = value

    def part_get_gpt_type(self, device, n):
        return self.entries[n]["type"]

    def part_get_gpt_guid(self, device, n):
        return self.entries[n]["guid"]

    def part_get_name(self, device, n):
        return self.entries[n]["name"]


class ExactOwnedGuidWriterTests(unittest.TestCase):
    def test_both_pop_entries_receive_the_proposed_unique_guids(self):
        from windows10_popos_independent_esp_root_stage import (
            _write_exact_owned_partition,
        )
        _, _, _, _, _, _, plan = staged_fixture()
        disk = DummyOwnedPartitionGuest()
        for part in plan["partitions"]:
            _write_exact_owned_partition(disk, part)
        applied = [x for x in disk.calls if x[0] == "part_set_gpt_guid"]
        self.assertEqual(applied, [
            ("part_set_gpt_guid", p["index"], p["uniqueGuid"])
            for p in plan["partitions"]
        ])

    def test_foreign_partition_number_refused_before_any_write(self):
        from windows10_popos_independent_esp_root_stage import (
            _write_exact_owned_partition,
        )
        _, _, _, _, _, _, plan = staged_fixture()
        foreign = {**plan["partitions"][0], "index": 7}
        disk = DummyOwnedPartitionGuest()
        with self.assertRaises(DiskAuditError):
            _write_exact_owned_partition(disk, foreign)
        self.assertEqual(disk.calls, [])

    def test_guid_readback_mismatch_fails_after_writing_only_private_guest(self):
        from windows10_popos_independent_esp_root_stage import (
            _write_exact_owned_partition,
        )
        _, _, _, _, _, _, plan = staged_fixture()
        disk = DummyOwnedPartitionGuest()
        disk.part_get_gpt_guid = lambda device, n: str(uuid.uuid4())
        with self.assertRaises(DiskAuditError):
            _write_exact_owned_partition(disk, plan["partitions"][0])


class WindowsPostPairBootWitnessContracts(unittest.TestCase):
    def setUp(self):
        from windows10_popos_independent_esp_root_stage import (
            POSTBOOT_IMMUTABLE_WINDOWS, POSTBOOT_WINDOWS_STATE,
        )
        keys = POSTBOOT_IMMUTABLE_WINDOWS + POSTBOOT_WINDOWS_STATE
        self.before = {
            "diskGuid": "b65d18c0-d3ac-40b3-930d-b259c857b63a",
            "windowsPartitions": [(1, 2048, 532480, "esp", "windows-guid")],
            "windowsFilesSha256": {
                key: f"{i+1:x}" * 64 for i, key in enumerate(keys)
            },
        }

    def test_windows_guest_changes_runtime_hive_and_bcd_without_changing_boot_exes(self):
        from windows10_popos_independent_esp_root_stage import (
            reconcile_windows_postboot_witness,
        )
        after = copy.deepcopy(self.before)
        after["windowsFilesSha256"]["/EFI/Microsoft/Boot/BCD"] = "a"*64
        after["windowsFilesSha256"]["/Windows/System32/config/SYSTEM"] = "b"*64
        result = reconcile_windows_postboot_witness(self.before, after)
        self.assertTrue(result["windowsPostbootBcdStateSha256Changed"])
        self.assertTrue(result["windowsPostbootSystemHiveSha256Changed"])
        self.assertTrue(result["windowsPostbootBootManagerExeSha256Unchanged"])
        self.assertTrue(result["windowsPostbootWinloadExeSha256Unchanged"])

    def test_postboot_refuses_any_foreign_geometry_or_executable_hash_change(self):
        from windows10_popos_independent_esp_root_stage import (
            reconcile_windows_postboot_witness,
        )
        for kind in ("diskGuid", "partitionGeometry", "bootmgfw", "winload",
                     "missingBcd", "extraFile", "invalidDigest"):
            after = copy.deepcopy(self.before)
            if kind == "diskGuid":
                after["diskGuid"] = str(uuid.uuid4())
            elif kind == "partitionGeometry":
                after["windowsPartitions"][0] = (1, 2048, 532481, "esp", "windows-guid")
            elif kind == "bootmgfw":
                after["windowsFilesSha256"]["/EFI/Microsoft/Boot/bootmgfw.efi"] = "c"*64
            elif kind == "winload":
                after["windowsFilesSha256"]["/Windows/System32/winload.efi"] = "c"*64
            elif kind == "missingBcd":
                del after["windowsFilesSha256"]["/EFI/Microsoft/Boot/BCD"]
            elif kind == "extraFile":
                after["windowsFilesSha256"]["/Windows/System32/foreign.sys"] = "c"*64
            else:
                after["windowsFilesSha256"]["/Windows/System32/config/SYSTEM"] = "INVALID"
            with self.subTest(kind=kind), self.assertRaises(DiskAuditError):
                reconcile_windows_postboot_witness(self.before, after)


class PopOwnedPairStageContracts(unittest.TestCase):
    def test_crc_and_entire_windows_pmbr_unchanged_with_two_owned_entries(self):
        f0, b0, f1, b1, before, after, plan = staged_fixture()
        reconcile_owned_pair(before, after, plan)
        self.assertEqual(f0[:SECTOR], f1[:SECTOR])
        self.assertEqual(f0[34*SECTOR:], f1[34*SECTOR:])
        self.assertEqual(b0[:WINDOW_BYTES-33*SECTOR], b1[:WINDOW_BYTES-33*SECTOR])
        self.assertEqual(after["popEsp"]["type"], ESP)
        self.assertEqual(after["linuxRoot"]["type"], LINUX_TYPE)
        self.assertEqual([after["popEsp"]["number"], after["linuxRoot"]["number"]],
                         [5, 6])
        self.assertEqual(before["windowsEntryHex"], after["windowsEntryHex"])
        self.assertFalse(after["productionInstallationAuthorized"])

    def test_refuse_changed_mbr_windows_guid_foreign_esp_or_root(self):
        _, _, _, _, before, after, plan = staged_fixture()
        for key, value in (
            ("mbrSha256", "0"*64),
            ("diskGuid", "00000000-0000-0000-0000-000000000000"),
            ("windowsEntryHex", ["invalid"]*4),
        ):
            with self.subTest(key=key):
                modified = copy.deepcopy(after)
                modified[key] = value
                with self.assertRaises(DiskAuditError):
                    reconcile_owned_pair(before, modified, plan)
        for name, field, value in (
            ("foreign_esp_guid", "guid", str(uuid.uuid4())),
            ("wrong_esp_lba", "startLba", after["popEsp"]["startLba"]+1),
            ("root_wrong_size", "endLba", after["linuxRoot"]["endLba"]-1),
        ):
            with self.subTest(name=name):
                modified = copy.deepcopy(after)
                node = "popEsp" if name.startswith("foreign") or name.startswith("wrong") else "linuxRoot"
                modified[node][field] = value
                with self.assertRaises(DiskAuditError):
                    reconcile_owned_pair(before, modified, plan)

    def test_six_entry_parser_refuses_extra_partitions_or_bad_crc(self):
        _, _, f, b, _, _, _ = staged_fixture()
        damaged = bytearray(f)
        damaged[6*128 + 2*SECTOR] = 17
        with self.assertRaises(DiskAuditError):
            parse_windows_pop_gpt(bytes(damaged), b, expected_count=6)
        bad_backup = bytearray(b)
        bad_backup[-SECTOR + 25] ^= 1
        with self.assertRaises(DiskAuditError):
            parse_windows_pop_gpt(f, bytes(bad_backup), expected_count=6)

    def test_pair_stage_never_claims_a_real_installed_pop_system(self):
        _, _, _, _, before, after, plan = staged_fixture()
        reconcile_owned_pair(before, after, plan)
        self.assertFalse(plan["productionInstallationAuthorized"])
        for item in plan["partitions"]:
            self.assertFalse(item["formatRequested"])


if __name__ == "__main__":
    unittest.main()
