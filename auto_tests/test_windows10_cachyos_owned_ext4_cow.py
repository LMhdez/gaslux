"""Negative contracts for the Windows 10 fifth-only ext4 COW experiment.

No filesystem is formatted by these tests. Real mkfs only runs in a separate
GitHub-hosted disposable QEMU/libguestfs integration with its own consent.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
import uuid
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import windows10_cachyos_owned_ext4_cow as ext4

WINDOWS = [
    {"firstLba": 2048, "lastLba": 206847},
    {"firstLba": 206848, "lastLba": 239615},
    {"firstLba": 239616, "lastLba": 170000000},
    {"firstLba": 170000001, "lastLba": 170800000},
]
START = 170801152
SECTORS = 24 * 1024**3 // 512
GUID = "48a33c62-c391-486f-b0f8-b6637f0bced0"


def fixture():
    geometry = {"windowsPartitions": copy.deepcopy(WINDOWS)}
    linux = {
        "index": 5, "firstLba": START, "lastLba": START+SECTORS-1,
        "lengthBytes": 24*1024**3,
        "typeGuid": "0fc63daf-8483-4772-8e79-3d69d8477de4",
        "uniqueGuid": GUID, "name": "GASLUX-CACHYOS-ROOT",
    }
    rows = []
    for number, win in enumerate(WINDOWS, 1):
        rows.append({
            "part_num": number, "part_start": win["firstLba"] * 512,
            "part_size": (win["lastLba"]-win["firstLba"]+1)*512,
        })
    rows.append({
        "part_num": 5, "part_start": START*512,
        "part_size": 24 * 1024**3,
    })
    return geometry, linux, rows


def prove(geometry=None, linux=None, rows=None, type_guid=None, unique_guid=None):
    g, l, p = fixture()
    ext4.validate_partition_records(
        g if geometry is None else geometry,
        l if linux is None else linux,
        p if rows is None else rows,
        l["typeGuid"] if type_guid is None else type_guid,
        l["uniqueGuid"] if unique_guid is None else unique_guid,
    )


class OwnedFifthOnlyExt4Tests(unittest.TestCase):
    def test_only_exact_five_partitions_are_allowed(self):
        prove()
        g, l, p = fixture()
        for bad in (p[:-1], p+[dict(p[-1], part_num=6)]):
            with self.subTest(count=len(bad)), self.assertRaises(
                    ext4.OwnedExt4Rejected):
                prove(rows=bad)

    def test_windows_first_four_offsets_sizes_and_numbers_immutable(self):
        for index in range(4):
            for name, bad in (
                ("part_start", 2048),
                ("part_size", 512),
                ("part_num", 7),
            ):
                g, l, p = fixture()
                p[index][name] = bad
                with self.subTest(index=index, name=name), self.assertRaisesRegex(
                        ext4.OwnedExt4Rejected, "Windows partition"):
                    prove(rows=p)

    def test_linux_fifth_requires_exact_guid_range_size_and_index(self):
        for k, bad in (
            ("index", 4), ("firstLba", START + 2048),
            ("lengthBytes", 23 * 1024**3),
            ("typeGuid", "de94bba4-06d1-4d40-a16a-bfd50179d6ac"),
            ("name", "FOREIGN"),
        ):
            g, l, p = fixture()
            l[k] = bad
            with self.subTest(field=k), self.assertRaisesRegex(
                    ext4.OwnedExt4Rejected, "Linux partition"):
                prove(linux=l)

    def test_linux_unique_guid_cannot_be_foreign_or_zero(self):
        g, l, p = fixture()
        with self.assertRaisesRegex(ext4.OwnedExt4Rejected, "unique GUID"):
            prove(unique_guid="00000000-0000-0000-0000-000000000000")
        with self.assertRaisesRegex(ext4.OwnedExt4Rejected, "unique GUID"):
            prove(unique_guid=str(uuid.uuid4()))

    def test_reject_moved_start_overlap_windows_recovery(self):
        g, l, p = fixture()
        l["firstLba"] = WINDOWS[-1]["lastLba"]
        p[4]["part_start"] = l["firstLba"] * 512
        with self.assertRaisesRegex(ext4.OwnedExt4Rejected, "overlaps"):
            prove(linux=l, rows=p)

    def test_boolean_or_float_is_not_a_sector_offset(self):
        for invalid in (True, 2048.0, "1024"):
            _, _, p = fixture()
            p[4]["part_start"] = invalid
            with self.subTest(value=invalid), self.assertRaises(
                    ext4.OwnedExt4Rejected):
                prove(rows=p)

    def test_refuse_ext4_without_separate_explicit_consent(self):
        with patch.object(ext4, "validate_workspace") as protected, \
                patch.dict("os.environ", {
                    "GASLUX_CACHYOS_ROOT_EXT4_COW_CONSENT": "WRONG",
                    "GASLUX_CACHYOS_OVERLAY_GPT_CONSENT":
                        "I_ACCEPT_DISPOSABLE_QCOW2_OVERLAY_GPT_ONLY",
                }):
            with self.assertRaisesRegex(
                    ext4.OwnedExt4Rejected, "consent"):
                ext4.format_fifth_ext4_only_in_cow(
                    Path("/never/real-device"), Path("/never/vars"), {}, {}, {})
            protected.assert_called_once()

    def test_no_whole_disk_or_windows_esp_format_primitives(self):
        source=(TOOLS/"windows10_cachyos_owned_ext4_cow.py").read_text()
        self.assertIn('guest.mkfs("ext4", root, label=LABEL)', source)
        self.assertIn('root = dev + "5"', source)
        self.assertIn("g.mount_ro", source.replace("guest.mount_ro", "g.mount_ro"))
        for forbidden in ("sgdisk --clear", 'mkfs.vfat', "grub-install",
                          "pacstrap -K", "efibootmgr -c"):
            self.assertNotIn(forbidden, source)

    def test_previous_overlay_checkpoint_contract_remains_fail_closed(self):
        source=(TOOLS/"windows10_cachyos_real_gpt_overlay_rehearsal.py").read_text()
        self.assertIn("format_fifth_ext4_only_in_cow", source)
        self.assertIn("linuxRootExt4TrialPerformedOnlyOnDiscardedOverlay", source)
        self.assertIn('"linuxRootFilesystemFormatted": False', source)
        self.assertIn('"cachyosInstalled": False', source)
        self.assertIn('"releaseEligible": False', source)
        self.assertNotIn("sgdisk --clear", source)


if __name__ == "__main__":
    unittest.main()
