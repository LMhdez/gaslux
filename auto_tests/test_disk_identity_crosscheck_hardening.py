"""Offline adversarial tests; temporary JSON only, never VM or physical disks."""
from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auto_tests.test_disk_identity_crosscheck import fixture
from auto_tests.tools import disk_identity_crosscheck as checker


class CrosscheckHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.records = fixture()
        self.paths = {}
        for name, record in self.records.items():
            path = self.root / f"{name}.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            self.paths[name] = str(path)

    def test_original_eight_are_not_a_substitute_for_file_tests(self):
        self.assertIs(checker.compare_files(self.paths), True)

    def test_legacy_toctou_reproduction_path_becomes_symlink_after_check(self):
        """Exact old check/read pattern accepts a symlink introduced after check."""
        target = Path(self.paths["guest"])
        foreign = self.root / "foreign.json"
        foreign.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        original = Path.read_text
        swapped = False

        def switch_before_legacy_read(path, *args, **kwargs):
            nonlocal swapped
            if path == target and not swapped:
                target.unlink()
                target.symlink_to(foreign)
                swapped = True
            return original(path, *args, **kwargs)

        def legacy(paths):
            records = {}
            for name, path in paths.items():
                p = Path(path)
                if p.is_symlink() or not p.is_file():
                    raise checker.IdentityMismatch("unsafe evidence path")
                records[name] = json.loads(p.read_text(encoding="utf-8"))
            return checker.compare_evidence(records)

        with patch.object(Path, "read_text", switch_before_legacy_read):
            self.assertIs(legacy(self.paths), True)
        self.assertTrue(swapped)
        self.assertTrue(target.is_symlink())
        with self.assertRaises(checker.IdentityMismatch):
            checker.compare_files(self.paths)

    def test_swap_between_prestat_and_fd_open_is_rejected(self):
        target = Path(self.paths["guest"])
        attacker = self.root / "attacker.json"
        attacker.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        original_open = os.open
        replaced = False

        def swap_on_open(path, flags, *args, **kwargs):
            nonlocal replaced
            if path == "guest.json" and kwargs.get("dir_fd") is not None and not replaced:
                os.replace(attacker, target)
                replaced = True
            return original_open(path, flags, *args, **kwargs)

        with (
            patch.object(checker.os, "open", swap_on_open),
            self.assertRaisesRegex(checker.IdentityMismatch, "substituted"),
        ):
            checker.compare_files(self.paths)
        self.assertTrue(replaced)

    def test_swap_to_symlink_between_prestat_and_open_is_rejected(self):
        target = Path(self.paths["guest"])
        attacker = self.root / "attacker.json"
        attacker.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        original_open = os.open
        replaced = False

        def replace_with_symlink(path, flags, *args, **kwargs):
            nonlocal replaced
            if path == "guest.json" and kwargs.get("dir_fd") is not None and not replaced:
                target.unlink()
                target.symlink_to(attacker)
                replaced = True
            return original_open(path, flags, *args, **kwargs)

        with (
            patch.object(checker.os, "open", replace_with_symlink),
            self.assertRaises(checker.IdentityMismatch),
        ):
            checker.compare_files(self.paths)
        self.assertTrue(replaced)

    def test_symlink_leaf_and_parent_are_rejected(self):
        target = Path(self.paths["guest"])
        target.unlink()
        target.symlink_to(self.root / "host.json")
        with self.assertRaises(checker.IdentityMismatch):
            checker.compare_files(self.paths)
        target.unlink()
        target.write_text(json.dumps(self.records["guest"]), encoding="utf-8")
        linked = self.root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        self.paths["guest"] = str(linked / "guest.json")
        with self.assertRaises(checker.IdentityMismatch):
            checker.compare_files(self.paths)

    def test_nonregular_fifo_is_rejected_without_hang(self):
        target = Path(self.paths["guest"])
        target.unlink()
        os.mkfifo(target)
        with self.assertRaises(checker.IdentityMismatch):
            checker.compare_files(self.paths)

    def test_hardlinked_evidence_is_rejected(self):
        target = Path(self.paths["guest"])
        os.link(target, self.root / "another-link.json")
        with self.assertRaises(checker.IdentityMismatch):
            checker.compare_files(self.paths)

    def test_invalid_truncated_and_oversized_json_are_rejected(self):
        target = Path(self.paths["guest"])
        invalid_contents = (
            "", "{", "not json", "{}", "\\xff",
            " " * (checker._MAX_EVIDENCE_BYTES + 1),
        )
        for content in invalid_contents:
            target.write_bytes(content.encode("utf-8"))
            with (
                self.subTest(length=len(content)),
                self.assertRaises(checker.IdentityMismatch),
            ):
                checker.compare_files(self.paths)

    def test_duplicate_json_fields_rejected(self):
        target = Path(self.paths["guest"])
        content = target.read_text(encoding="utf-8")
        duplicated = content.replace('"diskId":', '"diskId": "duplicated", "diskId":', 1)
        target.write_text(duplicated, encoding="utf-8")
        with self.assertRaisesRegex(checker.IdentityMismatch, "duplicate JSON"):
            checker.compare_files(self.paths)

    def test_missing_inventory_rejected(self):
        target = Path(self.paths["guest"])
        record = copy.deepcopy(self.records["guest"])
        del record["partitions"]
        target.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(checker.IdentityMismatch):
            checker.compare_files(self.paths)

    def test_in_place_change_during_read_rejected(self):
        target = Path(self.paths["guest"])
        target_inode = target.stat().st_ino
        original_pread = os.pread
        changed = False

        def mutate_while_reading(fd, length, offset):
            nonlocal changed
            if os.fstat(fd).st_ino == target_inode and not changed:
                with open(target, "ab") as handle:
                    handle.write(b" ")
                changed = True
            return original_pread(fd, length, offset)

        with (
            patch.object(checker.os, "pread", mutate_while_reading),
            self.assertRaises(checker.IdentityMismatch),
        ):
            checker.compare_files(self.paths)
        self.assertTrue(changed)

    def test_entry_replaced_during_read_rejected(self):
        target = Path(self.paths["guest"])
        foreign = self.root / "replacement.json"
        foreign.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        target_inode = target.stat().st_ino
        original_pread = os.pread
        swapped = False

        def swap_while_reading(fd, length, offset):
            nonlocal swapped
            if os.fstat(fd).st_ino == target_inode and not swapped:
                os.replace(foreign, target)
                swapped = True
            return original_pread(fd, length, offset)

        with (
            patch.object(checker.os, "pread", swap_while_reading),
            self.assertRaises(checker.IdentityMismatch),
        ):
            checker.compare_files(self.paths)
        self.assertTrue(swapped)

    def test_mbr_inventory_rejected_without_affecting_other_backends(self):
        records = fixture()
        for record in records.values():
            record["partitionStyle"] = "MBR"
        with self.assertRaisesRegex(checker.IdentityMismatch, "MBR/EBR unsupported"):
            checker.compare_evidence(records)

    def test_identical_forgery_does_not_become_authenticated(self):
        fake = fixture()
        for record in fake.values():
            record["diskId"] = "forged-serial"
            record["partitionTableSha256"] = "f" * 64
        # True means only syntactic agreement: no attestation or write authority.
        self.assertIs(checker.compare_evidence(fake), True)
        self.assertIs(type(checker.compare_evidence(fake)), bool)
        self.assertFalse(hasattr(checker, "authorize_write"))

    def test_replay_and_source_exchange_cannot_claim_provenance(self):
        old = fixture()
        replay = copy.deepcopy(old)
        exchanged = {"host": old["windows"], "guest": old["host"], "windows": old["guest"]}
        self.assertIs(checker.compare_evidence(replay), True)
        self.assertIs(checker.compare_evidence(exchanged), True)
        self.assertFalse(hasattr(checker, "authenticate_source"))


if __name__ == "__main__":
    unittest.main()
