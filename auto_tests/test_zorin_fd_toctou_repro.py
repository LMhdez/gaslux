"""FD-bound GPT regression tests on disposable synthetic RAW fixtures.

The real canonical Safety #307 inspect_gpt_fd implementation is used unchanged.
Race hooks change physical fixture inodes/bytes but NEVER mock GPT results or
bypass a second vulnerable pathname opening.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

import libertix_disk_identity_gate as safety
import test_zorin_synthetic_writeset as fixture
import zorin_synthetic_writeset as verifier


class DescriptorPathToctouAfterFix(unittest.TestCase):
    def setUp(self):
        self.case = fixture.ZorinSyntheticWriteSetTests(
            "test_no_change_passes_with_canonical_fd_binding"
        )
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root
        self.policy = self.case.policy
        self.original_inodes = {
            name: (self.root / name).stat().st_ino
            for name in ("baseline.raw", "trial.raw", "checkpoint.raw")
        }
        self.swaps = []

    def replace_regular(self, name, *, protected_change=True):
        """Swap to a different inode with valid, same-identity GPT bytes."""
        path = self.root / name
        replacement = self.root / ("foreign-" + name)
        raw = bytearray(fixture.generated_valid_gpt())
        if protected_change:
            raw[fixture.PARTS[2][1] * fixture.SECTOR + 90] ^= 0xAF
        replacement.write_bytes(raw)
        os.replace(path, self.root / ("original-" + name))
        os.replace(replacement, path)
        self.assertNotEqual(path.stat().st_ino, self.original_inodes[name])
        self.swaps.append(name)

    def expect_source_race(self, name):
        with self.assertRaises(verifier.WriteSetRefused) as caught:
            verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(caught.exception.code, "E_SOURCE_RACE")
        self.assertIn(name, self.swaps)

    def test_control_no_swap_passes_without_write_authority(self):
        result = verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(result["result"], "SYNTHETIC_NO_CHANGE")
        self.assertEqual(result["authorization"], "DENY_NO_WRITER")
        self.assertFalse(result["productionWriteAuthorized"])

    def test_canonical_gpt_reader_never_reopens_raw_path(self):
        original_open = os.open
        counts = {name: 0 for name in self.original_inodes}

        def audit_open(path, flags, *args, **kwargs):
            for name in counts:
                if isinstance(path, (str, os.PathLike)) and Path(path) == self.root / name:
                    counts[name] += 1
                    self.assertEqual(counts[name], 1, "RAW path reopened after owned_fd")
            return original_open(path, flags, *args, **kwargs)

        with patch.object(safety.os, "open", side_effect=audit_open):
            result = verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(result["result"], "SYNTHETIC_NO_CHANGE")
        self.assertEqual(set(counts.values()), {1})

    def test_baseline_swapped_after_owned_fd_is_refused(self):
        original = verifier.owned_fd

        def change(root, name, maximum):
            fd, st = original(root, name, maximum)
            if name == "baseline.raw":
                self.replace_regular(name)
            return fd, st

        with patch.object(verifier, "owned_fd", side_effect=change):
            self.expect_source_race("baseline.raw")

    def test_trial_swapped_after_owned_fd_is_refused(self):
        original = verifier.owned_fd

        def change(root, name, maximum):
            fd, st = original(root, name, maximum)
            if name == "trial.raw":
                self.replace_regular(name)
            return fd, st

        with patch.object(verifier, "owned_fd", side_effect=change):
            self.expect_source_race("trial.raw")

    def test_checkpoint_swapped_after_owned_fd_is_refused(self):
        original = verifier.owned_fd

        def change(root, name, maximum):
            fd, st = original(root, name, maximum)
            if name == "checkpoint.raw":
                self.replace_regular(name)
            return fd, st

        with patch.object(verifier, "owned_fd", side_effect=change):
            self.expect_source_race("checkpoint.raw")

    def test_swapped_before_real_gpt_inspection_is_refused(self):
        original = verifier.read_gpt
        target = self.original_inodes["trial.raw"]

        def intercept(fd, policy):
            if os.fstat(fd).st_ino == target:
                self.replace_regular("trial.raw")
            # Calls the REAL Safety #307 inspect_gpt_fd; no fake result.
            return original(fd, policy)

        with patch.object(verifier, "read_gpt", side_effect=intercept):
            self.expect_source_race("trial.raw")

    def test_swap_during_canonical_os_dup_is_refused(self):
        """Change pathname exactly as canonical GPT reader duplicates pinned fd."""
        original_dup = os.dup
        target = self.original_inodes["trial.raw"]

        def intercept(fd):
            if os.fstat(fd).st_ino == target and not self.swaps:
                self.replace_regular("trial.raw")
            return original_dup(fd)

        with patch.object(safety.os, "dup", side_effect=intercept):
            self.expect_source_race("trial.raw")

    def test_swap_between_gpt_and_raw_comparison_is_refused(self):
        original = verifier.compare_raw

        def intercept(baseline_fd, trial_fd, policy):
            self.replace_regular("trial.raw")
            return original(baseline_fd, trial_fd, policy)

        with patch.object(verifier, "compare_raw", side_effect=intercept):
            self.expect_source_race("trial.raw")

    def test_same_guid_regular_swap_is_refused(self):
        original = verifier.read_gpt
        target = self.original_inodes["trial.raw"]

        def intercept(fd, policy):
            if os.fstat(fd).st_ino == target:
                self.replace_regular("trial.raw", protected_change=False)
            return original(fd, policy)

        with patch.object(verifier, "read_gpt", side_effect=intercept):
            self.expect_source_race("trial.raw")

    def test_foreign_partuuid_valid_gpt_in_place_is_refused(self):
        (self.root / "trial.raw").write_bytes(
            fixture.generated_valid_gpt(root_guid="8a98e4fc-37fa-4b34-8017-52d7e4bff9d1")
        )
        with self.assertRaises(verifier.WriteSetRefused) as caught:
            verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(caught.exception.code, "E_PARTUUID_CHANGED")

    def test_symlink_after_owned_fd_is_refused(self):
        original = verifier.read_gpt
        target = self.original_inodes["trial.raw"]

        def intercept(fd, policy):
            if os.fstat(fd).st_ino == target:
                os.replace(self.root / "trial.raw", self.root / "original-trial.raw")
                (self.root / "trial.raw").symlink_to("original-trial.raw")
                self.swaps.append("trial.raw")
            return original(fd, policy)

        with patch.object(verifier, "read_gpt", side_effect=intercept):
            self.expect_source_race("trial.raw")

    def test_hardlink_after_owned_fd_is_refused(self):
        original = verifier.read_gpt
        target = self.original_inodes["trial.raw"]

        def intercept(fd, policy):
            if os.fstat(fd).st_ino == target:
                foreign = self.root / "foreign-valid.raw"
                foreign.write_bytes(fixture.generated_valid_gpt())
                os.replace(self.root / "trial.raw", self.root / "original-trial.raw")
                os.link(foreign, self.root / "trial.raw")
                self.swaps.append("trial.raw")
                self.assertEqual((self.root / "trial.raw").stat().st_nlink, 2)
            return original(fd, policy)

        with patch.object(verifier, "read_gpt", side_effect=intercept):
            self.expect_source_race("trial.raw")

    def test_closed_descriptor_has_explicit_refusal(self):
        original = verifier.read_gpt
        target = self.original_inodes["trial.raw"]
        closed = False

        def intercept(fd, policy):
            nonlocal closed
            if os.fstat(fd).st_ino == target and not closed:
                closed = True
                os.close(fd)
            return original(fd, policy)

        with patch.object(verifier, "read_gpt", side_effect=intercept):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertTrue(closed)
        self.assertEqual(caught.exception.code, "E_GPT_INVALID")

    def test_primary_gpt_in_place_during_fd_inspection_is_refused(self):
        system_pread = os.pread
        target = self.original_inodes["trial.raw"]
        changed = False

        def intercept(fd, length, offset):
            nonlocal changed
            result = system_pread(fd, length, offset)
            if not changed and offset == fixture.SECTOR and os.fstat(fd).st_ino == target:
                changed = True
                self.case.mutate("trial.raw", fixture.SECTOR + 60)
            return result

        with patch.object(safety.os, "pread", side_effect=intercept):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertTrue(changed)
        self.assertEqual(caught.exception.code, "E_GPT_INVALID")

    def test_short_read_in_canonical_gpt_is_refused(self):
        """Actual GPT reader receives fewer bytes than the primary sector."""
        system_pread = os.pread
        trial_inode = self.original_inodes["trial.raw"]
        shortened = False

        def intercept(fd, length, offset):
            nonlocal shortened
            result = system_pread(fd, length, offset)
            if (
                not shortened
                and offset == fixture.SECTOR
                and length == fixture.SECTOR
                and os.fstat(fd).st_ino == trial_inode
            ):
                shortened = True
                return result[:-1]
            return result

        with patch.object(safety.os, "pread", side_effect=intercept):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertTrue(shortened)
        self.assertEqual(caught.exception.code, "E_GPT_INVALID")

    def test_short_read_in_full_raw_comparison_is_refused(self):
        """The real RAW comparator refuses a short read after valid FD GPT."""
        system_pread = os.pread
        original_compare = verifier.compare_raw
        trial_inode = self.original_inodes["trial.raw"]
        shortened = False

        def intercept_compare(baseline_fd, trial_fd, policy):
            def short_read(fd, length, offset):
                nonlocal shortened
                result = system_pread(fd, length, offset)
                if (
                    not shortened
                    and os.fstat(fd).st_ino == trial_inode
                    and offset == 0
                    and length == verifier.BLOCK
                ):
                    shortened = True
                    return result[:-1]
                return result

            with patch.object(verifier.os, "pread", side_effect=short_read):
                return original_compare(baseline_fd, trial_fd, policy)

        with patch.object(verifier, "compare_raw", side_effect=intercept_compare):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertTrue(shortened)
        self.assertEqual(caught.exception.code, "E_TRUNCATED_SOURCE")

    def test_authenticated_geometry_4096_against_512_gpt_is_refused(self):
        """The declared 4K sector geometry must not reinterpret 512B GPT."""
        altered = self.policy.copy()
        altered["diskIdentity"] = {**self.policy["diskIdentity"]}
        altered["logicalSectorBytes"] = 4096
        altered["diskIdentity"]["logicalSectorSizeBytes"] = 4096
        with self.assertRaises(verifier.WriteSetRefused) as caught:
            verifier.verify_private_synthetic(self.root, altered)
        self.assertEqual(caught.exception.code, "E_GPT_INVALID")

    def test_stale_disk_geometry_is_refused_before_any_gpt_read(self):
        """Mismatched policy geometry cannot be trusted as a target plan."""
        altered = self.policy.copy()
        altered["diskBytes"] = self.policy["diskBytes"] + fixture.SECTOR
        with self.assertRaises(verifier.WriteSetRefused) as caught:
            verifier.verify_private_synthetic(self.root, altered)
        self.assertEqual(caught.exception.code, "E_POLICY_GEOMETRY")

    def test_foreign_artifact_provenance_is_refused(self):
        """Matching data bytes do not convert a foreign receipt into ownership."""
        import json

        receipt = self.case.receipt.copy()
        receipt["provenance"] = "FOREIGN_BACKEND"
        (self.root / "receipt.json").write_text(json.dumps(receipt))
        with self.assertRaises(verifier.WriteSetRefused) as caught:
            verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(caught.exception.code, "E_FOREIGN_TRANSACTION")

    def test_missing_transaction_ownership_is_refused(self):
        """A diagnostic synthetic owner label cannot be substituted by CachyOS."""
        altered = self.policy.copy()
        altered["ownerLabel"] = "GASLUX-CACHYOS-ROOT"
        with self.assertRaises(verifier.WriteSetRefused) as caught:
            verifier.verify_private_synthetic(self.root, altered)
        self.assertEqual(caught.exception.code, "E_POLICY_SCHEMA")

    def test_primary_gpt_mutation_after_inspection_is_refused(self):
        """Mutating GPT after the canonical read cannot become a clean verdict."""
        original_compare = verifier.compare_raw
        mutated = False

        def intercept(baseline_fd, trial_fd, policy):
            nonlocal mutated
            mutated = True
            self.case.mutate("trial.raw", fixture.SECTOR + 64)
            return original_compare(baseline_fd, trial_fd, policy)

        with patch.object(verifier, "compare_raw", side_effect=intercept):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertTrue(mutated)
        self.assertEqual(caught.exception.code, "E_GPT_BYTES_CHANGED")

    def test_late_in_place_mutation_after_byte_comparison_is_refused(self):
        """A late write on the still-pinned RAW FD invalidates final metadata."""
        original_guard = verifier.close_guard
        trial_inode = self.original_inodes["trial.raw"]
        mutated = False

        def intercept(fd, original):
            nonlocal mutated
            if not mutated and os.fstat(fd).st_ino == trial_inode:
                mutated = True
                self.case.mutate("trial.raw", fixture.PARTS[2][1] * fixture.SECTOR + 31)
            return original_guard(fd, original)

        with patch.object(verifier, "close_guard", side_effect=intercept):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertTrue(mutated)
        self.assertEqual(caught.exception.code, "E_SOURCE_RACE")

    def test_esp_entry_swap_between_stat_and_open_is_refused(self):
        system_open = os.open
        original = self.root / "esp-trial/EFI/Microsoft/Boot/bootmgfw.efi"
        switched = False

        def intercept(path, flags, *args, **kwargs):
            nonlocal switched
            if (
                str(path) == "bootmgfw.efi"
                and "dir_fd" in kwargs
                and Path(os.readlink("/proc/self/fd/" + str(kwargs["dir_fd"]))) == original.parent
                and not switched
            ):
                switched = True
                foreign = self.root / "foreign-efi"
                foreign.write_bytes(b"altered")
                os.replace(original, self.root / "original-efi")
                os.replace(foreign, original)
            return system_open(path, flags, *args, **kwargs)

        with patch.object(verifier.os, "open", side_effect=intercept):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(caught.exception.code, "E_ESP_RACE")
        self.assertTrue(switched)

    def test_esp_directory_replaced_between_stat_and_open_is_refused(self):
        system_open = os.open
        target = self.root / "esp-trial/EFI/Microsoft/Boot"
        original_inode = target.stat().st_ino
        did_change = False

        def intercept(path, flags, *args, **kwargs):
            nonlocal did_change
            if (
                str(path) == "Boot"
                and "dir_fd" in kwargs
                and Path(os.readlink("/proc/self/fd/" + str(kwargs["dir_fd"]))) == target.parent
                and not did_change
            ):
                did_change = True
                replacement = self.root / "replacement-boot-dir"
                replacement.mkdir()
                (replacement / "bootmgfw.efi").write_bytes(b"synthetic-windows")
                os.replace(target, self.root / "original-boot-dir")
                os.replace(replacement, target)
                self.assertNotEqual(target.stat().st_ino, original_inode)
            return system_open(path, flags, *args, **kwargs)

        with patch.object(verifier.os, "open", side_effect=intercept):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertTrue(did_change)
        self.assertEqual(caught.exception.code, "E_ESP_RACE")

    def test_esp_open_dirfd_does_not_follow_replaced_pathname(self):
        system_scandir = os.scandir
        target = self.root / "esp-trial/EFI/Microsoft/Boot"
        original_inode = target.stat().st_ino
        did_change = False

        def intercept(directory):
            nonlocal did_change
            if isinstance(directory, int) and not did_change:
                opened = Path(os.readlink("/proc/self/fd/" + str(directory)))
                if opened == target:
                    did_change = True
                    moved = self.root / "original-boot-dir"
                    replacement = self.root / "replacement-boot-dir"
                    replacement.mkdir()
                    (replacement / "bootmgfw.efi").write_bytes(b"foreign")
                    os.replace(target, moved)
                    os.replace(replacement, target)
                    self.assertNotEqual(target.stat().st_ino, original_inode)
            return system_scandir(directory)

        with patch.object(verifier.os, "scandir", side_effect=intercept):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertTrue(did_change)
        self.assertEqual(caught.exception.code, "E_ESP_RACE")


if __name__ == "__main__":
    unittest.main()
