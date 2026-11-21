"""Deterministic BEFORE-FIX TOCTOU reproduction using disposable synthetic GPT bytes.

The fixture and pinned Safety #265 GPT reader are reused without modification.
These tests reproduce the original race, then require fail-closed refusal
in the mitigation commit. They do not authorize any installation.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

import test_zorin_synthetic_writeset as fixture
import zorin_synthetic_writeset as verifier
import libertix_disk_identity_gate as safety


class DescriptorPathToctouBeforeFix(unittest.TestCase):
    def setUp(self):
        self.case = fixture.ZorinSyntheticWriteSetTests("test_positive_no_change")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root
        self.policy = self.case.policy
        self.original_inodes = {
            name: (self.root / name).stat().st_ino
            for name in ("baseline.raw", "trial.raw", "checkpoint.raw")
        }
        self.swaps = []

    def replace_regular(self, name, *, foreign_partuuid=False, protected_change=True):
        path = self.root / name
        replacement = self.root / ("foreign-" + name)
        new_guid = (
            "8a98e4fc-37fa-4b34-8017-52d7e4bff9d1"
            if foreign_partuuid else fixture.ROOT_GUID
        )
        raw = bytearray(fixture.generated_valid_gpt(root_guid=new_guid))
        if protected_change:
            raw[fixture.PARTS[2][1] * fixture.SECTOR + 90] ^= 0xAF
        replacement.write_bytes(raw)
        os.replace(path, self.root / ("original-" + name))
        os.replace(replacement, path)
        self.assertNotEqual(path.stat().st_ino, self.original_inodes[name])
        self.swaps.append(name)

    def expect_binding_refusal(self, name):
        with self.assertRaises(verifier.WriteSetRefused) as caught:
            verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(caught.exception.code, "E_GPT_FD_BINDING_REQUIRED")
        self.assertIn(name, self.swaps)

    def test_control_no_swap_requires_safety_fd_api(self):
        with self.assertRaises(verifier.WriteSetRefused) as caught:
            verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(caught.exception.code, "E_GPT_FD_BINDING_REQUIRED")

    def test_baseline_regular_swap_before_gpt_is_refused(self):
        original = verifier.read_gpt

        def change(root, name, policy):
            if name == "baseline.raw":
                self.replace_regular(name)
            return original(root, name, policy)

        with patch.object(verifier, "read_gpt", side_effect=change):
            self.expect_binding_refusal("baseline.raw")

    def test_trial_regular_swap_before_gpt_is_refused(self):
        original = verifier.read_gpt

        def change(root, name, policy):
            if name == "trial.raw":
                self.replace_regular(name)
            return original(root, name, policy)

        with patch.object(verifier, "read_gpt", side_effect=change):
            self.expect_binding_refusal("trial.raw")

    def test_trial_replaced_at_actual_safety_os_open_is_refused(self):
        original_read = verifier.read_gpt
        system_open = os.open

        def read_with_open_race(root, name, policy):
            if name != "trial.raw":
                return original_read(root, name, policy)

            def intercept(path, flags, *args, **kwargs):
                if Path(path) == self.root / "trial.raw":
                    self.replace_regular("trial.raw")
                return system_open(path, flags, *args, **kwargs)

            with patch.object(safety.os, "open", side_effect=intercept):
                return original_read(root, name, policy)

        with patch.object(verifier, "read_gpt", side_effect=read_with_open_race):
            self.expect_binding_refusal("trial.raw")

    def test_checkpoint_path_swap_after_original_descriptor_is_refused(self):
        original = verifier.owned_fd

        def change(root, name, maximum):
            fd, stat_result = original(root, name, maximum)
            if name == "checkpoint.raw":
                self.replace_regular(name)
            return fd, stat_result

        with patch.object(verifier, "owned_fd", side_effect=change):
            self.expect_binding_refusal("checkpoint.raw")

    def test_path_replaced_between_gpt_and_byte_comparison_is_refused(self):
        original = verifier.compare_raw

        def change(a, b, policy):
            self.replace_regular("trial.raw")
            return original(a, b, policy)

        with patch.object(verifier, "compare_raw", side_effect=change):
            self.expect_binding_refusal("trial.raw")

    def test_foreign_partuuid_gpt_is_refused(self):
        original = verifier.read_gpt

        def change(root, name, policy):
            if name == "trial.raw":
                self.replace_regular(name, foreign_partuuid=True)
            return original(root, name, policy)

        with patch.object(verifier, "read_gpt", side_effect=change):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(caught.exception.code, "E_PARTUUID_CHANGED")

    def test_symlink_after_owned_descriptor_is_refused(self):
        original = verifier.read_gpt

        def change(root, name, policy):
            if name == "trial.raw":
                os.replace(self.root / name, self.root / "original-trial.raw")
                (self.root / name).symlink_to("original-trial.raw")
            return original(root, name, policy)

        with patch.object(verifier, "read_gpt", side_effect=change):
            with self.assertRaises(verifier.WriteSetRefused) as caught:
                verifier.verify_private_synthetic(self.root, self.policy)
        self.assertEqual(caught.exception.code, "E_GPT_INVALID")

    def test_hardlink_replacement_before_gpt_is_refused(self):
        original = verifier.read_gpt

        def change(root, name, policy):
            if name == "trial.raw":
                foreign = self.root / "foreign-valid.raw"
                foreign.write_bytes(fixture.generated_valid_gpt())
                os.replace(self.root / name, self.root / "original-trial.raw")
                os.link(foreign, self.root / name)
                self.swaps.append("trial.raw")
                self.assertEqual((self.root / name).stat().st_nlink, 2)
            return original(root, name, policy)

        with patch.object(verifier, "read_gpt", side_effect=change):
            self.expect_binding_refusal("trial.raw")

    def test_esp_entry_swap_between_stat_and_open_is_refused(self):
        system_open = os.open
        original = self.root / "esp-trial/EFI/Microsoft/Boot/bootmgfw.efi"
        switched = False

        def intercept(path, flags, *args, **kwargs):
            nonlocal switched
            if str(path) == "bootmgfw.efi" and "dir_fd" in kwargs and not switched:
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
            if str(path) == "Boot" and "dir_fd" in kwargs and not did_change:
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
        # A rename AFTER opening the pinned directory may not redirect
        # the scanner to the replacement tree. The final name binding
        # check must still refuse the transient mutation.
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
