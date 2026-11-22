"""Fail-closed Mint A/B forensic checkpoint contracts (no guests, no Windows)."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import subprocess

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows_mint_ab_checkpoint as ab


class MintAbCheckpointContracts(unittest.TestCase):
    def test_absent_explicit_checkpoint_consent_rejects_before_any_disk(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ab.AbCheckpointError, "separate Mint A/B"):
                ab.prepare_checkpoint(
                    base=Path("/dev/sda"), nvram=Path("/dev/nvram"),
                    overlay=Path("/dev/sdb"), ovmf_code=Path("/dev/ovmf"),
                    mint_root_uuid="00000000-0000-4000-8000-000000000001")

    def test_symlink_and_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "src"
            src.write_bytes(b"qcow2")
            for dst in (root / "linked", root / "symlink"):
                if dst.name == "linked":
                    os.link(src, dst)
                else:
                    dst.symlink_to(src)
                with self.subTest(dst=dst):
                    with self.assertRaisesRegex(ab.AbCheckpointError,
                                                "symlinked|hardlink"):
                        ab.file_guard(dst, root)

    def test_wrong_mode_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            target = folder / "arm-a.qcow2"
            target.write_bytes(b"test")
            target.chmod(0o644)
            with self.assertRaisesRegex(ab.AbCheckpointError, "permissions"):
                ab.file_guard(target, folder, 0o600)

    def test_foreign_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            target = folder / "arm-a.qcow2"
            target.write_bytes(b"test")
            with self.assertRaisesRegex(ab.AbCheckpointError, "foreign"):
                ab.file_guard(target, folder / "elsewhere")

    def test_duplicate_destination_rejected_before_convert(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            image = folder / "arm-a.qcow2"
            image.write_bytes(b"existing")
            with patch.object(ab, "command") as command:
                with self.assertRaisesRegex(ab.AbCheckpointError, "reused"):
                    ab.standalone(folder / "reference.qcow2", image, folder)
                command.assert_not_called()

    def test_independent_image_must_have_no_backing_or_encryption(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sample.qcow2"
            for extra in ({"backing-filename": "/tmp/shared.qcow2"},
                          {"full-backing-filename": "/tmp/shared.qcow2"},
                          {"encrypted": True},
                          {"virtual-size": ab.VIRTUAL_BYTES - 512}):
                import json
                payload = {"format": "qcow2",
                           "virtual-size": ab.VIRTUAL_BYTES} | extra
                with self.subTest(extra=extra):
                    with patch.object(ab, "command",
                            return_value=subprocess.CompletedProcess(
                                [], 0, json.dumps(payload), "")):
                        with self.assertRaisesRegex(ab.AbCheckpointError,
                                                    "not independent"):
                            ab.image_info(path)

    def test_ovmf_independent_clones_match_bytewise(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "trial-vars.fd"
            src.write_bytes(b"var" * 1000)
            dst_a = root / "arm-a-vars.fd"
            dst_b = root / "arm-b-vars.fd"
            sha = ab.clone_vars(src, dst_a, root)
            self.assertEqual(sha, ab.clone_vars(src, dst_b, root))
            self.assertEqual(len({src.stat().st_ino, dst_a.stat().st_ino,
                                  dst_b.stat().st_ino}), 3)
            self.assertEqual(dst_a.stat().st_mode & 0o777, 0o600)

    def test_missing_tpm_is_explicitly_not_applicable(self):
        with tempfile.TemporaryDirectory() as d:
            info = ab.clone_tpm_state(None, Path(d))
            self.assertIs(info["applicable"], False)

    def test_optional_stopped_tpm_state_has_two_independent_owned_clones(self):
        """A copied TPM state is not a real TPM boot/recovery proof."""
        import hashlib

        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root)
            state = workspace / "swtpm-state"
            state.mkdir(mode=0o700)
            original = state / "tpm2-00.permall"
            original.write_bytes(b"synthetic-not-a-real-tpm-state")
            directory = workspace / ab.AB_DIR
            directory.mkdir(mode=0o700)
            proof = ab.clone_tpm_state(state, directory)
            self.assertTrue(proof["applicable"])
            variants = [
                directory / proof["armA"] / "tpm2-00.permall",
                directory / proof["armB"] / "tpm2-00.permall",
            ]
            self.assertEqual(
                len({original.stat().st_ino, *[f.stat().st_ino for f in variants]}),
                3,
            )
            digest = hashlib.sha256(original.read_bytes()).hexdigest()
            self.assertEqual(proof["sourceHashes"]["tpm2-00.permall"], digest)
            self.assertTrue(all(
                hashlib.sha256(f.read_bytes()).hexdigest() == digest for f in variants
            ))

    def test_tpm_rejects_links_and_unexpected_socket(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "swtpm-state"
            src.mkdir()
            data = src / "state.bin"
            data.write_bytes(b"state")
            directory = root / "mint-ab-independent-checkpoint"
            directory.mkdir()
            os.link(data, src / "bad-hardlink")
            with self.assertRaisesRegex(ab.AbCheckpointError, "unsafe TPM"):
                ab.clone_tpm_state(src, directory)

    def test_recovery_must_detect_corruption_before_restoring(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            reference, arm = root / "reference.qcow2", root / "arm-a.qcow2"
            reference.write_bytes(b"reference")
            reference.chmod(0o400)
            arm.write_bytes(b"arm")
            arm.chmod(0o600)
            responses = [
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", ""),
            ]
            import windows_mint_ab_capacity as cap
            with patch.object(ab, "choose_injection_offset",
                              return_value=127 * 1024**3), \
                 patch.object(cap, "qemu_fully_allocated_bytes",
                              return_value=1024), \
                 patch.object(ab, "assert_detached_from_processes"), \
                 patch.object(ab, "command", side_effect=responses):
                with self.assertRaisesRegex(ab.AbCheckpointError, "not independently detected"):
                    ab.reproduce_restore(reference, arm, root)
            self.assertTrue(arm.exists(), "must not destroy arm on unproved recovery")

    def test_enospc_during_atomic_restore_leaves_arm_and_reference(self):
        import errno
        import windows_mint_ab_capacity as cap
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            reference, arm = root/"reference.qcow2", root/"arm-a.qcow2"
            reference.write_bytes(b"reference")
            reference.chmod(0o400)
            arm.write_bytes(b"arm")
            arm.chmod(0o600)
            old_arm, old_ref = arm.read_bytes(), reference.read_bytes()
            def fake_command(argv, **kwargs):
                if argv[0] == "qemu-io":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[0] == "qemu-img" and "compare" in argv:
                    return subprocess.CompletedProcess(argv, 1, "", "")
                raise AssertionError("unexpected command")
            with patch.object(ab, "choose_injection_offset",
                              return_value=127*1024**3), \
                 patch.object(cap, "qemu_fully_allocated_bytes",
                              return_value=ab.VIRTUAL_BYTES), \
                 patch.object(ab, "assert_detached_from_processes"), \
                 patch.object(ab, "image_info"), \
                 patch.object(ab.os, "statvfs", return_value=type(
                     "FakeFs", (), {"f_bavail": 1_000_000_000,
                                    "f_frsize": 4096})()), \
                 patch.object(ab, "command", side_effect=fake_command), \
                 patch.object(ab, "standalone",
                              side_effect=OSError(errno.ENOSPC, "disk full")):
                with self.assertRaises(OSError) as error:
                    ab.reproduce_restore(reference, arm, root)
            self.assertEqual(error.exception.errno, errno.ENOSPC)
            self.assertEqual(arm.read_bytes(), old_arm)
            self.assertEqual(reference.read_bytes(), old_ref)
            self.assertFalse((root/"checkpoint.json").exists())

    def test_wrong_fifth_extent_rejects_injection_before_any_write(self):
        import struct
        import windows_cachyos_overlay_reboot as reboot
        import windows_cachyos_qcow2_gpt_readonly as gpt
        entry = bytearray(128*128)
        total = ab.VIRTUAL_BYTES//512
        for i in range(5):
            entry[i*128:i*128+16] = b"x"*16
            begin = 2048 if i == 0 else (2048 + i*100000)
            end = begin + 99999 if i != 4 else total-40
            struct.pack_into("<QQ", entry, i*128+32, begin, end)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"reference.qcow2"
            with patch.object(reboot, "gpt_windows",
                              return_value=(b"x"*1048576, b"y"*1048576)), \
                 patch.object(gpt, "header_at", return_value=b"GPT"), \
                 patch.object(gpt, "part_array", return_value=bytes(entry)):
                with self.assertRaisesRegex(ab.AbCheckpointError,
                                            "no verified unallocated"):
                    ab.choose_injection_offset(path)

    def test_valid_gpt_free_extent_is_derived_from_fifth_end(self):
        import struct
        import windows_cachyos_overlay_reboot as reboot
        import windows_cachyos_qcow2_gpt_readonly as gpt
        entry = bytearray(128*128)
        spans = []
        for i in range(5):
            entry[i*128:i*128+16] = b"x"*16
            start = 2048 + i*100000
            end = start + 99999
            spans.append((start, end))
            struct.pack_into("<QQ", entry, i*128+32, start, end)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"reference.qcow2"
            with patch.object(reboot, "gpt_windows",
                              return_value=(b"x"*1048576, b"y"*1048576)), \
                 patch.object(gpt, "header_at", return_value=b"GPT"), \
                 patch.object(gpt, "part_array", return_value=bytes(entry)):
                offset = ab.choose_injection_offset(path)
            self.assertGreater(offset, spans[-1][1]*512)
            self.assertLess(offset+ab.WRITE_SIZE, ab.VIRTUAL_BYTES-34*512)

    def test_atomic_restore_requires_detached_QEMU_file_handles(self):
        with patch.object(ab.shutil, "which", return_value="/usr/bin/fuser"), \
             patch.object(ab, "command",
                          return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaisesRegex(ab.AbCheckpointError, "still open"):
                ab.assert_detached_from_processes(Path("/tmp/owned-arm.qcow2"))

    def test_atomic_restore_rejects_missing_fuser(self):
        with patch.object(ab.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ab.AbCheckpointError, "fuser is required"):
                ab.assert_detached_from_processes(Path("/tmp/owned-arm.qcow2"))

    def test_restore_rejects_underestimated_storage_bound_before_clone(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            ref = folder/"reference.qcow2"
            arm = folder/"arm-a.qcow2"
            ref.write_bytes(b"reference")
            ref.chmod(0o400)
            arm.write_bytes(b"arm")
            arm.chmod(0o600)
            with patch.object(ab, "standalone") as convert:
                with self.assertRaisesRegex(ab.AbCheckpointError, "underestimated"):
                    ab.atomic_restore_owned_arm(
                        ref, arm, folder,
                        expected_virtual_bytes=64*1024**2,
                        fully_allocated_bound=1,
                    )
                convert.assert_not_called()

    def test_source_never_uses_production_disk_utilities_or_merge_semantics(self):
        code = (Path(__file__).parent / "tools" /
                "windows_mint_ab_checkpoint.py").read_text()
        for unsafe in ("sgdisk", "wipefs", "mkfs", "parted", "mount -o rw",
                       "os.system(", "ACCEPT_NO_WRITER", "qemu-img rebase"):
            with self.subTest(command=unsafe):
                self.assertNotIn(unsafe, code)
        self.assertIn('"qemu-img", "compare"', code)
        self.assertIn('"qemu-img", "convert"', code)
        self.assertIn("controlRecoveredAfterFaultInjection", code)


if __name__ == "__main__":
    unittest.main()
