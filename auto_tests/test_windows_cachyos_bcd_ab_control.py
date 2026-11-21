"""Pure contracts for the matched Windows-only/CachyOS BCD A/B experiment."""
from __future__ import annotations

from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import windows_cachyos_bcd_ab_control as lab
from windows_cachyos_cow_checkpoint import CheckpointError


def forensic(before: str, after: str, changed: int, spans: list[dict]) -> dict:
    return {
        "prebootBcdSha256": before,
        "postbootBcdSha256": after,
        "changedByteCount": changed,
        "firstChangedByteSpans": spans,
    }


class BcdAbControlContracts(unittest.TestCase):
    def test_windows_only_control_reproduces_identical_bcd_change(self):
        before = "a" * 64
        after = "b" * 64
        span = [{"offset": 4, "length": 1}]
        result = lab.compare_bcd_ab(
            forensic(before, after, 1, span),
            forensic(before, after, 1, span),
        )
        self.assertTrue(result["initialBcdEqual"])
        self.assertTrue(result["controlAndTreatmentPostBootBcdEqual"])
        self.assertEqual(
            result["classification"],
            "WINDOWS_ONLY_CONTROL_REPRODUCED_IDENTICAL_BCD_MUTATION;"
            " NO_ADDITIONAL_CACHYOS_BCD_DELTA",
        )
        self.assertFalse(result["processAttributionProven"])
        self.assertFalse(result["approvedMutation"])
        self.assertFalse(result["releaseEligible"])

    def test_treatment_only_bcd_change_is_association_not_process_attribution(self):
        result = lab.compare_bcd_ab(
            forensic("a" * 64, "a" * 64, 0, []),
            forensic("a" * 64, "b" * 64, 7, [{"offset": 4096, "length": 7}]),
        )
        self.assertEqual(result["classification"], "TREATMENT_ONLY_BCD_MUTATION; TREATMENT_ASSOCIATION_OR_WINDOWS_NONDETERMINISM")
        self.assertTrue(result["initialBcdEqual"])
        self.assertFalse(result["processAttributionProven"])

    def test_different_postboot_hives_are_not_overattributed(self):
        result = lab.compare_bcd_ab(
            forensic("a" * 64, "b" * 64, 4, [{"offset": 4, "length": 4}]),
            forensic("a" * 64, "c" * 64, 4, [{"offset": 8, "length": 4}]),
        )
        self.assertEqual(
            result["classification"],
            "POSTBOOT_BCD_STATES_DIFFER;"
            " TREATMENT_ASSOCIATION_OR_WINDOWS_NONDETERMINISM",
        )
        self.assertFalse(result["controlAndTreatmentPostBootBcdEqual"])
        self.assertFalse(result["first64ChangedSpansEqual"])

    def test_initial_bcd_mismatch_invalidates_experiment(self):
        result = lab.compare_bcd_ab(
            forensic("a" * 64, "b" * 64, 1, []),
            forensic("c" * 64, "d" * 64, 1, []),
        )
        self.assertEqual(result["classification"], "INVALID_INITIAL_BCD_MISMATCH")
        self.assertFalse(result["initialBcdEqual"])

    def test_no_change_in_either_arm(self):
        result = lab.compare_bcd_ab(
            forensic("a" * 64, "a" * 64, 0, []),
            forensic("a" * 64, "a" * 64, 0, []),
        )
        self.assertEqual(result["classification"], "NO_BCD_MUTATION_IN_EITHER_ARM")

    def test_bcd_forensic_bounds_spans_but_hashes_the_complete_offset_set(self):
        before = b"regf" + b"\\x00" * 4092
        changed = bytearray(before)
        for offset in range(4, 140, 2):
            changed[offset] = 1
        result = lab.summarize_bcd_difference(before, bytes(changed))
        self.assertEqual(result["changedByteCount"], 68)
        self.assertEqual(result["changedRunCount"], 68)
        self.assertEqual(len(result["firstChangedByteSpans"]), 64)
        self.assertTrue(result["truncatedToFirst64Spans"])
        self.assertEqual(len(result["changedOffsetSetSha256"]), 64)
        self.assertEqual(len(result["changedSpansSha256"]), 64)

    def test_qemu_write_event_discovery_filters_read_only_and_unrelated_events(self):
        sample = """Available trace events:
bdrv_co_pwritev
bdrv_co_preadv
qcow2_cache_entry_write
virtio_blk_req_complete
usb_packet_state
"""
        self.assertEqual(
            lab.block_write_event_names(sample),
            ["bdrv_co_pwritev", "qcow2_cache_entry_write"],
        )

    def test_swtpm_interrupted_and_healthy_session_are_host_only(self):
        healthy = lab.tpm_session_observation(
            exit_before_cleanup=None, exit_after_cleanup=0,
            socket_present_before_cleanup=True)
        failed = lab.tpm_session_observation(
            exit_before_cleanup=127, exit_after_cleanup=127,
            socket_present_before_cleanup=False)
        self.assertTrue(healthy["emulatorRunningAtGuestSessionEnd"])
        self.assertFalse(healthy["emulatorExitedUnexpectedly"])
        self.assertFalse(failed["emulatorRunningAtGuestSessionEnd"])
        self.assertTrue(failed["emulatorExitedUnexpectedly"])
        self.assertEqual(failed["exitCodeBeforeCleanup"], 127)
        self.assertEqual(healthy["controlChannel"], "swtpm-ctrl")
        for snapshot in (healthy, failed):
            self.assertFalse(snapshot["guestBootVerified"])
            self.assertFalse(snapshot["productionStorageWritesAuthorized"])
            self.assertFalse(snapshot["releaseEligible"])

    def test_swtpm_emulator_uses_qemu_control_not_command_server(self):
        root = Path("/tmp/lab-bcd-ab-fixture")
        for state_name, socket_name in (
            (lab.TPM_CONTROL, "bcd-ab-control-tpm.sock"),
            (lab.TPM_TREATMENT, "bcd-ab-treatment-tpm.sock"),
        ):
            argv = lab.swtpm_emulator_command(
                root / state_name, root / socket_name
            )
            self.assertIn("--ctrl", argv)
            self.assertNotIn("--server", argv)
            self.assertEqual(argv[argv.index("--ctrl") + 1],
                             f"type=unixio,path={root / socket_name},mode=0600")
        with self.assertRaisesRegex(lab.BcdAbControlError, "unowned"):
            lab.swtpm_emulator_command(root / "unexpected", root / "foreign.sock")

    def test_tpm_state_digest_is_stable_for_independent_byte_copies(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "tpm"
            root.mkdir(mode=0o700)
            (root / "state.bin").write_bytes(b"synthetic TPM state")
            root.chmod(0o700)
            clone = Path(td) / "tpm-clone"
            import shutil
            shutil.copytree(root, clone)
            self.assertEqual(
                lab.tpm_state_tree_sha256(root),
                lab.tpm_state_tree_sha256(clone),
            )
            (clone / "state.bin").write_bytes(b"changed TPM state")
            self.assertNotEqual(
                lab.tpm_state_tree_sha256(root),
                lab.tpm_state_tree_sha256(clone),
            )

    def test_tpm_state_trees_must_not_share_hardlinked_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            left = root / "left"
            right = root / "right"
            left.mkdir(mode=0o700)
            right.mkdir(mode=0o700)
            source = left / "state.bin"
            source.write_bytes(b"independent TPM state")
            clone = right / "state.bin"
            clone.write_bytes(source.read_bytes())
            self.assertTrue(lab.tpm_state_trees_independent(left, right))
            clone.unlink()
            os.link(source, clone)
            self.assertFalse(lab.tpm_state_trees_independent(left, right))

    def test_windows_only_control_requires_explicit_consent_before_disk_access(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(
                lab, "validate_workspace",
                side_effect=AssertionError("disk validation must not run"),
            ):
                with self.assertRaisesRegex(
                    lab.BcdAbControlError, "separate Windows-only BCD A/B control consent"
                ):
                    lab.run_windows_only_bcd_control(
                        original=[], base=Path("/not-a-disk"),
                        nvram=Path("/not-a-vars"), geometry={}, checkpoint={},
                        staged={}, third={}, ext4={}, fourth={},
                        workspace=Path("/not-a-workspace"),
                    )

    def test_bcd_ab_rejects_invalid_hash_types(self):
        with self.assertRaisesRegex(lab.BcdAbControlError,
                                    "invalid hash, byte count or spans"):
            lab.compare_bcd_ab(
                forensic(None, "b" * 64, 1, []),
                forensic("a" * 64, "b" * 64, 1, []),
            )

    def test_tpm_state_digest_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "tpm"
            root.mkdir(mode=0o700)
            target = root / "real.bin"
            target.write_bytes(b"state")
            (root / "link.bin").symlink_to(target)
            with self.assertRaisesRegex(lab.BcdAbControlError, "symlink"):
                lab.tpm_state_tree_sha256(root)


    def _real_checkpoint(self, root):
        folder = root / lab.CHECKPOINT_DIR
        folder.mkdir(mode=0o700)
        disk = folder / lab.OVERLAY_NAME
        vars_b = folder / "trial-ovmf-variables.fd"
        disk.write_bytes(b"synthetic QCOW2 checkpoint" * 20)
        vars_b.write_bytes(b"synthetic OVMF VARS checkpoint" * 20)
        disk.chmod(0o600)
        vars_b.chmod(0o600)
        return folder, disk, vars_b

    def test_prepare_real_clones_in_correct_order(self):
        with tempfile.TemporaryDirectory() as d:
            folder, disk, vars_b = self._real_checkpoint(Path(d))
            a, v, disk_hash, vars_hash = lab.prepare_matched_checkpoint_clones(folder)
            self.assertEqual(lab.sha256_file(a), disk_hash)
            self.assertEqual(lab.sha256_file(v), vars_hash)
            self.assertEqual(a.read_bytes(), disk.read_bytes())
            self.assertEqual(v.read_bytes(), vars_b.read_bytes())
            self.assertNotEqual(a.stat().st_ino, disk.stat().st_ino)
            self.assertNotEqual(v.stat().st_ino, vars_b.stat().st_ino)
            for p in (a, v):
                self.assertEqual(p.stat().st_uid, os.getuid())
                self.assertEqual(p.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_prepare_refuses_missing_source_and_reused_destinations(self):
        with tempfile.TemporaryDirectory() as d:
            folder, disk, vars_b = self._real_checkpoint(Path(d))
            vars_b.unlink()
            with self.assertRaises((FileNotFoundError, lab.BcdAbControlError)):
                lab.prepare_matched_checkpoint_clones(folder)
            self.assertFalse((folder / lab.WINDOWS_CONTROL_OVERLAY).exists())
        for target_name in (lab.WINDOWS_CONTROL_OVERLAY, lab.WINDOWS_CONTROL_VARS):
            with self.subTest(target_name=target_name), tempfile.TemporaryDirectory() as d:
                folder, disk, vars_b = self._real_checkpoint(Path(d))
                target = folder / target_name
                target.write_bytes(b"unrelated existing file")
                with self.assertRaisesRegex(lab.BcdAbControlError, "reused"):
                    lab.prepare_matched_checkpoint_clones(folder)
                self.assertEqual(target.read_bytes(), b"unrelated existing file")

    def test_prepare_refuses_symlinks_hardlinks_and_bad_modes(self):
        for kind in ("symlink", "hardlink", "source_mode", "directory_mode"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                folder, disk, vars_b = self._real_checkpoint(Path(d))
                if kind == "symlink":
                    vars_b.unlink()
                    vars_b.symlink_to(disk)
                elif kind == "hardlink":
                    vars_b.unlink()
                    os.link(disk, vars_b)
                elif kind == "source_mode":
                    vars_b.chmod(0o644)
                else:
                    folder.chmod(0o755)
                # The shared checkpoint guard intentionally rejects
                # redirected or linked inputs before the A/B layer runs.
                with self.assertRaises((lab.BcdAbControlError, CheckpointError)):
                    lab.prepare_matched_checkpoint_clones(folder)
                self.assertFalse((folder / lab.WINDOWS_CONTROL_OVERLAY).exists())
                self.assertFalse((folder / lab.WINDOWS_CONTROL_VARS).exists())

    def test_prepare_refuses_divergent_clone_and_cleans_owned_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            folder, disk, vars_b = self._real_checkpoint(Path(d))
            real_copy = lab._copy_owned
            def corrupt(source, target, mode):
                result = real_copy(source, target, mode)
                if target.name == lab.WINDOWS_CONTROL_VARS:
                    target.write_bytes(b"tampered clone")
                return result
            with mock.patch.object(lab, "_copy_owned", side_effect=corrupt):
                with self.assertRaisesRegex(lab.BcdAbControlError, "diverged"):
                    lab.prepare_matched_checkpoint_clones(folder)
            self.assertFalse((folder / lab.WINDOWS_CONTROL_OVERLAY).exists())
            self.assertFalse((folder / lab.WINDOWS_CONTROL_VARS).exists())
            self.assertTrue(disk.exists() and vars_b.exists())

    def test_prepare_cleans_both_clones_on_partial_second_copy(self):
        with tempfile.TemporaryDirectory() as d:
            folder, disk, vars_b = self._real_checkpoint(Path(d))
            real_copy = lab._copy_owned
            def fail_second(source, target, mode):
                if target.name == lab.WINDOWS_CONTROL_VARS:
                    with mock.patch.object(lab.shutil, "copyfileobj",
                                           side_effect=OSError("simulated disk full")):
                        return real_copy(source, target, mode)
                return real_copy(source, target, mode)
            with mock.patch.object(lab, "_copy_owned", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "simulated disk full"):
                    lab.prepare_matched_checkpoint_clones(folder)
            self.assertTrue(disk.exists() and vars_b.exists())
            self.assertFalse((folder / lab.WINDOWS_CONTROL_OVERLAY).exists())
            self.assertFalse((folder / lab.WINDOWS_CONTROL_VARS).exists())

    def test_prepare_refuses_source_modified_during_copy(self):
        with tempfile.TemporaryDirectory() as d:
            folder, disk, vars_b = self._real_checkpoint(Path(d))
            real_copy = lab.shutil.copyfileobj
            def concurrent_writer(src, dst, length):
                real_copy(src, dst, length=length)
                with disk.open("r+b") as writer:
                    writer.seek(0)
                    writer.write(b"changed")
            with mock.patch.object(lab.shutil, "copyfileobj",
                                   side_effect=concurrent_writer):
                with self.assertRaisesRegex(lab.BcdAbControlError, "stable"):
                    lab.prepare_matched_checkpoint_clones(folder)
            self.assertFalse((folder / lab.WINDOWS_CONTROL_OVERLAY).exists())

    def test_prepare_refuses_source_modified_between_two_clones(self):
        with tempfile.TemporaryDirectory() as d:
            folder, disk, vars_b = self._real_checkpoint(Path(d))
            real_copy = lab._copy_owned
            def source_changed(source, target, mode):
                result = real_copy(source, target, mode)
                if source == disk:
                    vars_b.write_bytes(b"modified before OVMF clone")
                return result
            with mock.patch.object(lab, "_copy_owned", side_effect=source_changed):
                with self.assertRaisesRegex(lab.BcdAbControlError, "diverged"):
                    lab.prepare_matched_checkpoint_clones(folder)
            self.assertFalse((folder / lab.WINDOWS_CONTROL_OVERLAY).exists())
            self.assertFalse((folder / lab.WINDOWS_CONTROL_VARS).exists())

    def test_prepare_refuses_reused_symlink_target_without_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            folder, disk, vars_b = self._real_checkpoint(Path(d))
            target = folder / lab.WINDOWS_CONTROL_VARS
            target.symlink_to(vars_b)
            with self.assertRaisesRegex(lab.BcdAbControlError, "reused"):
                lab.prepare_matched_checkpoint_clones(folder)
            self.assertTrue(target.is_symlink())
            self.assertFalse((folder / lab.WINDOWS_CONTROL_OVERLAY).exists())

    def test_clone_copy_refuses_reused_target_and_symlink_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.bin"
            source.write_bytes(b"owned")
            target = root / "clone.bin"
            lab._copy_owned(source, target, 0o600)
            self.assertEqual(target.read_bytes(), b"owned")
            self.assertEqual(target.stat().st_nlink, 1)
            with self.assertRaisesRegex(lab.BcdAbControlError, "reused"):
                lab._copy_owned(source, target, 0o600)
            link = root / "source-link.bin"
            link.symlink_to(source)
            with self.assertRaisesRegex(lab.BcdAbControlError, "owned regular"):
                lab._copy_owned(link, root / "refused.bin", 0o600)


if __name__ == "__main__":
    unittest.main()
