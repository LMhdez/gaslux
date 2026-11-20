"""Pure contracts for the matched Windows-only/CachyOS BCD A/B experiment."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import windows_cachyos_bcd_ab_control as lab


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
        self.assertEqual(result["classification"], "TREATMENT_ASSOCIATED_BCD_MUTATION")
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
        self.assertFalse(result["first24ChangedSpansEqual"])

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

    def test_qemu_write_event_discovery_filters_read_only_and_unrelated_events(self):
        sample = """Available trace events:
bdrv_co_pwritev
bdrv_co_preadv
qcow2_cache_entry_flush
virtio_blk_req_complete
usb_packet_state
"""
        self.assertEqual(
            lab.block_write_event_names(sample),
            ["bdrv_co_pwritev", "qcow2_cache_entry_flush"],
        )

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

    def test_tpm_state_digest_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "tpm"
            root.mkdir(mode=0o700)
            target = root / "real.bin"
            target.write_bytes(b"state")
            (root / "link.bin").symlink_to(target)
            with self.assertRaisesRegex(lab.BcdAbControlError, "symlink"):
                lab.tpm_state_tree_sha256(root)

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
