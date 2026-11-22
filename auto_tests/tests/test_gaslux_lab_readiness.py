"""No synthetic VM evidence may authorize an installed OS or release."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "tools/gaslux_lab_readiness.py"
SPEC = importlib.util.spec_from_file_location("gaslux_lab_readiness", SOURCE)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def reports():
    quota = {
        "schema": "gaslux-private-60gib-quota-readiness-v1",
        "status": "PRIVATE_60GIB_QUOTA_AND_QCOW2_VERIFIED",
        "private_quota_exact_file_bytes": 60 * 1024**3,
        "physical_preallocation_proven_bytes": 60 * 1024**3,
        "exact_private_loop_mount_verified": True,
        "same_size_60gib_backing_overlay_chain_verified": True,
        "qemu_io_actual_overlay_write_verified": True,
        "baseline_integrity_and_reset_verified": True,
        "guest_writer_admitted": False,
        "windows_guest_booted": False,
        "mint_guest_installed": False,
    }
    scaled = {
        "schema": "gaslux-private-ext4-quota-fixture-v1",
        "loop_source_exact_verified": True,
        "ext4_capacity_bound_tested": True,
        "qemu_io_enospc_observed": True,
        "baseline_unchanged_after_enospc": True,
        "overlay_recreated_and_canary_restored": True,
        "lab_writer_admitted": False,
    }
    media = {
        "schema": "gaslux-windows-media-source-intake-v1",
        "status": "BLOCKED_MEDIA",
        "file_verified": False,
        "official_pinned_hash_matched": False,
        "guest_writer_admitted": False,
        "windows_guest_booted": False,
    }
    return quota, scaled, media


class LabReadinessTests(unittest.TestCase):
    def test_two_real_fixture_checkpoints_cannot_certify_guest(self):
        report = mod.readiness(*reports())
        self.assertEqual(report["evidence_verified_count"], 2)
        self.assertEqual(report["evidence_required_count"], 11)
        self.assertEqual(report["next_blocking_gate"],
                         "windows_iso_exact_microsoft_hash")
        self.assertFalse(report["guest_writer_admitted"])
        self.assertFalse(report["installation_verified"])
        self.assertFalse(report["release_eligible"])
        self.assertEqual(report["checkpoints"][0]["state"], "verified")
        self.assertEqual(report["checkpoints"][1]["state"], "verified")

    def test_even_verified_media_does_not_admit_guest_without_install_proofs(self):
        q, s, m = reports()
        m.update({"status": "PINNED_WINDOWS_ISO_BYTES_VERIFIED",
                  "file_verified": True, "official_pinned_hash_matched": True,
                  "iso9660_pvd_verified": True})
        report = mod.readiness(q, s, m)
        self.assertEqual(report["evidence_verified_count"], 3)
        self.assertEqual(report["next_blocking_gate"], "installed_windows_authenticated")
        self.assertFalse(report["installation_verified"])
        self.assertFalse(report["release_eligible"])

    def test_false_quota_or_untrusted_windows_guests_are_rejected(self):
        q, s, m = reports()
        q["physical_preallocation_proven_bytes"] = 0
        self.assertEqual(mod.readiness(q, s, m)["evidence_verified_count"], 1)
        q["windows_guest_booted"] = True
        with self.assertRaisesRegex(ValueError, "Unsafe guest"):
            mod.readiness(q, s, m)
        q["windows_guest_booted"] = False
        s["lab_writer_admitted"] = True
        self.assertEqual(mod.readiness(q, s, m)["evidence_verified_count"], 0)
        q["schema"] = "fake"
        with self.assertRaisesRegex(ValueError, "schema"):
            mod.readiness(q, s, m)


if __name__ == "__main__":
    unittest.main()
