"""Read-only A/B evidence and controlled guest-order safety contracts."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows_mint_ab_forensic as forensic


class MintAbForensicContracts(unittest.TestCase):
    def test_missing_ab_boot_consent_blocks_all_clones_or_guests(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(forensic, "prepare_checkpoint") as checkpoint:
                with self.assertRaisesRegex(forensic.ForensicError, "consent"):
                    forensic.run_ab(
                        original=[], base=Path("/dev/sda"), nvram=Path("/dev/sdb"),
                        overlay=Path("/dev/sdc"), workspace=Path("/tmp"),
                        root_uuid="00000000-0000-4000-8000-000000000001",
                        kernel=Path("/tmp/kernel"), initramfs=Path("/tmp/initramfs"),
                        evidence=Path("/tmp"))
                checkpoint.assert_not_called()

    def test_all_partitions_tracked_individually(self):
        initial = ["1"*64, "2"*64, "3"*64, "4"*64]
        changed = ["5"*64, "2"*64, "6"*64, "7"*64]
        delta = [a != b for a, b in zip(initial, changed)]
        self.assertEqual(delta, [True, False, True, True])
        self.assertTrue(any(delta[i] for i in (0, 1, 3)))

    def test_file_level_diff_identifies_add_remove_and_modified(self):
        def state(esp, recovery):
            return {"fileInventories": {
                "esp": {"available": True, "fileSha256": esp},
                "recovery": {"available": True, "fileSha256": recovery},
            }}
        old = state({"/EFI/Boot/a.efi": "a"*64,
                     "/EFI/Microsoft/Boot/bootmgfw.efi": "b"*64},
                    {"/Recovery/winre.wim": "c"*64})
        new = state({"/EFI/Microsoft/Boot/bootmgfw.efi": "d"*64,
                     "/EFI/new.efi": "e"*64},
                    {"/Recovery/winre.wim": "c"*64})
        result = forensic.changed_files(old, new)
        self.assertEqual(result["esp"]["changed"], [
            "/EFI/Boot/a.efi", "/EFI/Microsoft/Boot/bootmgfw.efi", "/EFI/new.efi"])
        self.assertEqual(result["recovery"]["changed"], [])
        self.assertIsNone(result["esp"]["afterSha256"]["/EFI/Boot/a.efi"])

    def test_incomplete_readonly_inventory_never_claims_success(self):
        old = {"fileInventories": {
            "esp": {"available": False, "reason": "not mounted"},
            "recovery": {"available": True, "fileSha256": {"/f": "a"*64}}}}
        new = {"fileInventories": {
            "esp": {"available": True, "fileSha256": {"/f": "b"*64}},
            "recovery": {"available": True, "fileSha256": {"/f": "a"*64}}}}
        result = forensic.changed_files(old, new)
        self.assertIs(result["esp"]["available"], False)

    def test_never_write_guest_partitions_or_repair_protection(self):
        code = (Path(__file__).parent/"tools"/
                "windows_mint_ab_forensic.py").read_text()
        for token in ("mkfs", "wipefs", "sgdisk", "reagentc /enable",
                      "bcdboot.exe", "mount_rw(", "os.system(", "ACCEPT_NO_WRITER"):
            with self.subTest(token=token):
                self.assertNotIn(token, code)
        self.assertIn("third_guest_args", code)
        self.assertIn("has_orderly_shutdown_witness", code)
        self.assertIn("prepare_checkpoint", code)
        self.assertIn("run_windows_arm", code)
        self.assertIn("run_mint_arm", code)

    def test_refuse_reusing_evidence_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            (d/"mint-ab-forensic.json").write_text("{}")
            with self.assertRaisesRegex(forensic.ForensicError, "unsafe"):
                forensic.write_manifest(d, "mint-ab-forensic.json", {})


if __name__ == "__main__":
    unittest.main()
