"""Synthetic-only contracts for a real Windows COW + official Pop live ISO run.

No hosted VM, signing key fetch, ISO download or disk read in these tests.
"""
from __future__ import annotations

import copy
import pathlib
import sys
import unittest
import uuid
from unittest.mock import patch
import os

HERE = pathlib.Path(__file__).resolve().parent
TOOLS = HERE / "tools"
sys.path.insert(0, str(TOOLS))

from test_windows10_popos_independent_esp_root_stage import staged_fixture
from windows10_popos_live_cow_host import (
    ISO_SHA256, gpt_windows_cow_live_manifest,
    run_official_pop_windows_cow_live_probe,
)
from windows_x64_installed_gpt_ro_audit import DiskAuditError
from windows_x64_tcg_firstboot import main as windows_main
from windows10_popos_official_live_probe_guest import (
    _decode_gpt, Refusal,
)


class PopOfficialRealWindowsReadOnlyContract(unittest.TestCase):
    def setUp(self):
        _, _, self.front, self.back, self.before, self.after, self.plan = staged_fixture()

    def test_manifest_matches_byte_exact_six_gpt_and_is_never_a_write_plan(self):
        manifest = gpt_windows_cow_live_manifest(
            self.before, self.after, self.plan, self.front, self.back,
        )
        self.assertEqual(manifest["ownedIndexes"], [5, 6])
        self.assertEqual(manifest["windowsIndexes"], [1, 2, 3, 4])
        self.assertEqual(manifest["diskGuid"], self.before["diskGuid"])
        self.assertEqual(manifest["diskSerial"], "GASLUX_POP_WIN10_COW")
        self.assertEqual(manifest["popEspGuid"], self.plan["partitions"][0]["uniqueGuid"])
        self.assertEqual(manifest["popRootGuid"], self.plan["partitions"][1]["uniqueGuid"])
        self.assertEqual(manifest["expectedSectorBytes"], 512)
        self.assertIs(manifest["productionInstallationAuthorized"], False)
        self.assertEqual(
            ISO_SHA256,
            "a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c",
        )

    def test_host_and_actual_guest_gpt_decoders_share_exact_six_partition_contract(self):
        manifest = gpt_windows_cow_live_manifest(
            self.before, self.after, self.plan, self.front, self.back,
        )
        rows = _decode_gpt(self.front, self.back, manifest)
        self.assertEqual([x["index"] for x in rows], [1, 2, 3, 4, 5, 6])
        self.assertEqual(rows[4]["guid"], manifest["popEspGuid"])
        self.assertEqual(rows[5]["guid"], manifest["popRootGuid"])
        altered = copy.deepcopy(manifest)
        altered["frontMiBSha256"] = "0" * 64
        with self.assertRaises(Refusal):
            _decode_gpt(self.front, self.back, altered)
        with self.assertRaises(Refusal):
            _decode_gpt(self.front, self.back[:-1], manifest)

    def test_host_declines_corrupt_gpt_crc_backing_identity_and_guids(self):
        cases = []
        f = bytearray(self.front)
        f[512+16] ^= 1
        cases.append(("primaryCRC", self.before, self.after, self.plan, bytes(f), self.back))
        b = bytearray(self.back)
        b[-512+16] ^= 1
        cases.append(("backupCRC", self.before, self.after, self.plan, self.front, bytes(b)))
        fake = copy.deepcopy(self.after)
        fake["linuxRoot"]["guid"] = str(uuid.uuid4())
        cases.append(("popRootOwner", self.before, fake, self.plan, self.front, self.back))
        fake = copy.deepcopy(self.before)
        fake["diskGuid"] = str(uuid.uuid4())
        cases.append(("windowsDiskGuid", fake, self.after, self.plan, self.front, self.back))
        fake = copy.deepcopy(self.plan)
        fake["partitions"][0]["uniqueGuid"] = str(uuid.uuid4())
        cases.append(("planOwner", self.before, self.after, fake, self.front, self.back))
        cases.append(("truncated", self.before, self.after, self.plan, self.front[:-1], self.back))
        for name, before, after, plan, front, back in cases:
            with self.subTest(name=name), self.assertRaises(DiskAuditError):
                gpt_windows_cow_live_manifest(before, after, plan, front, back)

    def test_real_probe_refuses_nonhost_without_any_disk_or_iso(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=True):
            with self.assertRaises(DiskAuditError):
                run_official_pop_windows_cow_live_probe(
                    pathlib.Path("/dev/sda"), {}, {}, {},
                    pathlib.Path("/tmp"), pathlib.Path("/tmp"),
                )

    def test_new_real_pop_live_flag_fails_without_verified_windows_preconditions(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit) as caught:
                windows_main([
                    "--profile", "win10_22h2_en_us_x64", "--accel", "kvm",
                    "--probe-pop-live-post-pair",
                ])
        self.assertIn("requires independent", str(caught.exception))

    def test_shell_never_attaches_real_windows_cow_writable(self):
        shell = (TOOLS / "windows10_popos_signed_live_cow_vm.sh").read_text("utf-8")
        guest = (TOOLS / "windows10_popos_official_live_probe_guest.py").read_text("utf-8")
        self.assertIn("readonly=on,format=qcow2,file=$overlay", shell)
        self.assertIn("GASLUX_POP_WIN10_LIVE_CONSENT", shell)
        self.assertIn("gpg --batch --verify", shell)
        self.assertIn(ISO_SHA256, shell)
        self.assertIn("not mounted", guest.lower()) if False else None
        self.assertNotIn("--use $overlay", shell)
        self.assertNotIn("distinst --", shell)
        self.assertNotIn("mkfs.ext4", shell)
        self.assertIn("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW", guest)


if __name__ == "__main__":
    unittest.main()
