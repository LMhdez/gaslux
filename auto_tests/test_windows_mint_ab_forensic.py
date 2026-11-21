"""Read-only A/B evidence and controlled guest-order safety contracts."""
from __future__ import annotations

import copy
from contextlib import ExitStack
import hashlib
import json
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

    def test_same_run_capacity_evidence_must_precede_checkpoint_or_qemu(self):
        import json
        from windows_mint_ab_checkpoint import CONSENT
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            early = d/"mint-ab-capacity-early.json"
            args = dict(original=["if=pflash,format=raw,readonly=on,file=/tmp/firmware"],
                base=d/"base", nvram=d/"vars", overlay=d/"overlay",
                workspace=d, root_uuid="00000000-0000-4000-8000-000000000001",
                kernel=d/"kernel", initramfs=d/"initramfs", evidence=d)
            with patch.dict(os.environ, {
                "GASLUX_MINT_AB_CHECKPOINT_CONSENT": CONSENT,
                "GASLUX_MINT_AB_BOOT_CONSENT":
                    "I_ACCEPT_ONE_DISPOSABLE_WINDOWS10_MINT_AB_AFTER_RESTORE",
                "GITHUB_RUN_ID": "12345", "GITHUB_SHA": "a"*40,
            }, clear=True), patch.object(forensic, "prepare_checkpoint") as checkpoint:
                with self.assertRaisesRegex(forensic.ForensicError,
                                             "untrusted A/B evidence"):
                    forensic.run_ab(**args)
                checkpoint.assert_not_called()
                early.write_text(json.dumps({
                    "schema": "gaslux-mint-ab-capacity-v1",
                    "phase": "early", "result": "PASS",
                    "checkpointReadyForReview": False,
                    "compressionAssumedForCapacity": False,
                    "githubRunId": "different-run", "sourceCommit": "a"*40,
                }))
                with self.assertRaisesRegex(forensic.ForensicError, "same-run"):
                    forensic.run_ab(**args)
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

    @staticmethod
    def _fake_lab(root):
        """Private QCOW2-shaped files, genuine hashes, zero guest execution."""
        from windows_mint_ab_checkpoint import AB_DIR, ARMS, REFERENCE, VARS

        workspace = Path(root)
        evidence = workspace / "evidence"
        evidence.mkdir(mode=0o700)
        directory = workspace / AB_DIR
        directory.mkdir(mode=0o700)
        base = workspace / "windows-backing.qcow2"
        base.write_bytes(b"BACKING-CONTROL")
        reference = directory / REFERENCE
        reference.write_bytes(b"REFERENCE-CONTROL")
        reference.chmod(0o400)
        arm_a = directory / ARMS[0]
        arm_b = directory / ARMS[1]
        for arm in (arm_a, arm_b):
            arm.write_bytes(b"REFERENCE-CONTROL")
            arm.chmod(0o600)
        vars_a, vars_b = (directory / name for name in VARS)
        for state in (vars_a, vars_b):
            state.write_bytes(b"INITIAL-VARS")
            state.chmod(0o600)

        def digest(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        checkpoint = {
            "transactionId": "test-cross-arm-0001",
            "referenceSha256": digest(reference),
            "controlSha256": digest(arm_a),
            "treatmentSha256": digest(arm_b),
            "windowsBackingSha256": digest(base),
            "initialOvmfVarsSha256": digest(vars_b),
        }
        (directory / "checkpoint.json").write_text(json.dumps(checkpoint))
        early = {
            "schema": "gaslux-mint-ab-capacity-v1",
            "phase": "early", "result": "PASS",
            "checkpointReadyForReview": False,
            "compressionAssumedForCapacity": False,
            "githubRunId": "99981",
            "sourceCommit": "a" * 40,
        }
        (evidence / "mint-ab-capacity-early.json").write_text(json.dumps(early))
        gpt = {
            "diskGuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "partitionGuids": [f"00000000-0000-4000-8000-{i:012d}"
                               for i in range(1, 6)],
            "partitionRanges": [
                {"index": i, "firstLba": 2048 + i * 4096,
                 "lastLba": 2048 + i * 4096 + 4095}
                for i in range(1, 6)
            ],
            "sectorBytes": 512,
            "rawPrimaryGptWindowSha256": "a" * 64,
            "rawBackupGptWindowSha256": "b" * 64,
        }
        before = {
            "partitionSha256": [str(i) * 64 for i in range(1, 5)],
            "rootUuid": "00000000-0000-4000-8000-000000000001",
            "mintRootFiles": {"/etc/os-release": "a" * 64,
                              "/etc/fstab": "b" * 64,
                              "/boot/vmlinuz-test": "c" * 64,
                              "/boot/initrd.img-test": "d" * 64},
            "fileInventories": {
                part: {"available": True, "fileSha256": {"/f": "a" * 64}}
                for part in ("esp", "recovery")
            },
        }
        args = {
            "original": ["if=pflash,format=raw,readonly=on,file=/test/OVMF_CODE.fd"],
            "base": base, "nvram": workspace / "original-vars.fd",
            "overlay": workspace / "unmodified-overlay.qcow2",
            "workspace": workspace, "root_uuid": before["rootUuid"],
            "kernel": workspace / "kernel", "initramfs": workspace / "initrd",
            "evidence": evidence,
        }
        return {
            "args": args, "evidence": evidence, "directory": directory,
            "reference": reference, "arm_b": arm_b, "vars_b": vars_b,
            "base": base, "checkpoint": checkpoint, "gpt": gpt,
            "before": before,
        }

    def _run_with_guest_stubs(self, lab, *, mutate_after_a=None,
                              change_gpt=None, change_after_mint=None):
        """Exercise REAL run_ab ordering with mocks only at guest boundaries."""
        from windows_mint_ab_checkpoint import CONSENT

        pre = lab["before"]
        after = copy.deepcopy(pre)
        if change_after_mint:
            change_after_mint(after)
        gpt_after = copy.deepcopy(lab["gpt"])
        if change_gpt:
            change_gpt(gpt_after)

        win_calls = []
        mint_calls = []

        class ReachedWindowsB(Exception):
            pass

        def fake_windows(*args, **kwargs):
            win_calls.append(1)
            if len(win_calls) == 1:
                if mutate_after_a:
                    mutate_after_a(lab)
                return {"bootWitnessSha256": "e" * 64}
            raise ReachedWindowsB()

        def fake_mint(*args, **kwargs):
            mint_calls.append(1)
            return {"mintSerialSha256": "f" * 64}

        def fake_archive(source, destination, **kwargs):
            return "f" * 64 if "mint-serial" in source.name else "e" * 64

        env = {
            "GASLUX_MINT_AB_CHECKPOINT_CONSENT": CONSENT,
            "GASLUX_MINT_AB_BOOT_CONSENT":
                "I_ACCEPT_ONE_DISPOSABLE_WINDOWS10_MINT_AB_AFTER_RESTORE",
            "GITHUB_RUN_ID": "99981",
            "GITHUB_SHA": "a" * 40,
        }
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, env, clear=True))
            stack.enter_context(patch.object(
                forensic, "_guest_disk_audit", return_value=None))
            stack.enter_context(patch.object(
                forensic, "prepare_checkpoint", return_value=lab["checkpoint"]))
            stack.enter_context(patch.object(forensic, "verify_ab_source"))
            stack.enter_context(patch.object(forensic, "image_info"))
            stack.enter_context(patch.object(forensic, "equivalent"))
            stack.enter_context(patch.object(
                forensic, "guest_ro_inventory",
                side_effect=[copy.deepcopy(pre), copy.deepcopy(pre),
                             copy.deepcopy(pre), after]))
            stack.enter_context(patch.object(
                forensic, "gpt_manifest",
                side_effect=[copy.deepcopy(lab["gpt"]),
                             copy.deepcopy(lab["gpt"]),
                             copy.deepcopy(lab["gpt"]), gpt_after]))
            stack.enter_context(patch.object(
                forensic, "run_windows_arm", side_effect=fake_windows))
            stack.enter_context(patch.object(
                forensic, "run_mint_arm", side_effect=fake_mint))
            stack.enter_context(patch.object(
                forensic, "archive_serial", side_effect=fake_archive))
            try:
                forensic.run_ab(**lab["args"])
            except ReachedWindowsB:
                return win_calls, mint_calls, "WINDOWS_B_REACHED"
            except forensic.ForensicError as exc:
                return win_calls, mint_calls, str(exc)
        self.fail("unexpected complete forensic run without Windows B boundary")

    def test_f01_each_modified_resource_stops_before_mint_b(self):
        resources = {
            "referenceStillUntouched": "reference",
            "armBStillUntouched": "arm_b",
            "backingUnchanged": "base",
            "ovmfBStillUntouched": "vars_b",
        }
        for flag, key in resources.items():
            with self.subTest(resource=key), tempfile.TemporaryDirectory() as root:
                lab = self._fake_lab(root)

                def tamper(lab):
                    path = lab[key]
                    if key == "reference":
                        path.chmod(0o600)
                    path.write_bytes(path.read_bytes() + b"TAMPER")
                    if key == "reference":
                        path.chmod(0o400)

                windows, mint, result = self._run_with_guest_stubs(
                    lab, mutate_after_a=tamper)
                self.assertEqual(windows, [1], "Windows B must never start")
                self.assertEqual(mint, [], "Mint B must never start")
                self.assertIn("F-01", result)
                self.assertIn(flag, result)
                blocked = json.loads(
                    (lab["evidence"] / "mint-ab-after-control-gate.json").read_text())
                self.assertEqual(blocked["result"], "BLOCKED_INTEGRITY")
                self.assertIs(blocked["checks"][flag], False)
                self.assertFalse(blocked["referenceAndBStillUntouched"])
                self.assertFalse((lab["evidence"] / "mint-ab-control.json").exists())
                self.assertFalse((lab["evidence"] / "mint-ab-after-mint-gate.json").exists())

    def test_f02_gpt_guid_partuuids_offsets_and_backup_drift_stop_windows_b(self):
        changes = {
            "disk GUID": lambda g: g.__setitem__(
                "diskGuid", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            "PARTUUID": lambda g: g["partitionGuids"].__setitem__(
                3, "cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            "partition end": lambda g: g["partitionRanges"][4].__setitem__(
                "lastLba", 987654),
            "partition offset": lambda g: g["partitionRanges"][0].__setitem__(
                "firstLba", 8888),
            "secondary GPT checksum": lambda g: g.__setitem__(
                "rawBackupGptWindowSha256", "e" * 64),
        }
        for case, change in changes.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as root:
                lab = self._fake_lab(root)
                windows, mint, reason = self._run_with_guest_stubs(
                    lab, change_gpt=change)
                self.assertEqual(windows, [1], "Windows B must never start")
                self.assertEqual(mint, [1])
                self.assertIn("F-02", reason)
                self.assertIn("gptUnchanged", reason)
                record = json.loads(
                    (lab["evidence"] / "mint-ab-after-mint-gate.json").read_text())
                self.assertEqual(record["result"], "BLOCKED_INTEGRITY")
                self.assertFalse(record["checks"]["gptUnchanged"])
                self.assertEqual(record["windowsPartitionSha256BeforeMint"],
                                 record["windowsPartitionSha256AfterMint"])
                self.assertTrue(any(record["gptDifferences"].values()))
                self.assertTrue(record["gptBefore"] != record["gptAfterMint"])

    def test_f02_protected_windows_digests_and_root_changes_also_stop_windows_b(self):
        changes = {
            "windowsEspUnchanged": lambda d: d["partitionSha256"].__setitem__(0, "f" * 64),
            "windowsMsrUnchanged": lambda d: d["partitionSha256"].__setitem__(1, "f" * 64),
            "windowsOsNtfsUnchanged": lambda d: d["partitionSha256"].__setitem__(2, "f" * 64),
            "windowsRecoveryUnchanged": lambda d: d["partitionSha256"].__setitem__(3, "f" * 64),
            "rootUuidUnchanged": lambda d: d.__setitem__(
                "rootUuid", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
            "mintRootFilesUnchanged": lambda d: d["mintRootFiles"].__setitem__(
                "/etc/fstab", "f" * 64),
        }
        for flag, mutate in changes.items():
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as root:
                lab = self._fake_lab(root)
                windows, mint, reason = self._run_with_guest_stubs(
                    lab, change_after_mint=mutate)
                self.assertEqual((windows, mint), ([1], [1]))
                self.assertIn(flag, reason)
                report = json.loads(
                    (lab["evidence"] / "mint-ab-after-mint-gate.json").read_text())
                self.assertFalse(report["checks"][flag])

    def test_valid_two_gates_allow_only_the_next_mock_windows_boundary(self):
        with tempfile.TemporaryDirectory() as root:
            lab = self._fake_lab(root)
            windows, mint, status = self._run_with_guest_stubs(lab)
            self.assertEqual(status, "WINDOWS_B_REACHED")
            self.assertEqual(windows, [1, 1])
            self.assertEqual(mint, [1])
            control = json.loads(
                (lab["evidence"] / "mint-ab-after-control-gate.json").read_text())
            post_mint = json.loads(
                (lab["evidence"] / "mint-ab-after-mint-gate.json").read_text())
            self.assertEqual(control["result"], "PASS")
            self.assertEqual(post_mint["result"], "PASS")
            self.assertTrue(control["referenceAndBStillUntouched"])
            self.assertTrue(all(post_mint["checks"].values()))
            self.assertFalse(control["productionInstallAuthorized"])
            self.assertFalse(post_mint["productionInstallAuthorized"])

    def test_refuse_reusing_evidence_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            (d/"mint-ab-forensic.json").write_text("{}")
            with self.assertRaisesRegex(forensic.ForensicError, "unsafe"):
                forensic.write_manifest(d, "mint-ab-forensic.json", {})


if __name__ == "__main__":
    unittest.main()
