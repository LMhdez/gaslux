"""GASLUX-SAFETY F-01..F-04 reproductions against real six-GPT functions.

Runs ONLY on regular files and mocked text interfaces; never starts QEMU guest,
loads an ISO, accesses Windows, or invokes System76 distinst.
"""
from __future__ import annotations

import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

import gaslux_popos_six_gpt_contract as contract  # noqa: E402
import gaslux_popos_six_gpt_lab as lab  # noqa: E402
import gaslux_popos_six_gpt_ownership as ownership  # noqa: E402
from gaslux_popos_reuse_snapshot_gate import Refusal  # noqa: E402


class OwnedFileSafetyTests(unittest.TestCase):
    def test_f01_original_directory_renamed_and_replaced_same_uid(self):
        with tempfile.TemporaryDirectory() as parent:
            p = Path(parent)
            work = p / "gaslux-pop-six-gpt-owned"
            work.mkdir(mode=0o700)
            foreign = p / "same-uid-foreign"
            foreign.mkdir(mode=0o700)
            (foreign / "foreign.txt").write_text("DO NOT DELETE")
            parked = p / "original-survives"
            with ownership.OwnedDirectory(work) as owned:
                owned.create_file(work / "owned.raw", 2048)
                os.rename(work, parked)
                os.rename(foreign, work)
                with self.assertRaisesRegex(Refusal, "REFUSE_OWNERSHIP"):
                    owned.cleanup()
                self.assertTrue((parked / "owned.raw").exists())
                self.assertEqual((work / "foreign.txt").read_text(), "DO NOT DELETE")

    def test_f01_same_name_same_size_foreign_inode_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent) / "gaslux-pop-six-gpt-owned"
            work.mkdir(mode=0o700)
            with ownership.OwnedDirectory(work) as owned:
                orig = work / "resource.qcow2"
                owned.create_file(orig, 4096)
                kept = work / "kept-original"
                os.rename(orig, kept)
                orig.write_bytes(b"F" * 4096)
                self.assertNotEqual(orig.stat().st_ino, kept.stat().st_ino)
                with self.assertRaisesRegex(Refusal, "REFUSE_OWNERSHIP"):
                    owned.remove(orig)
                self.assertEqual(orig.read_bytes(), b"F" * 4096)
                self.assertTrue(kept.exists())

    def test_f01_swap_during_quarantine_preserves_foreign_resource(self):
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent) / "gaslux-pop-six-gpt-owned"
            work.mkdir(mode=0o700)
            with ownership.OwnedDirectory(work) as owned:
                original = owned.create_file(work / "child.qcow2", 64)
                other = work / "unlinked-original-preserved"
                real_rename = os.rename
                mutation = {"done": False}

                def swap_before_atomic_rename(src, dest, **kwargs):
                    if src == "child.qcow2" and not mutation["done"]:
                        mutation["done"] = True
                        real_rename(original, other)
                        original.write_bytes(b"FOREIGN" * 9 + b"F")
                    return real_rename(src, dest, **kwargs)

                with (
                    patch.object(ownership.os, "rename", side_effect=swap_before_atomic_rename),
                    self.assertRaisesRegex(Refusal, "REFUSE_OWNERSHIP"),
                ):
                    owned.remove(original)
                self.assertTrue(other.is_file())
                quarantined = list(work.glob(".owned-six-remove-*"))
                self.assertEqual(len(quarantined), 1)
                self.assertTrue(quarantined[0].read_bytes().startswith(b"FOREIGN"))
                self.assertTrue(mutation["done"])

    def test_f01_symlink_and_hardlink_fail_without_removal(self):
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent) / "gaslux-pop-six-gpt-owned"
            work.mkdir(mode=0o700)
            with ownership.OwnedDirectory(work) as owned:
                original = owned.create_file(work / "owned", 64)
                hardlink = work / "foreign-hardlink"
                os.link(original, hardlink)
                with self.assertRaises(Refusal):
                    owned.remove(original)
                self.assertTrue(original.exists())
                self.assertTrue(hardlink.exists())
                hardlink.unlink()
                preserved = work / "retained"
                os.rename(original, preserved)
                original.symlink_to(preserved)
                with self.assertRaises((Refusal, OSError)):
                    owned.remove(original)
                self.assertTrue(preserved.exists())

    def test_f01_enospc_partial_create_does_not_remove_foreign(self):
        with tempfile.TemporaryDirectory() as parent:
            p = Path(parent)
            other = p / "different-transaction"
            other.write_text("unchanged")
            work = p / "gaslux-pop-six-gpt-owned"
            work.mkdir(mode=0o700)
            with ownership.OwnedDirectory(work) as owned:
                with patch.object(
                    ownership.os, "ftruncate",
                    side_effect=OSError(errno.ENOSPC, "injected ENOSPC")
                ), self.assertRaises(OSError):
                    owned.create_file(work / "partial.raw", 4096)
                self.assertEqual((work / "partial.raw").stat().st_size, 0)
                self.assertIn("partial.raw", owned.entries)
                owned.cleanup()
            self.assertFalse(work.exists())
            self.assertEqual(other.read_text(), "unchanged")

    def test_f01_normal_owned_cleanup_with_open_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent) / "gaslux-pop-six-gpt-owned"
            work.mkdir(mode=0o700)
            with ownership.OwnedDirectory(work) as owned:
                owned.create_file(work / "one", 128)
                owned.create_file(work / "two", 4096)
                owned.remove(work / "one")
                owned.cleanup()
            self.assertFalse(work.exists())

    def test_f01_ambiguous_unregistered_resource_stops_cleanup(self):
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent) / "gaslux-pop-six-gpt-owned"
            work.mkdir(mode=0o700)
            with ownership.OwnedDirectory(work) as owned:
                owned.create_file(work / "one", 128)
                (work / "unregistered").write_text("foreign transaction")
                with self.assertRaisesRegex(Refusal, "REFUSE_OWNERSHIP"):
                    owned.cleanup()
                self.assertTrue((work / "one").exists())
                self.assertEqual((work / "unregistered").read_text(),
                                 "foreign transaction")


class TraceProvenanceTests(unittest.TestCase):
    def test_f02_two_different_virtio_devices_rejected(self):
        trace = (
            "vda virtio_blk_handle_write sector 3188736 nsectors 1\n"
            "vdb virtio_blk_handle_write sector 5285888 nsectors 1"
        )
        with self.assertRaisesRegex(Refusal, "OBSERVATION_INCOMPLETE"):
            contract.audit_qemu_trace(trace)

    def test_f02_concatenated_greedy_regex_rejected(self):
        trace = (
            "virtio_blk_handle_write sector 64 nsectors 1 "
            "virtio_blk_handle_write sector 3188736 nsectors 1"
        )
        with self.assertRaisesRegex(Refusal, "OBSERVATION_INCOMPLETE"):
            contract.audit_qemu_trace(trace)

    def test_f02_valid_but_fabricated_is_parsed_untrusted_not_proof(self):
        trace = "virtio_blk_handle_write sector 3188736 nsectors 1\n"
        parsed = contract.audit_qemu_trace(trace)
        self.assertEqual(parsed["parseStatus"], "PARSED_UNTRUSTED")
        self.assertTrue(parsed["parsedWriteLocationsWithinDeclaredRanges"])
        self.assertFalse(parsed["observedWritesConfinedToOwnedPopPartitions"])
        for field in (
            "traceOriginAuthenticated", "traceBoundToQemuProcess",
            "traceBoundToVirtioSerial", "traceBoundToOwnedChildAndBacking",
            "traceBoundToTransaction", "traceCollectionComplete",
            "observationComplete", "windowsWriterAuthorized",
            "productionInstallationAuthorized",
        ):
            with self.subTest(field=field):
                self.assertIs(parsed[field], False)

    def test_f02_truncated_unknown_overflow_and_discard_refused(self):
        for payload in (
            "virtio_blk_handle_write sector -1 nsectors 1",
            "virtio_blk_handle_write sector 3188736 nsectors 0",
            "virtio_blk_handle_write sector 3188736 nsectors 0001",
            "virtio_blk_handle_write sector 3188736 nsectors 999999999999999999999",
            "virtio_blk_handle_write sector 3188736 nsectors 1 extra",
            "virtio_blk_handle_write sector 3188736 nsectors 1\n\n",
            "virtio_blk_handle_discard sector 3188736 nsectors 1",
            "virtio_blk_handle_write_zeroes sector 3188736 nsectors 1",
            "virtio_blk_handle_write sector 3188736 nsectors 1\r",
            "qemu-img truncation detected",
        ):
            with self.subTest(payload=payload), self.assertRaises(Refusal):
                contract.audit_qemu_trace(payload)


class QcowMapSafetyTests(unittest.TestCase):
    @staticmethod
    def backing_map() -> list[dict]:
        return [{"start": 0, "length": lab.SIZE, "depth": 1,
                 "data": False, "zero": True, "present": True}]

    @staticmethod
    def injected_map(sector: int) -> list[dict]:
        offset = sector * lab.SECTOR
        return [
            {"start": 0, "length": offset, "depth": 1,
             "data": False, "zero": True},
            {"start": offset, "length": 4096, "depth": 0,
             "data": True, "zero": False},
            {"start": offset + 4096, "length": lab.SIZE - offset - 4096,
             "depth": 1, "data": False, "zero": True},
        ]

    def test_f04_exact_safety_zero_extent_refused(self):
        case = [{"depth": 0, "data": False, "zero": True,
                 "start": 0, "length": 4096}]
        with (
            patch.object(lab, "chain"),
            patch.object(lab, "command", return_value=json.dumps(case)),
            self.assertRaisesRegex(Refusal, "REFUSE_RECOVERY_UNPROVEN"),
        ):
            lab.ensure_empty_child(Path("/tmp/child"), Path("/tmp/backing"))

    def test_f04_zero_child_full_length_also_refused(self):
        case = [{"depth": 0, "data": False, "zero": True,
                 "start": 0, "length": lab.SIZE}]
        with patch.object(lab, "chain"), patch.object(
            lab, "command", return_value=json.dumps(case)
        ), self.assertRaisesRegex(Refusal, "depth-0 child"):
            lab.ensure_empty_child(Path("/tmp/child"), Path("/tmp/backing"))

    def test_f04_false_empty_map_missing_keys_gaps_and_unknown_fields(self):
        cases = [
            [],
            [{"start": 0, "length": lab.SIZE, "depth": 1, "data": False}],
            [{"start": 0, "length": lab.SIZE, "depth": True,
              "data": False, "zero": True}],
            [{"start": 0, "length": lab.SIZE, "depth": 1,
              "data": False, "zero": True, "foreign": True}],
            [{"start": 0, "length": lab.SIZE - 4096, "depth": 1,
              "data": False, "zero": True}],
            [{"start": 0, "length": lab.SIZE, "depth": 0,
              "data": False, "zero": True, "present": False}],
            "not an array",
        ]
        for item in cases:
            with (
                self.subTest(item=str(item)[:120]),
                patch.object(lab, "chain"),
                patch.object(lab, "command", return_value=json.dumps(item)),
                self.assertRaisesRegex(Refusal, "REFUSE_RECOVERY_UNPROVEN"),
            ):
                lab.ensure_empty_child(Path("/tmp/c"), Path("/tmp/b"))

    def test_f04_valid_no_depth_zero_calls_effective_compare(self):
        with patch.object(lab, "chain"), patch.object(lab, "command") as cmd:
            cmd.side_effect = [json.dumps(self.backing_map()), ""]
            lab.ensure_empty_child(Path("/tmp/c"), Path("/tmp/b"))
            self.assertEqual(cmd.call_count, 2)
            self.assertEqual(cmd.call_args.args[:3],
                             ("qemu-img", "compare", "-f"))

    def test_f03_material_injection_detected_only_with_map_and_readback(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            child, base = p / "synthetic.qcow2", p / "synthetic.raw"
            child.write_bytes(b"child-test")
            base.write_bytes(b"backing-test")
            st = child.stat()
            sector = lab.PARTS[2].start + 4096
            with patch.object(lab, "chain"), patch.object(lab, "command") as cmd:
                cmd.side_effect = [json.dumps(self.injected_map(sector)), ""]
                proof = lab.prove_injected_fault(
                    child, base, sector, (st.st_dev, st.st_ino)
                )
            self.assertTrue(proof["ownedDepthZeroDataObserved"])
            self.assertTrue(proof["readbackPatternVerified"])
            self.assertFalse(proof["toolErrorsAcceptedAsCorruption"])

    def test_f03_injection_not_observed_tool_failure_backing_invalid(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            child, base = p / "child", p / "base"
            child.write_bytes(b"child-test")
            base.write_bytes(b"backing-test")
            st = child.stat()
            sector = lab.PARTS[2].start + 4096
            for failure in (
                Refusal("tool failure: qemu-img rc=1"),
                subprocess.TimeoutExpired("qemu-img", 30),
            ):
                with (
                    self.subTest(failure=str(failure)),
                    patch.object(lab, "chain"),
                    patch.object(lab, "command", side_effect=failure),
                    self.assertRaises((Refusal, subprocess.TimeoutExpired)),
                ):
                    lab.prove_injected_fault(
                        child, base, sector, (st.st_dev, st.st_ino)
                    )
            with patch.object(lab, "chain", side_effect=Refusal(
                "foreign backing"
            )), self.assertRaisesRegex(Refusal, "foreign backing"):
                lab.prove_injected_fault(child, base, sector,
                                         (st.st_dev, st.st_ino))
            with patch.object(lab, "chain"), patch.object(
                lab, "command", return_value="[INVALID"
            ), self.assertRaisesRegex(Refusal, "malformed"):
                lab.prove_injected_fault(child, base, sector,
                                         (st.st_dev, st.st_ino))
            with patch.object(lab, "chain"), patch.object(
                lab, "command", return_value=json.dumps(self.backing_map())
            ), self.assertRaisesRegex(Refusal, "not materially observed"):
                lab.prove_injected_fault(child, base, sector,
                                         (st.st_dev, st.st_ino))
            child.unlink()
            child.write_bytes(b"foreign-inode")
            with self.assertRaisesRegex(Refusal, "inode substituted"):
                lab.prove_injected_fault(child, base, sector,
                                         (st.st_dev, st.st_ino))

    def test_f04_real_qcow2_zero_cluster_when_qemu_tools_available(self):
        if shutil.which("qemu-img") is None or shutil.which("qemu-io") is None:
            self.skipTest("qemu-img and qemu-io unavailable; CI material lab covers")
        with tempfile.TemporaryDirectory(prefix="gaslux-pop-six-gpt-") as folder:
            work = Path(folder)
            base, child = work / "base.raw", work / "child.qcow2"
            with base.open("xb") as f:
                f.truncate(8 * 1024**2)
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-F", "raw",
                 "-b", str(base), str(child)], check=True, capture_output=True
            )
            subprocess.run(
                ["qemu-io", "-f", "qcow2", "-c", "write -z 0 65536", str(child)],
                check=True, capture_output=True,
            )
            info = json.loads(subprocess.check_output(
                ["qemu-img", "map", "--output=json", str(child)]
            ))
            if not any(row.get("depth") == 0 for row in info):
                self.skipTest("QEMU optimized zero write into backing-equivalent hole")
            with (
                patch.object(lab, "chain"),
                patch.object(lab, "SIZE", 8 * 1024**2),
                self.assertRaisesRegex(Refusal, "REFUSE_RECOVERY_UNPROVEN"),
            ):
                lab.ensure_empty_child(child, base)


if __name__ == "__main__":
    unittest.main()
