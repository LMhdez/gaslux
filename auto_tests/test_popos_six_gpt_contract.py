"""Offline adversarial contracts for Pop's Windows-FREE synthetic six-GPT lab.

No QEMU guest, ISO, Windows files, real block devices or destructive operations.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

import gaslux_popos_six_gpt_contract as c  # noqa: E402
import gaslux_popos_six_gpt_lab as lab  # noqa: E402
from gaslux_popos_reuse_snapshot_gate import Refusal, new_file, regular  # noqa: E402

TX = "a1234567-1234-4abc-9abc-123456789abc"


def sample_plan() -> dict:
    example = {
        "schemaVersion": 1,
        "scenario": c.SCENARIO,
        "transactionId": TX,
        "disk": {
            "sizeBytes": c.SIZE,
            "logicalSectorBytes": c.SECTOR,
            "guid": c.DISK_GUID,
            "virtioSerial": c.SERIAL,
        },
        "partitions": [p.as_dict() for p in c.PARTS],
        "media": {
            "isoSha256": c.ISO_SHA256,
            "distinstSha256": c.DISTINST_SHA256,
            "system76GpgFingerprint": c.SYSTEM76_GPG_FPR,
            "isoIndependentlyAuthenticatedHere": False,
        },
        "distinstReuseArgv": [
            "--no-efi-vars",
            "--use",
            ":5:reuse:mount=/boot/efi",
            "--use",
            ":6:reuse:mount=/",
        ],
        "gpt": {"pmbrAndPrimary": "a" * 64, "secondary": "b" * 64},
        "backingSha256": "c" * 64,
        "protectedPartitionHashes": {str(p.index): "d" * 64 for p in c.PROTECTED},
        "protectedEspFileSha256": "e" * 64,
        "canaries": [
            {"lba": lba, "role": role, "sectorSha256": "f" * 64}
            for lba, role in zip(
                (534536, 567304, 1615880, 64, 1024, 64006144, 67108800),
                (
                    "protected-msr",
                    "protected-data",
                    "protected-recovery",
                    "unallocated",
                    "unallocated",
                    "unallocated",
                    "unallocated",
                ),
                strict=True,
            )
        ],
        "ovmfTemplateSha256": "0" * 64,
        "filesystems": {"1": "vfat", "5": "vfat", "6": "ext4"},
        "onlyWritableGuestDisk": "owned-qcow2-child",
        "recoveryMode": "discard-private-child-recreate",
        "windowsAttached": False,
        "physicalDisksAttached": False,
        **c.BOOLEANS,
    }
    example["manifestSha256"] = c.canonical_digest(example)
    return example


def signed_fixture_with_change(plan: dict) -> dict:
    """Recompute plan digest to prove independent geometry/authority checks."""
    plan = copy.deepcopy(plan)
    plan["manifestSha256"] = c.canonical_digest(
        {k: v for k, v in plan.items() if k != "manifestSha256"}
    )
    return plan


class SixGptNegativeTests(unittest.TestCase):
    def test_fixed_geometry_exact_six_and_28g_root(self):
        c.validate_geometry()
        self.assertEqual([p.index for p in c.PARTS], list(range(1, 7)))
        self.assertEqual([p.owned for p in c.PARTS], [False, False, False, False, True, True])
        self.assertEqual(c.PARTS[-1].count * 512, 28 * 1024**3)
        self.assertEqual(c.PARTS[4].count * 512, 1024**3)
        self.assertEqual(c.PARTS[0].count * 512, 260 * 1024**2)

    def test_owned_write_endpoints_accept_only_five_and_six(self):
        for p in c.OWNED:
            for sector, count in (
                (p.start, 1),
                (p.end, 1),
                (p.start, p.count),
                (p.start + 100, 4096),
            ):
                self.assertEqual(c.classify_sector_write(sector, count), p.index)

    def test_all_protected_gpt_and_unallocated_writes_refused(self):
        invalid = [
            (0, 1),
            (1, 33),
            (c.COUNT - 33, 33),
            (c.COUNT - 1, 1),
            (c.COUNT, 1),
            (-1, 1),
            (c.PARTS[0].start - 1, 2),
            (c.PARTS[4].start - 1, 2),
            (c.PARTS[5].start - 1, 2),
            (c.PARTS[4].end, 2),
            (c.PARTS[5].end, 2),
            (c.PARTS[4].start, 0),
            (c.PARTS[5].start, "8"),
            (True, 1),
            (c.COUNT, -1),
        ]
        invalid.extend((p.start, 1) for p in c.PROTECTED)
        invalid.extend((p.end, 1) for p in c.PROTECTED)
        invalid.extend((lba, 1) for lba in c.UNALLOCATED_CANARIES)
        for sector, count in invalid:
            with (
                self.subTest(sector=sector, count=count),
                self.assertRaisesRegex(Refusal, "REFUSE_OUT_OF_WRITESET"),
            ):
                c.classify_sector_write(sector, count)

    def test_qemu_bio_trace_parser_denylist(self):
        for invalid in (
            "",
            "no write events",
            "virtio_blk_handle_write sector 1 nsectors 8",
            f"virtio_blk_handle_write sector {c.PARTS[0].start} nsectors 8",
            f"virtio_blk_handle_write sector {c.PARTS[2].start} nsectors 8",
            f"virtio_blk_handle_write sector {c.PARTS[3].start} nsectors 8",
            f"virtio_blk_handle_write sector {c.COUNT - 33} nsectors 8",
            "virtio_blk_handle_write invalid",
            "virtio_blk_handle_discard sector 3188736 nsectors 8",
            "virtio_blk_handle_write_zeroes sector 3188736 nsectors 8",
            "blk_co_pwritev",
            "virtio_blk_handle_write sector 3188736 nsectors 8\n"
            "virtio_blk_handle_write sector 64 nsectors 1",
        ):
            with self.subTest(trace=invalid[:90]), self.assertRaises(Refusal):
                c.audit_qemu_trace(invalid)
        valid = c.audit_qemu_trace(
            f"virtio_blk_handle_write sector {c.PARTS[4].start} nsectors 8\n"
            f"virtio_blk_handle_write sector {c.PARTS[5].start} nsectors 16\n"
        )
        self.assertEqual(valid["observedBytes"], 12288)
        self.assertFalse(valid["observedWritesConfinedToOwnedPopPartitions"])
        self.assertEqual(valid["traceClassification"], "PARSED_UNTRUSTED")
        self.assertFalse(valid["observationComplete"])
        self.assertFalse(valid["productionInstallationAuthorized"])

    def test_safety_f02_multidevice_concatenation_and_untrusted(self):
        for trace in (
            "vda virtio_blk_handle_write sector 3188736 nsectors 1\n"
            "vdb virtio_blk_handle_write sector 5285888 nsectors 1",
            "virtio_blk_handle_write sector 64 nsectors 1 "
            "virtio_blk_handle_write sector 3188736 nsectors 1",
            "virtio_blk_handle_write sector -1 nsectors 1",
            "virtio_blk_handle_write sector 3188736 nsectors 1x",
            "virtio_blk_handle_write sector 3188736 nsectors 0",
            "virtio_blk_handle_write sector 3188736 nsectors 999999999999",
            "virtio_blk_handle_write_zeroes sector 3188736 nsectors 1",
        ):
            with self.subTest(trace=trace), self.assertRaises(Refusal):
                c.audit_qemu_trace(trace)
        parsed = c.audit_qemu_trace("vda virtio_blk_handle_write sector 3188736 nsectors 1")
        self.assertFalse(parsed["observedWritesConfinedToOwnedPopPartitions"])
        self.assertFalse(parsed["traceProvenanceAuthenticated"])
        self.assertFalse(parsed["observationComplete"])

    def test_safety_f03_fault_detection_not_tool_failure(self):
        import subprocess

        full = json.dumps(
            [
                {"start": 0, "length": 4096, "depth": 1, "data": True, "zero": False},
                {"start": 4096, "length": c.SIZE - 4096, "depth": 0, "data": False, "zero": False},
            ]
        )
        with (
            patch.object(lab, "chain"),
            patch.object(lab, "pin_identity", return_value=(11, 22)),
            patch.object(lab, "command", return_value=full),
            self.assertRaisesRegex(Refusal, "not materialized"),
        ):
            lab.verify_injected_fault(Path("child"), Path("backing"), 8192, 4096, (11, 22))
        for error in (
            Refusal("qemu-img failed"),
            subprocess.TimeoutExpired("qemu-img", 1),
            ValueError("malformed JSON"),
        ):
            with (
                patch.object(lab, "chain"),
                patch.object(lab, "pin_identity", return_value=(11, 22)),
                patch.object(lab, "command", side_effect=error),
                self.assertRaises(type(error)),
            ):
                lab.verify_injected_fault(Path("child"), Path("backing"), 8192, 4096, (11, 22))
        injected = json.dumps(
            [
                {"start": 0, "length": 8192, "depth": 1, "data": True, "zero": False},
                {"start": 8192, "length": 4096, "depth": 0, "data": True, "zero": False},
                {"start": 12288, "length": c.SIZE - 12288, "depth": 1, "data": True, "zero": False},
            ]
        )
        with (
            patch.object(lab, "chain"),
            patch.object(lab, "command", return_value=injected),
            patch.object(lab, "pin_identity", return_value=(11, 22)),
            self.assertRaises(lab.ProtectedFaultDetected),
        ):
            lab.verify_injected_fault(Path("child"), Path("backing"), 8192, 4096, (11, 22))

    def test_safety_f04_zero_overlay_and_map_validation(self):
        zero = [
            {"depth": 0, "data": False, "zero": True, "start": 0, "length": 4096},
            {"depth": 1, "data": True, "zero": False, "start": 4096, "length": c.SIZE - 4096},
        ]
        with (
            patch.object(lab, "chain"),
            patch.object(lab, "command", return_value=json.dumps(zero)),
            self.assertRaisesRegex(Refusal, "owned extents"),
        ):
            lab.ensure_empty_child(Path("child"), Path("backing"))
        for malformed in (
            "{",
            "[]",
            '[{"depth":0,"data":false,"zero":true,"start":0,"length":4096}]',
            json.dumps(
                [
                    {
                        "depth": 1,
                        "data": True,
                        "zero": False,
                        "start": 0,
                        "length": c.SIZE,
                        "surprise": True,
                    }
                ]
            ),
        ):
            with self.subTest(malformed=malformed[:20]), self.assertRaises(Refusal):
                lab.parse_qcow_map(malformed)
        with self.assertRaisesRegex(Refusal, "compressed extent"):
            lab.parse_qcow_map(
                json.dumps(
                    [
                        {
                            "start": 0,
                            "length": c.SIZE,
                            "depth": 1,
                            "data": True,
                            "zero": False,
                            "compressed": True,
                        }
                    ]
                )
            )
        empty = [{"start": 0, "length": c.SIZE, "depth": 1, "data": True, "zero": False}]
        with (
            patch.object(lab, "chain"),
            patch.object(lab, "command", return_value=json.dumps(empty)),
        ):
            lab.ensure_empty_child(Path("child"), Path("backing"))

    def test_safety_f01_directory_swap_export_refuses_foreign(self):
        import gaslux_popos_six_gpt_ownership as owner

        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            work = parent / "gaslux-pop-six-gpt-owned"
            work.mkdir(mode=0o700)
            evidence = parent / "evidence"
            evidence.mkdir(mode=0o700)
            (work / owner.FILES[0]).write_text("original")
            pinned = (work.stat().st_dev, work.stat().st_ino)
            owner.export_evidence(work, evidence, pinned)
            self.assertEqual((evidence / owner.FILES[0]).read_text(), "original")
            work.rename(parent / "moved")
            work.mkdir(mode=0o700)
            (work / owner.FILES[1]).write_text("FOREIGN")
            with self.assertRaises(owner.OwnershipRefusal):
                owner.export_evidence(work, evidence, pinned)
            self.assertTrue((work / owner.FILES[1]).exists())
            self.assertTrue((parent / "moved" / owner.FILES[0]).exists())

    def test_safety_f03_readback_failure_is_not_material_detection(self):
        injected = json.dumps(
            [
                {"start": 0, "length": 8192, "depth": 1, "data": True, "zero": False},
                {"start": 8192, "length": 4096, "depth": 0, "data": True, "zero": False},
                {"start": 12288, "length": c.SIZE - 12288, "depth": 1, "data": True, "zero": False},
            ]
        )

        def command_with_bad_readback(*argv, **kwargs):
            if argv[:2] == ("qemu-img", "map"):
                return injected
            raise Refusal("qemu-io 0x5a readback mismatch")

        with (
            patch.object(lab, "chain"),
            patch.object(lab, "pin_identity", return_value=(11, 22)),
            patch.object(lab, "command", side_effect=command_with_bad_readback),
            self.assertRaisesRegex(Refusal, "readback mismatch"),
        ):
            lab.verify_injected_fault(Path("child"), Path("backing"), 8192, 4096, (11, 22))

    def test_safety_f03_child_replacement_refused_before_map(self):
        with tempfile.TemporaryDirectory() as folder:
            child = Path(folder) / "child.qcow2"
            original = Path(folder) / "original.qcow2"
            child.write_bytes(b"original")
            identity = lab.pin_identity(child)
            child.rename(original)
            child.write_bytes(b"foreign!")
            with self.assertRaisesRegex(Refusal, "child replaced"):
                lab.verify_injected_fault(child, Path(folder) / "base", 8192, 4096, identity)
            self.assertTrue(original.exists())
            self.assertEqual(child.read_bytes(), b"foreign!")

    def test_safety_f04_depth_zero_no_data_no_zero_refused(self):
        suspect = [
            {"start": 0, "length": 4096, "depth": 0, "data": False, "zero": False},
            {"start": 4096, "length": c.SIZE - 4096, "depth": 1, "data": True, "zero": False},
        ]
        with (
            patch.object(lab, "chain"),
            patch.object(lab, "command", return_value=json.dumps(suspect)),
            self.assertRaisesRegex(Refusal, "owned extents"),
        ):
            lab.ensure_empty_child(Path("child"), Path("base"))

    def test_safety_f01_same_size_inode_swap_does_not_delete(self):
        import gaslux_popos_six_gpt_ownership as owner

        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            work = parent / "gaslux-pop-six-gpt-pinned"
            evidence = parent / "evidence"
            work.mkdir(mode=0o700)
            evidence.mkdir(mode=0o700)
            document = work / owner.FILES[0]
            document.write_bytes(b"original")
            stat_doc = document.stat()
            file_pins = {document.name: (stat_doc.st_dev, stat_doc.st_ino)}
            original = work / "original-retained"
            document.rename(original)
            document.write_bytes(b"FOREIGN!")
            st = work.stat()
            with self.assertRaisesRegex(owner.OwnershipRefusal, "inode replaced"):
                owner.export_evidence(work, evidence, (st.st_dev, st.st_ino), file_pins)
            self.assertEqual(document.read_bytes(), b"FOREIGN!")
            self.assertEqual(original.read_bytes(), b"original")

    @unittest.skipUnless(
        os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and __import__("shutil").which("qemu-img")
        and __import__("shutil").which("qemu-io"),
        "qemu-utils unavailable outside disposable synthetic runner",
    )
    def test_real_qemu_img_qemu_io_zero_mapping_without_guest(self):
        import subprocess

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            backing = new_file(root / "backing.raw", c.SIZE)
            child = root / "zero-overlay.qcow2"
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(backing), str(child)],
                check=True,
                capture_output=True,
            )
            lab.ensure_empty_child(child, backing)
            subprocess.run(
                ["qemu-io", "-f", "qcow2", "-c", "write -z 0 4096", str(child)],
                check=True,
                capture_output=True,
            )
            with self.assertRaisesRegex(Refusal, "owned extents"):
                lab.ensure_empty_child(child, backing)

    def test_safety_f01_export_symlink_hardlink_foreign_survive(self):
        import gaslux_popos_six_gpt_ownership as owner

        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            work = parent / "gaslux-pop-six-gpt-links"
            evidence = parent / "evidence"
            work.mkdir(mode=0o700)
            evidence.mkdir(mode=0o700)
            foreign = parent / "foreign-transaction.json"
            foreign.write_bytes(b"foreign data survives")
            destination = work / owner.FILES[0]
            st = work.stat()
            directory_pin = (st.st_dev, st.st_ino)
            destination.symlink_to(foreign)
            with self.assertRaises(OSError):
                owner.export_evidence(work, evidence, directory_pin)
            self.assertEqual(foreign.read_bytes(), b"foreign data survives")
            destination.unlink()  # Test fixture setup only; never the lab cleanup path.
            os.link(foreign, destination)
            with self.assertRaises(owner.OwnershipRefusal):
                owner.export_evidence(work, evidence, directory_pin)
            self.assertEqual(foreign.read_bytes(), b"foreign data survives")
            self.assertTrue(destination.exists())

    def test_safety_f01_enospc_partial_file_retained_without_cleanup_delete(self):
        import errno

        import gaslux_popos_six_gpt_ownership as owner

        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            work = parent / "gaslux-pop-six-gpt-enospc"
            evidence = parent / "evidence"
            work.mkdir(mode=0o700)
            evidence.mkdir(mode=0o700)
            target = work / "incomplete-create.raw"
            with (
                patch(
                    "gaslux_popos_reuse_snapshot_gate.os.ftruncate",
                    side_effect=OSError(errno.ENOSPC, "synthetic no space"),
                ),
                self.assertRaises(OSError),
            ):
                new_file(target, 8192)
            if target.exists():
                target.rename(work / "original-partial.raw")
            target.write_bytes(b"foreign transaction after ENOSPC")
            st = work.stat()
            owner.export_evidence(work, evidence, (st.st_dev, st.st_ino))
            self.assertEqual(target.read_bytes(), b"foreign transaction after ENOSPC")

    def test_valid_plan_is_permanently_no_writer(self):
        plan = sample_plan()
        c.validate_plan(plan, TX)
        for key in c.BOOLEANS:
            self.assertIs(plan[key], False)
        self.assertEqual(
            plan["distinstReuseArgv"],
            [
                "--no-efi-vars",
                "--use",
                ":5:reuse:mount=/boot/efi",
                "--use",
                ":6:reuse:mount=/",
            ],
        )
        self.assertNotIn("--test", plan["distinstReuseArgv"])

    def test_schema_accepts_synthetic_only_and_rejects_permissions(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema optional outside validation workflow")
        schema_path = Path(__file__).resolve().parents[1] / "schemas/popos-six-gpt-lab.schema.json"
        schema = json.loads(schema_path.read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(sample_plan())
        for key in c.BOOLEANS:
            bad = sample_plan()
            bad[key] = True
            with self.subTest(key=key):
                self.assertFalse(Draft202012Validator(schema).is_valid(bad))

    def test_replay_manifest_tamper_and_foreign_transaction_fail(self):
        p = sample_plan()
        with self.assertRaises(Refusal):
            c.validate_plan(p, "b1234567-1234-4abc-9abc-123456789abc")
        bad = copy.deepcopy(p)
        bad["transactionId"] = "b1234567-1234-4abc-9abc-123456789abc"
        with self.assertRaises(Refusal):
            c.validate_plan(bad, TX)
        bad = copy.deepcopy(p)
        bad["backingSha256"] = "0" * 64
        with self.assertRaises(Refusal):
            c.validate_plan(bad, TX)

    def test_foreign_guid_lba_partuuid_serial_and_gpt_hash_refused(self):
        for mutation in (
            lambda x: x["disk"].update(guid="0" * 36),
            lambda x: x["disk"].update(virtioSerial="FOREIGN"),
            lambda x: x["disk"].update(sizeBytes=x["disk"]["sizeBytes"] - 512),
            lambda x: x["partitions"][0].update(startLba=2049),
            lambda x: x["partitions"][2].update(endLba=3000000),
            lambda x: x["partitions"][4].update(partuuid="0" * 36),
            lambda x: x["partitions"][5].update(ownedByPopTransaction=False),
            lambda x: x["gpt"].update(secondary="NOT-SHA256"),
            lambda x: x["protectedPartitionHashes"].pop("4"),
            lambda x: x.update(protectedEspFileSha256="broken"),
            lambda x: x.update(canaries=[]),
            lambda x: x["media"].update(isoSha256="0" * 64),
            lambda x: x["media"].update(distinstSha256="0" * 64),
        ):
            bad = sample_plan()
            mutation(bad)
            bad = signed_fixture_with_change(bad)
            with self.subTest(mutation=str(mutation)), self.assertRaises(Refusal):
                c.validate_plan(bad, TX)

    def test_production_flags_and_topology_are_never_authorized(self):
        for field in c.BOOLEANS:
            bad = sample_plan()
            bad[field] = True
            with self.subTest(field=field), self.assertRaises(Refusal):
                c.validate_plan(signed_fixture_with_change(bad), TX)
        for field in ("windowsAttached", "physicalDisksAttached"):
            bad = sample_plan()
            bad[field] = True
            with self.assertRaises(Refusal):
                c.validate_plan(signed_fixture_with_change(bad), TX)

    def test_ovmf_template_and_checkpoint_foreign_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            f = new_file(folder / "synthetic-foreign.bin", 4096)
            with self.assertRaises(Refusal):
                lab.private_ovmf_copy(f, folder / "copied.fd")
            self.assertFalse((folder / "copied.fd").exists())
            foreign = folder / "some-other-file"
            foreign.symlink_to(f)
            with self.assertRaises(Refusal):
                regular(foreign)
            os.link(f, folder / "hardlink")
            with self.assertRaises(Refusal):
                regular(f)

    def test_injected_fault_recovery_rejects_partial_or_foreign_overlay(self):
        with patch.object(lab, "chain") as chain:
            chain.return_value = {"backing-filename": "foreign"}
            with (
                patch.object(lab, "command", return_value=json.dumps([{"depth": 0, "data": True}])),
                self.assertRaisesRegex(Refusal, "REFUSE_RECOVERY_UNPROVEN"),
            ):
                lab.ensure_empty_child(Path("/tmp/foreign"), Path("/tmp/base"))
        runner_source = (TOOLS / "gaslux_popos_six_gpt_lab.py").read_text()
        self.assertIn("ensure_empty_child(fault, base)", runner_source)
        self.assertNotIn("regular(fault, write=True).unlink()", runner_source)
        self.assertIn('sha(base) == plan["backingSha256"]', runner_source)
        self.assertIn("verify_canaries(base, plan, work)", runner_source)

    def test_readonly_fsck_partition_copy_and_untrusted_bounds(self):
        import gaslux_popos_six_gpt_fsck as fsc

        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            base = new_file(work / "fsck-fixture.raw", c.SIZE)
            sentinel = b"GASLUX-SYNTHETIC-ONLY-BYTE-EXACT"
            with base.open("r+b") as out:
                out.seek(c.PARTS[0].start * c.SECTOR + 1024)
                out.write(sentinel)
            extracted = work / "fsck-before-1.img"
            fsc.copy_owned_partition(base, extracted, c.PARTS[0].start, 16)
            self.assertEqual(extracted.read_bytes()[1024 : 1024 + len(sentinel)], sentinel)
            self.assertEqual(extracted.stat().st_size, 16 * c.SECTOR)
            for first, sectors in (
                (-1, 16),
                (0, 0),
                (c.COUNT, 1),
                (c.COUNT - 4, 8),
                (c.PARTS[0].start, -1),
                (c.PARTS[0].start, True),
            ):
                with (
                    self.subTest(first=first, sectors=sectors),
                    self.assertRaisesRegex(Refusal, "REFUSE_RECOVERY_UNPROVEN"),
                ):
                    fsc.copy_owned_partition(
                        base,
                        work / "fsck-after-1.img",
                        first,
                        sectors,
                    )
            with self.assertRaisesRegex(Refusal, "REFUSE_RECOVERY_UNPROVEN"):
                fsc.copy_owned_partition(
                    base,
                    work / "foreign.img",
                    c.PARTS[0].start,
                    16,
                )
            with self.assertRaises((OSError, Refusal)):
                fsc.copy_owned_partition(
                    base,
                    extracted,
                    c.PARTS[0].start,
                    16,
                )

    def test_fsck_probe_requires_frozen_backing_and_false_writer_flags(self):
        import gaslux_popos_six_gpt_fsck as fsc

        with self.assertRaises((OSError, Refusal)):
            fsc.verify_read_only_fsck(Path("/tmp/unknown-gaslux-six"), "before")
        source = (TOOLS / "gaslux_popos_six_gpt_fsck.py").read_text()
        self.assertIn('"fsck.fat", "-n"', source)
        self.assertIn('"e2fsck", "-fn"', source)
        self.assertIn("readOnlyFsckAllPassed", source)
        self.assertIn("observationComplete", source)
        self.assertIn("write_json_exclusive", source)

    def test_six_gpt_has_no_executable_qemu_or_distinst(self):
        source = (TOOLS / "gaslux_popos_six_gpt_lab.py").read_text()
        assert "qemu-system-" not in source
        assert "/usr/bin/distinst" not in source
        self.assertIn('choices=["prepare", "preflight", "recover"]', source)
        self.assertIn(
            "OBSERVATION_INCOMPLETE", (TOOLS / "gaslux_popos_six_gpt_contract.py").read_text()
        )
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github/workflows/popos-six-gpt-preflight-only.yml"
        ).read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("qemu-system", workflow)
        self.assertNotIn("distinst --", workflow)
        self.assertIn("GASLUX_POP_SIX_GPT_CONSENT:", workflow)


if __name__ == "__main__":
    unittest.main()
