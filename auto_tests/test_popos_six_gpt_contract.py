"""Offline adversarial contracts for Pop's Windows-FREE synthetic six-GPT lab.

No QEMU guest, ISO, Windows files, real block devices or destructive operations.
"""

from __future__ import annotations

import copy
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

import gaslux_popos_six_gpt_contract as c  # noqa: E402
import gaslux_popos_six_gpt_lab as lab  # noqa: E402
import gaslux_popos_six_gpt_ownership as owner  # noqa: E402
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
        self.assertFalse(valid["observationComplete"])
        self.assertFalse(valid["observedWritesConfinedToOwnedPopPartitions"])
        self.assertEqual(valid["traceClassification"], "PARSED_UNTRUSTED")
        self.assertFalse(valid["productionInstallationAuthorized"])

    def test_safety_f02_multiple_devices_and_concatenated_events(self):
        for trace in (
            "vda virtio_blk_handle_write sector 3188736 nsectors 1\n"
            "vdb virtio_blk_handle_write sector 5285888 nsectors 1",
            "virtio_blk_handle_write sector 64 nsectors 1 "
            "virtio_blk_handle_write sector 3188736 nsectors 1",
            "virtio_blk_handle_discard sector 3188736 nsectors 1",
            "virtio_blk_handle_write sector -1 nsectors 1",
            "virtio_blk_handle_write sector 3188736 nsectors 1 trailing",
        ):
            with self.subTest(trace=trace), self.assertRaises(Refusal):
                c.audit_qemu_trace(trace)

    def test_f02_mixed_identity_truncated_unknown_and_fabricated(self):
        for trace in (
            "vda virtio_blk_handle_write sector 3188736 nsectors 1\n"
            "virtio_blk_handle_write sector 5285888 nsectors 1",
            "virtio_blk_handle_write sector 3188736 nsectors 0",
            "virtio_blk_handle_write sector 3188736 nsectors 1\n"
            "virtio_blk_handle_write sector 5285888",
            "virtio_blk_handle_write sector 3188736 nsectors 1\nunknown 3",
            "virtio_blk_handle_write sector 3188736 nsectors 1\n"
            "virtio_blk_handle_write_zeroes sector 5285888 nsectors 1",
            "virtio_blk_handle_write sector 3188736 nsectors 1\n"
            "virtio_blk_handle_discard sector 5285888 nsectors 1",
        ):
            with self.subTest(trace=trace), self.assertRaises(Refusal):
                c.audit_qemu_trace(trace)
        # A syntactically valid, fully fabricated producer string is never
        # promoted to independently observed / bound evidence.
        forged = c.audit_qemu_trace("vda virtio_blk_handle_write sector 3188736 nsectors 1")
        self.assertEqual(forged["traceClassification"], "PARSED_UNTRUSTED")
        for key in (
            "traceProvenanceAuthenticated",
            "virtioDeviceBound",
            "observationComplete",
            "observedWritesConfinedToOwnedPopPartitions",
        ):
            self.assertIs(forged[key], False)

    def test_f01_path_replacement_preserves_foreign_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "runner"
            workspace = Path(directory) / "repo"
            parent.mkdir()
            workspace.mkdir()
            work = Path(tempfile.mkdtemp(prefix="gaslux-pop-six-gpt-", dir=parent))
            evidence = workspace / "pop-six-gpt-evidence"
            evidence.mkdir(mode=0o700)
            with (
                patch.dict(
                    os.environ, {"RUNNER_TEMP": str(parent), "GITHUB_WORKSPACE": str(workspace)}
                ),
                owner.SafeWorkspace(work, evidence) as guard,
            ):
                (work / lab.PLAN_NAME).write_text("owned")
                guard.inspect()
                old = parent / "moved-original"
                work.rename(old)
                work.mkdir(mode=0o700)
                foreign = work / "foreign-private.txt"
                foreign.write_text("KEEP ME")
                with self.assertRaisesRegex(Refusal, "directory replaced"):
                    guard.inspect()
                self.assertEqual(foreign.read_text(), "KEEP ME")
                self.assertTrue((old / lab.PLAN_NAME).exists())
            self.assertEqual(foreign.read_text(), "KEEP ME")

    def test_f01_inode_symlink_hardlink_reuse_and_partial_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "runner"
            workspace = Path(directory) / "repo"
            parent.mkdir()
            workspace.mkdir()
            work = Path(tempfile.mkdtemp(prefix="gaslux-pop-six-gpt-", dir=parent))
            evidence = workspace / "pop-six-gpt-evidence"
            evidence.mkdir(mode=0o700)
            with patch.dict(
                os.environ, {"RUNNER_TEMP": str(parent), "GITHUB_WORKSPACE": str(workspace)}
            ):
                with owner.SafeWorkspace(work, evidence) as guard:
                    child = work / lab.CHILD_NAME
                    child.write_bytes(b"first")
                    guard.inspect()
                    # Preserve the original inode so inode reuse cannot hide a swap.
                    child.rename(work / "synthetic-esp-marker.tmp")
                    child.write_bytes(b"replacement")
                    with self.assertRaisesRegex(Refusal, "inode substituted"):
                        guard.inspect()
                    self.assertEqual(child.read_bytes(), b"replacement")
                child.unlink()
                child.symlink_to(work / lab.PLAN_NAME)
                with self.assertRaises((Refusal, OSError)), owner.SafeWorkspace(work, evidence):
                    pass
                child.unlink()
                child.write_bytes(b"private")
                os.link(child, work / lab.PLAN_NAME)
                with (
                    self.assertRaisesRegex(Refusal, "symlink/hardlink"),
                    owner.SafeWorkspace(work, evidence),
                ):
                    pass
                (work / lab.PLAN_NAME).unlink()
                child.unlink()
                # An incomplete run cannot export partial evidence or clean up.
                with owner.SafeWorkspace(work, evidence) as guard:
                    with self.assertRaisesRegex(Refusal, "missing proof"):
                        guard.evidence_bytes("pop-six-transaction.json")
                    with self.assertRaisesRegex(Refusal, "snapshot required"):
                        guard.export()
                self.assertTrue(work.is_dir())

    def test_f01_ovmf_vars_pinned_inode_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "runner"
            repo = root / "repo"
            parent.mkdir()
            repo.mkdir()
            work = Path(tempfile.mkdtemp(prefix="gaslux-pop-six-gpt-", dir=parent))
            evidence = repo / "pop-six-gpt-evidence"
            evidence.mkdir(mode=0o700)
            vars_path = work / lab.OVMF_NAME
            vars_path.write_bytes(b"original-private-vars")
            with (
                patch.dict(os.environ, {"RUNNER_TEMP": str(parent), "GITHUB_WORKSPACE": str(repo)}),
                owner.SafeWorkspace(work, evidence) as guard,
            ):
                old = work / "fault-injected-vars.fd"
                vars_path.rename(old)
                vars_path.write_bytes(b"foreign-vars")
                with self.assertRaisesRegex(Refusal, "inode substituted"):
                    guard.inspect()
                self.assertEqual(vars_path.read_bytes(), b"foreign-vars")
                self.assertEqual(old.read_bytes(), b"original-private-vars")
            with lab.PinnedResource(old) as pin:
                old.rename(work / "fault-restored-vars.fd")
                old.write_bytes(b"replacement-vars")
                with self.assertRaisesRegex(Refusal, "inode replaced"):
                    pin.verify()
            self.assertEqual(old.read_bytes(), b"replacement-vars")

    def test_f01_enospc_fails_without_unlink(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "runner"
            workspace = Path(directory) / "repo"
            parent.mkdir()
            workspace.mkdir()
            work = Path(tempfile.mkdtemp(prefix="gaslux-pop-six-gpt-", dir=parent))
            evidence = workspace / "pop-six-gpt-evidence"
            evidence.mkdir(mode=0o700)
            for name in owner.EVIDENCE:
                (work / name).write_text('{"synthetic":true}')
            with (
                patch.dict(
                    os.environ, {"RUNNER_TEMP": str(parent), "GITHUB_WORKSPACE": str(workspace)}
                ),
                owner.SafeWorkspace(work, evidence) as guard,
            ):
                snapshot = guard.capture_evidence()
                with (
                    patch.object(owner.os, "write", side_effect=OSError(errno.ENOSPC, "full")),
                    self.assertRaises(OSError),
                ):
                    guard.export(snapshot)
            for name in owner.EVIDENCE:
                self.assertEqual((work / name).read_text(), '{"synthetic":true}')

    def test_f03_tool_errors_never_become_typed_detection(self):
        offset = (c.PARTS[2].start + 4096) * c.SECTOR
        with tempfile.TemporaryDirectory() as directory:
            child = Path(directory) / "fault.qcow2"
            child.write_bytes(b"child")
            with lab.PinnedResource(child) as pin:
                for error in (
                    Refusal("qemu-img failure"),
                    ValueError("invalid json"),
                    subprocess.TimeoutExpired("qemu-img", 1),
                    subprocess.CalledProcessError(1, "qemu-io"),
                ):
                    with (
                        self.subTest(error=str(error)),
                        patch.object(lab, "child_owned_extents", side_effect=error),
                        self.assertRaises(type(error)),
                    ):
                        lab.verify_injected_fault(
                            child, Path(directory) / "base", offset, 4096, pin
                        )
                with (
                    patch.object(
                        lab,
                        "child_owned_extents",
                        return_value=[{"start": offset, "length": 4096, "data": True}],
                    ),
                    patch.object(lab, "command", side_effect=Refusal("qemu-io read failed")),
                    self.assertRaises(Refusal),
                ):
                    lab.verify_injected_fault(child, Path(directory) / "base", offset, 4096, pin)
                child.unlink()
                child.write_bytes(b"other")
                with self.assertRaisesRegex(Refusal, "inode replaced"):
                    lab.verify_injected_fault(child, Path(directory) / "base", offset, 4096, pin)

    @unittest.skipUnless(shutil.which("qemu-img") and shutil.which("qemu-io"), "qemu-utils absent")
    def test_f04_real_offline_qcow2_zero_data_and_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            base = folder / "base.raw"
            subprocess.run(["truncate", "-s", str(c.SIZE), str(base)], check=True)
            child = folder / "clean.qcow2"
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(base), str(child)],
                check=True,
                capture_output=True,
            )
            raw_map = subprocess.run(
                ["qemu-img", "map", "--output=json", str(child)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            print("F04_QEMU_MAP_CLEAN=" + raw_map[:4000], flush=True)
            lab.ensure_empty_child(child, base)
            subprocess.run(
                ["qemu-io", "-f", "qcow2", "-c", "write -P 0x5a 3188736 4096", str(child)],
                check=True,
                capture_output=True,
            )
            with self.assertRaisesRegex(Refusal, "owned extents"):
                lab.ensure_empty_child(child, base)
            zero_child = folder / "zero.qcow2"
            subprocess.run(
                [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    "-F",
                    "raw",
                    "-b",
                    str(base),
                    str(zero_child),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["qemu-io", "-f", "qcow2", "-c", "write -z 3188736 4096", str(zero_child)],
                check=True,
                capture_output=True,
            )
            with self.assertRaisesRegex(Refusal, "owned extents"):
                lab.ensure_empty_child(zero_child, base)
            wrong = folder / "wrong.raw"
            subprocess.run(["truncate", "-s", str(c.SIZE), str(wrong)], check=True)
            with self.assertRaisesRegex(Refusal, "foreign QCOW2"):
                lab.ensure_empty_child(zero_child, wrong)

    def test_safety_f04_zero_overlay_and_invalid_map(self):
        valid = {"start": 0, "length": c.SIZE, "depth": 1, "data": False, "zero": False}
        self.assertEqual(lab.parse_qcow_map(json.dumps([valid])), [valid])
        real_qemu = {**valid, "zero": True, "present": True, "compressed": False, "offset": 0}
        self.assertEqual(lab.parse_qcow_map(json.dumps([real_qemu])), [real_qemu])
        zero = {"start": 0, "length": 4096, "depth": 0, "data": False, "zero": True}
        for bad in (
            [zero],
            [{**valid, "unknown": True}],
            [{**valid, "length": 4096}],
            [{**valid, "start": -1}],
            [{**valid, "depth": 0, "present": False, "data": True}],
            [{**valid, "compressed": True, "data": False}],
            [
                {**valid, "length": 4096},
                {**valid, "start": 2048, "length": c.SIZE - 2048},
            ],
        ):
            with self.subTest(map=bad), self.assertRaises(Refusal):
                lab.parse_qcow_map(json.dumps(bad))
        with (
            patch.object(lab, "chain"),
            patch.object(
                lab,
                "command",
                return_value=json.dumps(
                    [
                        zero,
                        {
                            "start": 4096,
                            "length": c.SIZE - 4096,
                            "depth": 1,
                            "data": False,
                            "zero": False,
                        },
                    ]
                ),
            ),
            self.assertRaisesRegex(Refusal, "owned extents"),
        ):
            lab.ensure_empty_child(Path("/tmp/child"), Path("/tmp/base"))

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
        self.assertIn("verify_injected_fault(fault, base,", runner_source)
        self.assertIn("with PinnedResource(fault) as child_pin:", runner_source)
        self.assertIn("fault-rebuilt-child.qcow2", runner_source)
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
