"""Non-destructive ESP and Recovery block-offset RCA, private synthetic fixtures."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import windows_mint_ab_offset_rca as rca
from windows_mint_ab_checkpoint import AB_DIR, ARMS, REFERENCE


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


class OffsetRcaTests(unittest.TestCase):
    def test_fixed_granularity_changed_windows_and_absolute_offsets(self):
        base = b"a" * rca.CHUNK_BYTES + b"b" * rca.CHUNK_BYTES
        changed = b"a" * rca.CHUNK_BYTES + b"c" * rca.CHUNK_BYTES
        report = rca.analyze_partition_windows(
            lambda count, pos: base[pos : pos + count],
            lambda count, pos: changed[pos : pos + count],
            partition_bytes=len(base), disk_start_byte=2048 * 512,
            expected_before_sha256=sha(base),
            expected_after_sha256=sha(changed),
        )
        self.assertEqual(report["changedWindowCount"], 1)
        self.assertEqual(report["listedChangedWindows"][0]["partitionRelativeByteOffset"],
                         rca.CHUNK_BYTES)
        self.assertEqual(report["listedChangedWindows"][0]["diskAbsoluteByteOffset"],
                         2048 * 512 + rca.CHUNK_BYTES)
        self.assertFalse(report["writerAttributionProven"])
        self.assertFalse(report["byteExactOffsetsProven"])
        self.assertTrue(report["offsetMapComplete"])

    def test_incomplete_read_or_wrong_digest_never_passes(self):
        blob = b"a" * rca.CHUNK_BYTES
        for fault in ("partial", "bad_digest", "bad_size"):
            with (
                self.subTest(fault=fault),
                self.assertRaisesRegex(rca.OffsetRcaError, "BLOCKED_EVIDENCE"),
            ):
                rca.analyze_partition_windows(
                        lambda n, pos, fault=fault: blob[
                            pos : pos + n - (1 if fault == "partial" else 0)
                        ],
                        lambda n, pos: blob[pos : pos + n],
                        partition_bytes=len(blob) - (1 if fault == "bad_size" else 0),
                        disk_start_byte=0,
                        expected_before_sha256=sha(blob),
                        expected_after_sha256=("f" * 64 if fault == "bad_digest"
                                               else sha(blob)),
                    )

    def _owned_lab(self, root: str):
        workspace = Path(root)
        directory = workspace / AB_DIR
        directory.mkdir(mode=0o700)
        evidence = workspace / "evidence"
        evidence.mkdir(mode=0o700)
        reference = directory / REFERENCE
        reference.write_bytes(b"REFERENCE-QCOW2")
        reference.chmod(0o400)
        arm = directory / ARMS[0]
        arm.write_bytes(b"ARM-A-QCOW2")
        arm.chmod(0o600)
        checkpoint = {
            "transactionId": "test-offset-transaction",
            "checkpointReadyForReview": True,
            "qemuCompareReferenceBothArmsPassed": True,
            "sharedBackingChains": False,
            "referenceSha256": sha(reference.read_bytes()),
            "productionInstallAuthorized": False,
        }
        (directory / "checkpoint.json").write_text(json.dumps(checkpoint))
        geometry = {
            "sectorBytes": 512,
            "diskGuid": "11111111-1111-4111-8111-111111111111",
            "partitionRanges": [
                {"firstLba": 2048, "lastLba": 6143},
                {"firstLba": 6144, "lastLba": 6200},
                {"firstLba": 6201, "lastLba": 6900},
                {"firstLba": 7000, "lastLba": 11095},
                {"firstLba": 11096, "lastLba": 12000},
            ],
        }
        base = b"0" * (2 * rca.CHUNK_BYTES)
        esp_after = b"0" * rca.CHUNK_BYTES + b"1" * rca.CHUNK_BYTES
        rec_after = b"2" * (2 * rca.CHUNK_BYTES)
        return {
            "directory": directory, "evidence": evidence, "reference": reference,
            "arm": arm, "geometry": geometry,
            "first": {1: base, 4: base},
            "second": {1: esp_after, 4: rec_after},
            "before_hashes": [sha(base), "a" * 64, "b" * 64, sha(base)],
            "after_hashes": [sha(esp_after), "a" * 64, "b" * 64, sha(rec_after)],
        }

    def _scan(self, lab, *, corrupt=False):
        class MockGuest:
            def __init__(self, blobs):
                self.blobs = blobs
                self.readonly = None

            def add_drive_opts(self, image, **opts):
                self.readonly = opts.get("readonly")

            def launch(self):
                pass

            def list_devices(self):
                return ["/dev/sda"]

            def list_partitions(self):
                return ["/dev/sda" + str(i) for i in range(1, 6)]

            def blockdev_getsize64(self, device):
                if device == "/dev/sda":
                    return rca.VIRTUAL_BYTES
                number = int(device.removeprefix("/dev/sda"))
                return 2 * rca.CHUNK_BYTES if number in (1, 4) else 512

            def pread_device(self, device, count, offset):
                number = int(device.removeprefix("/dev/sda"))
                raw = self.blobs[number]
                if corrupt and number == 1 and offset == 0:
                    return raw[offset : offset + count - 1]
                return raw[offset : offset + count]

            def shutdown(self):
                pass

            def close(self):
                pass

        instances = [MockGuest(lab["first"]), MockGuest(lab["second"])]
        with (
            patch.dict(sys.modules, {"guestfs": types.SimpleNamespace(
                GuestFS=lambda **_: instances.pop(0))}),
            patch.object(rca, "assert_detached_from_processes"),
            patch.object(rca, "image_info"),
            patch.object(rca, "gpt_manifest", return_value=lab["geometry"]),
        ):
            return rca.compare_owned_ab_protected_offsets(
                directory=lab["directory"], reference=lab["reference"],
                observed=lab["arm"], evidence=lab["evidence"],
                manifest_name="mint-ab-offset-arm-a-control.json",
                transaction_id="test-offset-transaction",
                expected_gpt=lab["geometry"],
                before_partition_sha256=lab["before_hashes"],
                after_partition_sha256=lab["after_hashes"],
            )

    def test_readonly_detached_owned_arm_has_esp_recovery_absolute_offsets(self):
        with tempfile.TemporaryDirectory() as root:
            lab = self._owned_lab(root)
            before = [sha(p.read_bytes()) for p in (lab["reference"], lab["arm"])]
            report = self._scan(lab)
            self.assertEqual(report["result"], "PASS")
            self.assertEqual(report["partitions"]["esp"]["changedWindowCount"], 1)
            self.assertEqual(report["partitions"]["recovery"]["changedWindowCount"], 2)
            self.assertEqual(
                report["partitions"]["esp"]["listedChangedWindows"][0]["diskAbsoluteByteOffset"],
                2048 * 512 + rca.CHUNK_BYTES,
            )
            self.assertEqual(
                [sha(p.read_bytes()) for p in (lab["reference"], lab["arm"])], before)
            self.assertEqual(
                json.loads((lab["evidence"] / "mint-ab-offset-arm-a-control.json").read_text())[
                    "windowsOrMintWriterAttribution"], "UNKNOWN")

    def test_partial_libguestfs_read_does_not_publish_completed_offset_map(self):
        with tempfile.TemporaryDirectory() as root:
            lab = self._owned_lab(root)
            with self.assertRaisesRegex(rca.OffsetRcaError, "partial"):
                self._scan(lab, corrupt=True)
            self.assertFalse(
                (lab["evidence"] / "mint-ab-offset-arm-a-control.json").exists())

    def test_device_path_and_unsafe_output_refused_before_guestfs(self):
        with tempfile.TemporaryDirectory() as root:
            lab = self._owned_lab(root)
            for directory, manifest in (
                (Path("/dev"), "mint-ab-offset-arm-a-control.json"),
                (lab["directory"], "../escape.json"),
            ):
                with (
                    self.subTest(directory=str(directory), manifest=manifest),
                    self.assertRaisesRegex(rca.OffsetRcaError, "BLOCKED_EVIDENCE"),
                ):
                    rca.compare_owned_ab_protected_offsets(
                            directory=directory, reference=Path("/dev/sda"),
                            observed=lab["arm"], evidence=lab["evidence"],
                            manifest_name=manifest,
                            transaction_id="test-offset-transaction",
                            expected_gpt=lab["geometry"],
                            before_partition_sha256=lab["before_hashes"],
                            after_partition_sha256=lab["after_hashes"],
                        )


if __name__ == "__main__":
    unittest.main()
