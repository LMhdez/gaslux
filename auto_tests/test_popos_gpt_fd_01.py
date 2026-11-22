"""POP-GPT-FD-01: adversarial real sgdisk fixture, canonical FD reader, deny-only."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import gaslux_popos_six_gpt_lab as lab  # noqa: E402
import libertix_disk_identity_gate as canonical  # noqa: E402
from gaslux_popos_gpt_fd_boundary import PinnedSixGpt, inspect_owned_six_gpt  # noqa: E402
from gaslux_popos_reuse_snapshot_gate import Refusal  # noqa: E402
from gaslux_popos_six_gpt_contract import COUNT, DISK_GUID, PARTS, SECTOR, SIZE  # noqa: E402


class PinnedPopGptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(bool(os.environ.get("RUNNER_TEMP")))
        runner = Path(os.environ["RUNNER_TEMP"])
        self.temp = tempfile.TemporaryDirectory(
            prefix="gaslux-pop-six-gpt-fd-test-", dir=runner,
        )
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.base = self.work / "prepared-six.raw"
        with self.base.open("xb") as image:
            image.truncate(SIZE)
        self._sgdisk(
            "--zap-all", "--clear", "--disk-guid=" + DISK_GUID,
            *[
                arg
                for p in PARTS
                for arg in (
                    f"--new={p.index}:{p.start}:{p.end}",
                    f"--typecode={p.index}:{p.type_guid}",
                    f"--partition-guid={p.index}:{p.partuuid}",
                )
            ],
        )
        self.vars = patch.dict(
            os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "GITHUB_REPOSITORY": "LMhdez/gaslux",
            },
        )
        self.vars.start()
        self.addCleanup(self.vars.stop)

    def _sgdisk(self, *args: str) -> None:
        subprocess.run(["sgdisk", *args, str(self.base)], check=True, capture_output=True,
                       text=True, timeout=90)

    def test_h_valid_synthetic_gpt_and_byte_exact_region_hashes(self) -> None:
        with PinnedSixGpt(self.work) as pin:
            proof = pin.inspect()
            self.assertEqual(proof["diskGuid"], DISK_GUID)
            self.assertTrue(proof["primaryAndBackupCrcVerified"])
            self.assertEqual(len(proof["partitions"]), 6)
            with patch.object(
                lab, "command", side_effect=AssertionError("path authority forbidden")
            ):
                self.assertEqual(lab.verify_fd_gpt(self.base, pinned=pin), proof)
            self.assertEqual(inspect_owned_six_gpt(self.work), proof)
            primary = os.pread(pin.fd, 34 * SECTOR, 0)
            backup = os.pread(pin.fd, 33 * SECTOR, (COUNT - 33) * SECTOR)
            self.assertEqual(proof["pmbrAndPrimary"], hashlib.sha256(primary).hexdigest())
            self.assertEqual(proof["secondary"], hashlib.sha256(backup).hexdigest())

    def test_a_pathname_swap_after_fd_pin_refuses(self) -> None:
        substitute = self.work / "substitute.raw"
        with substitute.open("xb") as obj:
            obj.truncate(SIZE)
        with PinnedSixGpt(self.work) as pin:
            detached = self.work / "detached-owned.raw"
            self.base.rename(detached)
            substitute.rename(self.base)
            with self.assertRaises(Refusal):
                pin.inspect()

    def test_b_invalid_primary_crc_refuses(self) -> None:
        with self.base.open("r+b") as obj:
            obj.seek(SECTOR + 16)
            byte = obj.read(1)
            obj.seek(SECTOR + 16)
            obj.write(bytes([byte[0] ^ 0x01]))
        with self.assertRaises(Refusal):
            inspect_owned_six_gpt(self.work)

    def test_c_invalid_backup_crc_refuses(self) -> None:
        with self.base.open("r+b") as obj:
            obj.seek(SIZE - SECTOR + 16)
            byte = obj.read(1)
            obj.seek(SIZE - SECTOR + 16)
            obj.write(bytes([byte[0] ^ 0x01]))
        with self.assertRaises(Refusal):
            inspect_owned_six_gpt(self.work)

    def test_d_short_read_or_truncation_refuses(self) -> None:
        with PinnedSixGpt(self.work) as pin:
            os.truncate(self.base, SIZE - SECTOR)
            with self.assertRaises(Refusal):
                pin.inspect()

    def test_e_geometry_and_expected_partition_changes_refuse(self) -> None:
        with PinnedSixGpt(self.work) as pin:
            with self.assertRaises(Refusal):
                pin.inspect(expected_sector=4096)
            # sgdisk updates both GPT CRCs, so this is a structural deny,
            # not merely rejection of corrupt GPT data.
            self._sgdisk("--partition-guid=1:" + str(uuid.uuid4()))
            with self.assertRaises(Refusal):
                pin.inspect()

    def test_f_foreign_fd_even_with_valid_synthetic_gpt_refuses(self) -> None:
        foreign = self.work / "foreign.raw"
        with foreign.open("xb") as obj:
            obj.truncate(SIZE)
        with PinnedSixGpt(self.work) as pin:
            foreign_fd = os.open(foreign, os.O_RDONLY)
            try:
                with self.assertRaises(Refusal):
                    pin.inspect(supplied_fd=foreign_fd)
            finally:
                os.close(foreign_fd)

    def test_g_same_inode_mutation_during_canonical_read_refuses(self) -> None:
        original = os.pread
        attacked = {"yes": False}
        inode = self.base.stat().st_ino

        def interfere(fd: int, length: int, offset: int) -> bytes:
            value = original(fd, length, offset)
            if not attacked["yes"] and offset == SECTOR:
                attacked["yes"] = True
                with self.base.open("r+b", buffering=0) as obj:
                    obj.seek(SECTOR + 16)
                    old = obj.read(1)
                    obj.seek(SECTOR + 16)
                    obj.write(bytes([old[0] ^ 0x01]))
                    os.fsync(obj.fileno())
            return value

        with (
            PinnedSixGpt(self.work) as pin,
            patch.object(canonical.os, "pread", side_effect=interfere),
            self.assertRaises(Refusal),
        ):
            pin.inspect()
        self.assertTrue(attacked["yes"])
        self.assertEqual(self.base.stat().st_ino, inode)

    def test_closed_descriptor_refuses(self) -> None:
        with PinnedSixGpt(self.work) as pin:
            pin.close()
            with self.assertRaises(Refusal):
                pin.inspect()

    def test_work_directory_swap_refuses(self) -> None:
        with PinnedSixGpt(self.work) as pin:
            detached = self.work.parent / (self.work.name + "-detached")
            self.work.rename(detached)
            self.work.mkdir(mode=0o700)
            with self.assertRaises(Refusal):
                pin.inspect()

    def test_foreign_workspace_fd_refused_before_gpt_parsing(self) -> None:
        runner = Path(self.temp.name).parent
        outside = runner / "foreign.raw"
        with outside.open("xb") as obj:
            obj.truncate(SIZE)
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        with self.assertRaises(Refusal):
            lab.verify_fd_gpt(outside)

    def test_denial_has_no_operational_promotion(self) -> None:
        with PinnedSixGpt(self.work) as pin:
            proof = pin.inspect()
            self.assertNotIn("distinstExecutionAuthorized", proof)
            self.assertNotIn("windowsWriterAuthorized", proof)
            self.assertTrue(proof["primaryAndBackupCrcVerified"])


if __name__ == "__main__":
    unittest.main()
