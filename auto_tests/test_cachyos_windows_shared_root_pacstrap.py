"""Signed Archiso lab pacstrap scope: synthetic GPT and deny-by-default tests.

Never opens a real disk; GPT windows are bytes from the existing fixture.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import json
import stat
import struct
from types import SimpleNamespace
from unittest.mock import patch
import unittest
import uuid
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "tools"))
import cachyos_windows_shared_root_pacstrap as shared
from test_windows_cachyos_qcow2_gpt_readonly import create_disk_windows
from test_cachyos_windows_shared_archiso_handoff import fixture as signed_fixture
from tools.windows_cachyos_qcow2_gpt_readonly import TYPES

LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"


def fixture():
    front, back = create_disk_windows(part_types=list(TYPES) + [LINUX])
    data = front[2*512:34*512]
    parts = []
    for i in range(5):
        entry = data[i*128:(i+1)*128]
        lo, hi = struct.unpack_from("<QQ", entry, 32)
        parts.append({
            "index": i+1,
            "typeGuid": str(uuid.UUID(bytes_le=entry[:16])),
            "uniqueGuid": str(uuid.UUID(bytes_le=entry[16:32])),
            "firstLba": lo, "lastLba": hi,
        })
    return front, back, {
        "diskGuidSha256": hashlib.sha256(front[512+56:512+72]).hexdigest(),
        "gptWindowsSha256": hashlib.sha256(front+back).hexdigest(),
        "partitions": parts,
    }


def check(front, back, plan):
    # Only /dev/null is opened; the mock replaces every read with fixture bytes.
    # No block device is ever accessed or mutated.
    def pread(_fd, _count, offset):
        return front if offset == 0 else back
    def ioctl(_fd, request, _payload):
        if request == 0x80081272:
            return struct.pack("=Q", 128 * 1024**3)
        if request == 0x1268:
            return struct.pack("=I", 512)
        raise AssertionError("unexpected block ioctl")
    with patch.object(Path, "is_block_device", return_value=True), \
         patch.object(Path, "is_symlink", return_value=False), \
         patch("os.open", return_value=9), \
         patch("os.close"), \
         patch("fcntl.ioctl", side_effect=ioctl), \
         patch("os.pread", side_effect=pread), \
         patch("os.fstat", return_value=SimpleNamespace(
             st_mode=stat.S_IFBLK, st_rdev=123)):
        return shared.strict_gpt_evidence(Path("/dev/vdb"), plan)


class SharedRootOnlySafety(unittest.TestCase):
    def test_both_gpt_crcs_and_five_signed_entries(self):
        front, back, plan = fixture()
        proof = check(front, back, plan)
        self.assertTrue(proof["bothGptCopiesCrcVerified"])
        self.assertTrue(proof["allWindowsAndOwnedLinuxEntriesIdenticalToSignedPlan"])
        self.assertFalse(proof["productionWritesAuthorized"])

    def test_wrong_whole_disk_geometry_fails_before_gpt_reads(self):
        _, _, plan = fixture()
        for bytes_count, sector_bytes in (
            (64 * 1024**3, 512), (128 * 1024**3, 4096),
        ):
            def ioctl(_fd, request, _payload):
                return (struct.pack("=Q", bytes_count)
                        if request == 0x80081272
                        else struct.pack("=I", sector_bytes))
            with self.subTest(size=bytes_count, sector=sector_bytes), \
                 patch.object(Path, "is_block_device", return_value=True), \
                 patch.object(Path, "is_symlink", return_value=False), \
                 patch("os.open", return_value=9), \
                 patch("os.close"), \
                 patch("os.fstat", return_value=SimpleNamespace(
                     st_mode=stat.S_IFBLK, st_rdev=123)), \
                 patch("fcntl.ioctl", side_effect=ioctl), \
                 patch("os.pread") as read:
                with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                            "size/sector bytes"):
                    shared.strict_gpt_evidence(Path("/dev/vdb"), plan)
                read.assert_not_called()

    def test_partition_node_or_foreign_disk_rejected_before_open(self):
        _, _, plan = fixture()
        with patch.object(Path, "is_block_device", return_value=True), \
             patch.object(Path, "is_symlink", return_value=False), \
             patch("os.open") as opened:
            for bad in ("/dev/vdb5", "/dev/sda", "/dev/nvme0n1",
                        "/dev/mapper/windows", "/dev/vdb/../sda"):
                with self.subTest(path=bad), \
                     self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                            "one whole virtio disk"):
                    shared.strict_gpt_evidence(Path(bad), plan)
            opened.assert_not_called()

    def test_foreign_fifth_guid_rejected(self):
        front, back, plan = fixture()
        plan["partitions"][4]["uniqueGuid"] = "10000000-0000-4000-8000-000000000001"
        with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                    "GPT entry disagrees"):
            check(front, back, plan)

    def test_signed_windows_partition_record_bytes_are_binding(self):
        front, back, plan = fixture()
        plan["gptWindowsSha256"] = "a" * 64
        with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                    "Windows GPT entry bytes differ"):
            check(front, back, plan)

    def test_missing_backup_crc_or_modified_primary_rejected(self):
        front, back, plan = fixture()
        damaged = bytearray(back)
        damaged[-512+20] ^= 1
        with self.assertRaises(ValueError):
            check(front, bytes(damaged), plan)
        damaged = bytearray(front)
        damaged[2*512+20] ^= 1
        with self.assertRaises(ValueError):
            check(bytes(damaged), back, plan)

    def test_hybrid_mbr_refused(self):
        front, back, plan = fixture()
        damaged = bytearray(front)
        damaged[446+16+4] = 0x07
        with self.assertRaisesRegex(shared.SharedDiskHandoffRejected, "hybrid"):
            check(bytes(damaged), back, plan)

    def test_noncanonical_windows_pmbr_only_reported_not_authorized(self):
        front, back, plan = fixture()
        changed = bytearray(front)
        struct.pack_into("<I", changed, 446+12, 0xffffffff)
        plan["gptWindowsSha256"] = hashlib.sha256(bytes(changed)+back).hexdigest()
        observed = check(bytes(changed), back, plan)
        self.assertTrue(observed["protectiveMbrWindowsLabOversized"])
        self.assertFalse(observed["productionWritesAuthorized"])

    def test_no_disk_actions_from_non_archiso_user(self):
        with patch.object(shared, "require_live_archiso",
                          side_effect=shared.SharedDiskHandoffRejected("not Archiso")), \
             patch.object(shared, "protected_files_readonly") as files, \
             patch.object(shared, "execute") as commands:
            with self.assertRaisesRegex(shared.SharedDiskHandoffRejected, "not Archiso"):
                shared.guest_plan(SimpleNamespace())
            files.assert_not_called()
            commands.assert_not_called()

    @unittest.skipUnless(shutil.which("openssl"), "Ed25519 requires openssl")
    def test_independent_ed25519_cow_grant_required_and_signed(self):
        plan = signed_fixture()
        signed_bytes = shared.canonical(plan)
        with tempfile.TemporaryDirectory(prefix="gaslux-grant-sign-") as tmp:
            root = Path(tmp)
            private = root / "signing-key.pem"
            pub = root / "public.pem"
            plan_path = root / "plan.json"
            grant_path = root / "grant.json"
            signature = root / "grant.sig"
            plan_path.write_bytes(signed_bytes)
            # Synthetic immutable control scripts: the grant must bind the
            # same bytes that the Archiso will later execute from RO media.
            builder = root / "strict-pacman.py"
            checker = root / "pacman-trust.py"
            builder.write_bytes((HERE.parent / "assets/live/cachyos-strict-pacman.py").read_bytes())
            checker.write_bytes((HERE.parent / "assets/live/cachyos-pacman-trust.py").read_bytes())
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                            "-out", str(private)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "pkey", "-in", str(private),
                            "-pubout", "-out", str(pub)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            grant = {
                "schemaVersion": 1, "labOnly": True,
                "operation": "pacstrap-only-preexisting-fifth-ext4",
                "runId": plan["runId"], "bootNonce": plan["bootNonce"],
                "signedPlanSha256": hashlib.sha256(signed_bytes).hexdigest(),
                "targetVirtioSerial": plan["targetVirtioSerial"],
                "rootPartuuid": plan["partitions"][4]["uniqueGuid"],
                "rootFsUuid": plan["rootFsUuid"],
                "sourceWindowsGptSha256": plan["gptWindowsSha256"],
                "hostCheckpointSha256": "1" * 64,
                "hostOverlayBackingProofSha256": "2" * 64,
                "sourceImageReadOnly": True, "discardableOverlay": True,
                "windowsEspWritesAllowed": False,
                "strictPacmanBuilderSha256": hashlib.sha256(builder.read_bytes()).hexdigest(),
                "pacmanTrustGuardSha256": hashlib.sha256(checker.read_bytes()).hexdigest(),
            }
            args = SimpleNamespace(root_write_grant=grant_path,
                                   grant_signature=signature,
                                   plan=plan_path, public_key=pub)
            def signed(value):
                grant_path.write_bytes(shared.canonical(value))
                subprocess.run(["openssl", "pkeyutl", "-sign",
                                "-inkey", str(private), "-rawin",
                                "-in", str(grant_path), "-out",
                                str(signature)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            signed(grant)
            shared.verify_lab_root_write_grant(args, plan, control_dir=root)
            # A correct detached signature is insufficient if any scope
            # or host-checkpoint statement is changed and then re-signed.
            for field, wrong in (
                ("windowsEspWritesAllowed", True),
                ("discardableOverlay", False),
                ("sourceImageReadOnly", False),
                ("hostCheckpointSha256", "0" * 64),
                ("rootPartuuid", "00000000-0000-0000-0000-000000000000"),
                ("operation", "format-entire-disk"),
            ):
                altered = dict(grant)
                altered[field] = wrong
                signed(altered)
                with self.subTest(field=field), self.assertRaises(
                        shared.SharedDiskHandoffRejected):
                    shared.verify_lab_root_write_grant(args, plan, control_dir=root)
            # Even a correctly signed grant cannot accept modified policy
            # executables mounted from a foreign or swapped control image.
            signed(grant)
            original_builder = builder.read_bytes()
            builder.write_bytes(original_builder + b"\n# unexpected alteration\n")
            with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                        "program bytes differ"):
                shared.verify_lab_root_write_grant(args, plan, control_dir=root)
            builder.write_bytes(original_builder)
            original_checker = checker.read_bytes()
            checker.write_bytes(original_checker + b"\n# unexpected alteration\n")
            with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                        "program bytes differ"):
                shared.verify_lab_root_write_grant(args, plan, control_dir=root)
            checker.write_bytes(original_checker)
            signed(grant)
            grant_path.write_bytes(grant_path.read_bytes().replace(
                b'pacstrap-only', b'pacstrap-evil'))
            with self.assertRaises(shared.SharedDiskHandoffRejected):
                shared.verify_lab_root_write_grant(args, plan, control_dir=root)
            args.grant_signature = None
            with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                        "separate signed"):
                shared.verify_lab_root_write_grant(args, plan, control_dir=root)

    def test_pacstrap_never_called_without_separate_write_grant(self):
        args = SimpleNamespace()
        with patch.object(shared, "guest_plan",
                          return_value=(signed_fixture(), Path("/dev/null"))), \
             patch.object(shared, "verify_lab_root_write_grant",
                          side_effect=shared.SharedDiskHandoffRejected("no grant")), \
             patch.object(shared, "execute") as command:
            with self.assertRaisesRegex(shared.SharedDiskHandoffRejected, "no grant"):
                shared.pacstrap_only(args)
            command.assert_not_called()

    def test_unsigned_or_rw_pacman_control_cannot_authorize_root_mount(self):
        plan = signed_fixture()
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "is_symlink", return_value=False), \
             patch.object(shared, "execute", return_value="rw,relatime") as runner:
            with self.assertRaisesRegex(shared.SharedDiskHandoffRejected,
                                        "read-only"):
                shared.prepare_signed_only_pacman(plan)
            # Fail before invoking a renderer, pacman-conf, mount, or pacstrap.
            self.assertEqual(runner.call_count, 1)
            self.assertEqual(runner.call_args.args[0][0], "findmnt")

    def test_protected_windows_hash_refuses_intermediate_and_final_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-ro-hash-") as tmp:
            root = Path(tmp)
            (root / "Windows" / "System32").mkdir(parents=True)
            trusted = root / "Windows" / "System32" / "winload.efi"
            trusted.write_bytes(b"verified-owned-windows-file")
            good = hashlib.sha256(trusted.read_bytes()).hexdigest()
            self.assertEqual(shared.sha_file(trusted), good)

            # Final symlink to an existing file is refused, even if its
            # target bytes would match the signed digest.
            trusted.unlink()
            other = root / "other.bin"
            other.write_bytes(b"verified-owned-windows-file")
            trusted.symlink_to(other)
            with self.assertRaises(OSError):
                shared.sha_file(trusted)
            trusted.unlink()

            # Intermediary symlink cannot redirect the traversal into
            # another directory with an identically named file.
            original_dir = root / "Windows"
            original_dir.rename(root / "RealWindows")
            (root / "Windows").symlink_to(root / "RealWindows", target_is_directory=True)
            with self.assertRaises(OSError):
                shared.sha_file(root / "Windows" / "System32" / "winload.efi")

    def test_signed_partition_mount_rejects_foreign_source_and_unsafe_options(self):
        point = Path("/run/gaslux-cow-test")
        device = Path("/dev/vdb3")
        for readonly, expected_options in (
            (True, "ro,nosuid,nodev,noexec,relatime"),
            (False, "rw,nosuid,nodev,relatime"),
        ):
            def check(*, observed_source="/dev/vdb3", observed_type="ntfs3",
                      options=expected_options):
                def fake_run(argv):
                    self.assertEqual(argv[:4], ["findmnt", "-n", "-M",
                                                str(point)])
                    return {"SOURCE": observed_source,
                            "FSTYPE": observed_type,
                            "OPTIONS": options}[argv[-1]]
                shared.verify_mounted_source(
                    point, device, "ntfs3", readonly=readonly, run=fake_run)

            with self.subTest(readonly=readonly):
                check()
                for mutation in (
                    {"observed_source": "/dev/vdc3"},
                    {"observed_source": "/dev/vdb4"},
                    {"observed_type": "ext4"},
                    {"options": "rw,nosuid,nodev,noexec"} if readonly
                        else {"options": "ro,nosuid,nodev,noexec"},
                    {"options": "ro,relatime"} if readonly
                        else {"options": "rw,relatime"},
                ):
                    with self.subTest(mutation=mutation), \
                         self.assertRaisesRegex(
                             shared.SharedDiskHandoffRejected,
                             "mount source, filesystem or access flags"):
                        check(**mutation)

    def test_source_protection_is_required_on_both_mount_paths(self):
        source = (HERE / "tools/cachyos_windows_shared_root_pacstrap.py").read_text()
        self.assertIn("verify_mounted_source(Path(temp), source, mount_type,",
                      source)
        self.assertIn('verify_mounted_source(ROOT, root_partition, "ext4", readonly=False)',
                      source)
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("dir_fd=directory", source)

    def test_backend_writes_only_native_root_never_installs_bootloader(self):
        source = (HERE / "tools/cachyos_windows_shared_root_pacstrap.py").read_text()
        self.assertIn('"pacstrap", "-K", "-C", str(strict_config), str(ROOT)', source)
        self.assertIn("prepare_signed_only_pacman(plan)", source)
        self.assertIn('"python3", str(verifier), "--config", str(config)', source)
        self.assertNotIn("SigLevel = Never", source)
        self.assertIn('protected_files_readonly(disk, plan)', source)
        self.assertIn('strict_gpt_evidence(disk, plan)', source)
        self.assertIn('GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED', source)
        for command in ("sgdisk --clear", "mkfs.vfat", "mkfs.ext4",
                        "grub-install", "efibootmgr -c", "part_add(",
                        "part_del(", "BootOrder", "BootNext"):
            self.assertNotIn(command, source)


if __name__ == "__main__":
    unittest.main()
