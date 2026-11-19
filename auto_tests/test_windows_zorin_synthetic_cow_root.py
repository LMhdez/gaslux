"""Fail-closed Zorin/COW contracts, without disk access or ISO downloads."""
from __future__ import annotations

import importlib
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import windows_zorin_synthetic_cow_root as lab  # noqa: E402


class FakeGuest:
    active: "FakeGuest | None" = None

    def __init__(self, **_kwargs):
        self.dev = "/dev/sda"
        self.parts = [self.dev + str(i) for i in range(1, 6)]
        self.fs_uuid = "5ff126ad-d95c-4fb4-851b-c34b1537cfb2"
        self.windows_sha = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
        self.readonly = None
        self.mounted = False
        self.closed = False
        FakeGuest.active = self

    def add_drive_opts(self, _drive, *, format, readonly):
        assert format == "qcow2"
        self.readonly = readonly

    def launch(self):
        pass

    def list_devices(self):
        return [self.dev]

    def blockdev_getsize64(self, path):
        return 24 * 1024**3 if path.endswith("5") else lab.VIRTUAL_BYTES

    def list_partitions(self):
        return self.parts

    def vfs_type(self, _path):
        return "ext4"

    def vfs_uuid(self, _path):
        return self.fs_uuid

    def checksum_device(self, _algo, path):
        return self.windows_sha[int(path[-1]) - 1]

    def mount_ro(self, _path, _mount):
        self.mounted = True

    def is_file(self, path):
        return path in ("/etc/os-release", "/etc/fstab")

    def is_dir(self, path):
        return path == "/boot"

    def cat(self, _path):
        return "ID=zorin\nID_LIKE=\"ubuntu debian\"\n"

    def shutdown(self):
        pass

    def close(self):
        self.closed = True


class ZorinCowContracts(unittest.TestCase):
    def test_opt_in_is_required(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(lab.ZorinSyntheticError, "consent"):
                lab.ensure_hosted_only()

    def test_cannot_start_disk_without_verified_iso(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            with mock.patch.object(lab, "ensure_hosted_only", return_value=folder), \
                 mock.patch.object(lab, "verify_official_zorin",
                                   side_effect=lab.ZorinSyntheticError("bad media")):
                with self.assertRaisesRegex(lab.ZorinSyntheticError, "bad media"):
                    lab.run_synthetic_zorin(folder / "bad.iso", folder / "evidence")
            self.assertEqual(list(folder.iterdir()), [])

    def test_fake_sha_or_file_size_never_authorizes_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "iso"
            image.write_bytes(b"fake")
            with self.assertRaisesRegex(lab.ZorinSyntheticError, "unverified"):
                lab.verify_official_zorin(image)

    def test_fifth_audit_uses_readonly_libguestfs(self):
        mod = types.ModuleType("guestfs")
        mod.GuestFS = FakeGuest
        probe = FakeGuest()
        with mock.patch.dict(sys.modules, {"guestfs": mod}):
            lab.inspect_fifth(Path("synthetic.qcow2"), probe.fs_uuid, probe.windows_sha)
        self.assertEqual(FakeGuest.active.readonly, 1)
        self.assertTrue(FakeGuest.active.mounted)
        self.assertTrue(FakeGuest.active.closed)

    def test_hash_mismatch_refuses_lookalike_partitions(self):
        mod = types.ModuleType("guestfs")
        mod.GuestFS = FakeGuest
        probe = FakeGuest()
        with mock.patch.dict(sys.modules, {"guestfs": mod}):
            with self.assertRaisesRegex(lab.ZorinSyntheticError, "bytes changed"):
                lab.inspect_fifth(Path("synthetic.qcow2"), probe.fs_uuid,
                                  ["0" * 64] * 4)
        self.assertTrue(FakeGuest.active.closed)
        self.assertEqual(FakeGuest.active.readonly, 1)

    def test_root_uuid_mismatch_refused_before_ro_mount(self):
        mod = types.ModuleType("guestfs")
        mod.GuestFS = FakeGuest
        with mock.patch.dict(sys.modules, {"guestfs": mod}):
            with self.assertRaisesRegex(lab.ZorinSyntheticError, "changed Zorin root"):
                lab.inspect_fifth(Path("synthetic.qcow2"),
                                  "00000000-0000-0000-0000-000000000000",
                                  ["a" * 64, "b" * 64, "c" * 64, "d" * 64])
        self.assertFalse(FakeGuest.active.mounted)
        self.assertTrue(FakeGuest.active.closed)

    def test_source_checks_before_synthetic_partition_writes(self):
        text = Path(lab.__file__).read_text(encoding="utf-8")
        self.assertLess(text.index("verify_official_zorin(iso)  #"),
                        text.index('backing = workspace / "synthetic-no-windows.raw"'))
        self.assertLess(text.index("assert_distribution_rootfs_compatible_or_die"),
                        text.index('cmd("sgdisk", "-v"'))
        self.assertLess(text.index("format_only_fifth(guest, before_gpt, after_gpt)"),
                        text.index("_import_tar_into_exact_owned_root(overlay, archive"))
        self.assertIn('"realWindowsInstalledInBacking": False', text)
        self.assertIn('"sameDiskDualBootVerified": False', text)


if __name__ == "__main__":
    unittest.main()
