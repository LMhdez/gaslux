"""No-media, no-guest regressions for post-firstboot Windows GPT inspection."""
from __future__ import annotations
import importlib.util
import os
import pathlib
import sys
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
SPEC = importlib.util.spec_from_file_location(
    "gaslux_postfirstboot_gpt_ro", TOOLS / "windows_x64_installed_gpt_ro_audit.py"
)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)

MIB = 1024**2
GIB = 1024**3


class MockGuestFS:
    def __init__(self):
        self.parts = [
            {"part_num": 1, "part_start": 1*MIB, "part_size": 260*MIB},
            {"part_num": 2, "part_start": 261*MIB, "part_size": 16*MIB},
            {"part_num": 3, "part_start": 277*MIB, "part_size": 72*GIB},
            {"part_num": 4, "part_start": 277*MIB+72*GIB, "part_size": 1536*MIB},
        ]
        self.kinds = list(AUDIT.TYPES)
        self.guids = [
            f"0000000{i}-1111-2222-3333-444444444444" for i in range(1,5)
        ]
        self.mounts = []
        self.mounted = None
        self.files = {
            1: {"/EFI/Microsoft/Boot/bootmgfw.efi",
                "/EFI/Microsoft/Boot/BCD"},
            3: {"/Windows/System32/winload.efi",
                "/Windows/System32/config/SYSTEM"},
        }

    def list_devices(self):
        return ["/dev/sda"]

    def part_get_parttype(self, _):
        return "gpt"

    def blockdev_getsize64(self, _):
        return 128*GIB

    def part_list(self, _):
        return self.parts

    def part_get_gpt_type(self, _, number):
        return self.kinds[number-1]

    def part_get_gpt_guid(self, _, number):
        return self.guids[number-1]

    def vfs_type(self, volume):
        return {"/dev/sda1": "vfat", "/dev/sda3": "ntfs",
                "/dev/sda4": "ntfs"}.get(volume, "unknown")

    def mount_ro(self, volume, target):
        assert target == "/"
        self.mounts.append(volume)
        self.mounted = int(volume[-1])

    def is_file(self, filename):
        return filename in self.files.get(self.mounted, set())

    def umount_all(self):
        self.mounted = None


class OfflineWindowsDiskAuditTests(unittest.TestCase):
    def assert_rejected(self, transform, expected):
        g = MockGuestFS()
        transform(g)
        with self.assertRaisesRegex(AUDIT.DiskAuditError, expected):
            AUDIT.inspect_layout(g)

    def test_valid_layout_with_real_file_paths_still_claims_no_dualboot(self):
        g = MockGuestFS()
        report = AUDIT.inspect_layout(g)
        self.assertEqual(report["partitionCount"], 4)
        self.assertEqual(g.mounts, ["/dev/sda1", "/dev/sda3"])
        self.assertTrue(report["espBootManagerPresent"])
        self.assertTrue(report["espBcdPresent"])
        for flag in ("sameDiskDualBootVerified", "stable",
                     "winReRecoveryAfterLinuxVerified", "storageWritesAuthorized"):
            self.assertIs(report[flag], False)
        self.assertIn('"stable": false', AUDIT.encode_report(report))

    def test_mbr_is_rejected(self):
        self.assert_rejected(
            lambda g: setattr(g, "part_get_parttype", lambda _: "msdos"),
            "not a GPT",
        )

    def test_unexpected_extra_partition_rejected(self):
        self.assert_rejected(
            lambda g: g.parts.append({"part_num":5,"part_start":90*GIB,"part_size":GIB}),
            "four Windows GPT",
        )

    def test_recovery_guid_type_rejected(self):
        self.assert_rejected(
            lambda g: g.kinds.__setitem__(3, AUDIT.BASIC),
            "partition sequence",
        )

    def test_partition_overlap_rejected(self):
        self.assert_rejected(
            lambda g: g.parts[3].update(part_start=260*MIB),
            "geometry",
        )

    def test_duplicate_guid_rejected(self):
        self.assert_rejected(
            lambda g: g.guids.__setitem__(3, g.guids[0]),
            "duplicate GPT",
        )

    def test_absent_efi_boot_manager_rejected(self):
        self.assert_rejected(
            lambda g: g.files[1].remove("/EFI/Microsoft/Boot/bootmgfw.efi"),
            "Boot Manager",
        )

    def test_absent_bcd_rejected(self):
        self.assert_rejected(
            lambda g: g.files[1].remove("/EFI/Microsoft/Boot/BCD"),
            "BCD",
        )

    def test_absent_windows_loader_rejected(self):
        self.assert_rejected(
            lambda g: g.files[3].remove("/Windows/System32/winload.efi"),
            "loader",
        )

    def test_foreign_device_is_rejected(self):
        self.assert_rejected(
            lambda g: setattr(g, "list_devices", lambda: ["/dev/sda", "/dev/sdb"]),
            "disk count",
        )

    def test_non_hosted_environment_and_host_path_rejected(self):
        with patch.dict(os.environ, {
            "GITHUB_ACTIONS":"true",
            "RUNNER_ENVIRONMENT":"github-hosted",
            "RUNNER_OS":"Linux",
            "GITHUB_REPOSITORY":"LMhdez/gaslux",
            "RUNNER_TEMP":"/home/runner/work/_temp",
        }):
            for path in (pathlib.Path("/dev/sda"),
                         pathlib.Path("/tmp/foreign.qcow2"),
                         pathlib.Path("/home/runner/work/_temp/"
                                      "gaslux-win-x64-lab/foreign.qcow2")):
                with self.subTest(path=str(path)), self.assertRaisesRegex(
                    AUDIT.DiskAuditError, "exact privately owned"
                ):
                    AUDIT.require_owned_qcow2(path)

    def test_binding_uses_qcow2_explicit_readonly_no_host_mutation(self):
        text=(TOOLS / "windows_x64_installed_gpt_ro_audit.py").read_text()
        self.assertIn('g.add_drive_opts(str(path), readonly=1, format="qcow2")', text)
        self.assertIn('g.mount_ro("/dev/sda1", "/")', text)
        self.assertIn('g.mount_ro("/dev/sda3", "/")', text)
        self.assertNotIn("part_set_gpt_type(", text)
        self.assertNotIn("part_disk(", text)
        self.assertNotIn("mount_options(", text)
        self.assertNotIn('g.mount("/dev', text)


if __name__ == "__main__":
    unittest.main()
