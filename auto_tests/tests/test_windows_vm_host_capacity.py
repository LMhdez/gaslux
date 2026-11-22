"""No-VM, no-disk-mutation regression tests for Windows lab host admission."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "auto_tests/tools/windows_vm_host_capacity.py"
SPEC = importlib.util.spec_from_file_location("windows_vm_host_capacity", MODULE)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class FakeVfs:
    def __init__(self, free_bytes: int, block_size: int = 4096):
        self.f_frsize = block_size
        self.f_bavail = free_bytes // block_size


class WindowsVmHostCapacityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gaslux-resource-only-")
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)

    def measure(self, available, required=8192, reserve=0):
        return mod.assess_capacity(
            self.workspace, required, reserve,
            statvfs=lambda _: FakeVfs(available),
        )

    def test_historical_808gib_versus_85gib_rejects_before_vm(self):
        report = self.measure(
            mod.HISTORICAL_ACTIONS_AVAILABLE_BYTES,
            mod.HISTORICAL_MINT_AB_REQUIRED_BYTES,
        )
        self.assertEqual(report["resource_status"], "BLOCKED_STORAGE")
        self.assertEqual(report["deficit_bytes"], 776_436_875_264)
        self.assertFalse(report["windows_lab_admitted"])

    def test_exact_capacity_only_is_not_guest_admission(self):
        report = self.measure(8192)
        self.assertEqual(report["resource_status"], "CAPACITY_ONLY_OK")
        self.assertEqual(report["deficit_bytes"], 0)
        for key in (
            "windows_lab_admitted", "windows_guest_boot_verified",
            "snapshot_restore_verified", "windows_recovery_verified",
        ):
            self.assertFalse(report[key], key)

    def test_byte_reserve_is_enforced(self):
        report = self.measure(8192, reserve=4096)
        self.assertEqual(report["resource_status"], "BLOCKED_STORAGE")
        self.assertEqual(report["deficit_bytes"], 4096)

    def test_one_byte_deficit(self):
        report = self.measure(4096, required=4097)
        self.assertEqual(report["deficit_bytes"], 1)
        self.assertEqual(report["resource_status"], "BLOCKED_STORAGE")

    def test_zero_and_negative_requirements_rejected(self):
        for n in (0, -1):
            with self.subTest(required=n), self.assertRaises(ValueError):
                self.measure(8192, required=n)

    def test_bool_and_float_requirements_rejected(self):
        for n in (True, 1.5):
            with self.subTest(required=n), self.assertRaises(ValueError):
                self.measure(8192, required=n)

    def test_negative_reserve_rejected(self):
        with self.assertRaises(ValueError):
            self.measure(8192, reserve=-1)

    def test_overflow_required_plus_reserve_rejected(self):
        with self.assertRaisesRegex(ValueError, "signed 64-bit"):
            self.measure(8192, required=mod.MAX_BYTES, reserve=1)

    def test_invalid_disk_free_block_geometry_is_rejected(self):
        for block_size, blocks in ((0, 1), (-1, 1), (4096, -1),
                                   (4096, mod.MAX_BYTES)):
            with self.subTest(block_size=block_size, blocks=blocks):
                class BadVfs:
                    f_frsize = block_size
                    f_bavail = blocks
                with self.assertRaisesRegex(ValueError, "invalid/overflowed"):
                    mod.assess_capacity(
                        self.workspace, 1000, statvfs=lambda _: BadVfs()
                    )

    def test_nonexistent_workspace_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            mod.assess_capacity(
                self.workspace / "nonexistent", 1000, statvfs=lambda _: FakeVfs(8192)
            )

    def test_symlink_workspace_fails_closed(self):
        alias = self.workspace / "alias"
        alias.symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            mod.assess_capacity(alias, 1000, statvfs=lambda _: FakeVfs(8192))

    def test_symlink_ancestor_fails_closed(self):
        real = self.workspace / "real"
        real.mkdir()
        alias = self.workspace / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            mod.assess_capacity(alias / ".", 1000, statvfs=lambda _: FakeVfs(8192))

    def test_regular_file_not_accepted_as_workspace(self):
        f = self.workspace / "some.bin"
        f.write_bytes(b"not-a-directory")
        with self.assertRaisesRegex(ValueError, "regular directory"):
            mod.assess_capacity(f, 1000, statvfs=lambda _: FakeVfs(8192))

    def test_relative_workspace_rejected(self):
        with self.assertRaisesRegex(ValueError, "absolute"):
            mod.assess_capacity(Path("tmp"), 1000, statvfs=lambda _: FakeVfs(8192))

    def test_does_not_create_or_modify_vm_disk(self):
        disk = self.workspace / "windows.qcow2"
        before = set(self.workspace.iterdir())
        result = self.measure(8192)
        after = set(self.workspace.iterdir())
        self.assertEqual(before, after)
        self.assertFalse(disk.exists())
        self.assertFalse(result["windows_lab_admitted"])


if __name__ == "__main__":
    unittest.main()
