"""Issue #3: safe unit tests for protected Windows files in live Archiso.

No guest launch, mounts, block devices or Windows writes in this test module.
"""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "tools"))
import cachyos_windows_archiso_protected_files_guest as protected
from test_cachyos_windows_shared_archiso_guest_probe import evidence
from cachyos_windows_shared_archiso_handoff import SharedDiskHandoffRejected


class WindowsProtectedFilesReadOnlyTests(unittest.TestCase):
    def test_four_protected_files_bound_to_exact_signed_partitions(self):
        plan, observed = evidence()
        sources = protected.select_sources(plan, observed)
        self.assertEqual([(row[0], row[1]) for row in sources],
                         [("/dev/vdb1", "vfat"), ("/dev/vdb1", "vfat"),
                          ("/dev/vdb3", "ntfs3"), ("/dev/vdb4", "ntfs3")])
        self.assertEqual({row[3] for row in sources},
                         set(plan["windowsHashes"]))

    def test_foreign_mounts_or_guid_mismatch_rejected_before_any_mount(self):
        for index in (0, 2, 3):
            plan, observed = evidence()
            observed["blockdevices"][0]["children"][index]["partuuid"] = (
                "11111111-1111-4111-8111-111111111111")
            with self.subTest(partition=index), self.assertRaises(
                    SharedDiskHandoffRejected):
                protected.select_sources(plan, observed)
        plan, observed = evidence()
        observed["blockdevices"][0]["children"][3]["mountpoints"] = ["/mnt/recovery"]
        with self.assertRaises(SharedDiskHandoffRejected):
            protected.select_sources(plan, observed)

    def test_symlink_and_directory_refused_by_hash_reader(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "Windows" / "System32"
            target.mkdir(parents=True)
            (target / "winload.efi").write_bytes(b"real-file")
            self.assertEqual(len(protected.hash_regular_no_symlinks(
                root, "Windows/System32/winload.efi")), 64)
            (target / "winload.efi").unlink()
            (target / "winload.efi").symlink_to("/etc/hosts")
            with self.assertRaises(SharedDiskHandoffRejected):
                protected.hash_regular_no_symlinks(
                    root, "Windows/System32/winload.efi")
            with self.assertRaises(SharedDiskHandoffRejected):
                protected.hash_regular_no_symlinks(root, "../etc/passwd")

    def _exercise(self, *, tamper_hash=False, bad_source=False, bad_options=False):
        plan, observed = evidence()
        record = []
        selected = [None]
        known = {entry[2]:plan["windowsHashes"][entry[3]]
                 for entry in protected.select_sources(plan, observed)}
        def fake_run(argv, timeout):
            record.append(argv)
            if argv[0] == "mount":
                selected[0] = argv[-2]
                self.assertEqual(argv[1:5],
                                 ["-t", argv[2], "-o", "ro,nosuid,nodev,noexec"])
                self.assertTrue(selected[0].startswith("/dev/vdb"))
            if argv[0] == "findmnt":
                if argv[-1] == "SOURCE":
                    return "/dev/vdc3" if bad_source else selected[0]
                if argv[-1] == "OPTIONS":
                    return "rw,nosuid,nodev,noexec" if bad_options else (
                        "ro,nosuid,nodev,noexec,relatime")
            return ""
        def fake_hash(_folder, relative):
            return "f" * 64 if tamper_hash else known[relative]
        with tempfile.TemporaryDirectory() as td:
            if tamper_hash or bad_source or bad_options:
                with self.assertRaises(SharedDiskHandoffRejected):
                    protected.audit_protected_windows(
                        plan, observed, execute=fake_run, hash_file=fake_hash,
                        runtime_dir=Path(td))
            else:
                status = protected.audit_protected_windows(
                    plan, observed, execute=fake_run, hash_file=fake_hash,
                    runtime_dir=Path(td))
                self.assertIs(status["realWindowsEspBcdLoaderWinreGuestHashesVerified"],
                              True)
                for k in ("storageWritesAuthorized", "pacstrapAuthorized",
                          "releaseEligible", "sameDiskDualBootVerified"):
                    self.assertIs(status[k], False)
        return record

    def test_all_four_windows_checks_use_ro_mount_and_unmount(self):
        operations = self._exercise()
        self.assertEqual(sum(x[0] == "mount" for x in operations), 4)
        self.assertEqual(sum(x[0] == "umount" for x in operations), 4)
        self.assertNotIn("pacstrap", " ".join(" ".join(x) for x in operations))

    def test_tampered_windows_hash_fails_closed_and_unmounts(self):
        ops = self._exercise(tamper_hash=True)
        self.assertEqual([op[0] for op in ops].count("umount"), 1)

    def test_rw_mount_options_or_foreign_source_fail_closed(self):
        for k in ("bad_source", "bad_options"):
            with self.subTest(tamper=k):
                ops = self._exercise(**{k: True})
                self.assertEqual([op[0] for op in ops].count("umount"), 1)


if __name__ == "__main__":
    unittest.main()
