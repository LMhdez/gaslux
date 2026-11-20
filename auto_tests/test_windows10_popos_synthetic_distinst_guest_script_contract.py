#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


SCRIPT = Path(__file__).parent / "tools" / "windows10_popos_synthetic_distinst_guest.sh"


class SyntheticDistinstGuestScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")
        start_marker = "python3 -B - \"$MODE\" <<'PY'\n"
        start = cls.source.index(start_marker) + len(start_marker)
        end = cls.source.rfind("\nPY\n")
        if end <= start:
            raise AssertionError("embedded guest Python heredoc boundary missing")
        cls.python_source = cls.source[start:end]

    def test_embedded_guest_python_compiles(self):
        compile(self.python_source, str(SCRIPT) + ":embedded-python", "exec")

    def test_only_explicit_synthetic_partition_test_is_executable(self):
        self.assertIn('MODE = sys.argv[1]', self.python_source)
        self.assertIn('os.environ.get("GASLUX_POP_DISTINST_SYNTHETIC_CONSENT") == CONSENT',
                      self.python_source)
        self.assertIn('"--no-efi-vars", "--test"', self.python_source)
        self.assertIn('"--block", device', self.python_source)
        self.assertIn('f"{device}:1:reuse:mount=/boot/efi"',
                      self.python_source)
        self.assertIn('f"{device}:2:reuse:mount=/"', self.python_source)
        for forbidden in ('"--modify-boot"', '"--new-table"', '"--new"',
                          '"--delete"', '"--move"'):
            self.assertNotIn(forbidden, self.python_source)

    def test_reuse_variant_requires_preformat_and_byte_identical_gpt(self):
        self.assertIn('formatter_commands = [', self.python_source)
        self.assertIn('["mkfs.fat", "-F", "32", "-n", "POPSYN", device + "1"]',
                      self.python_source)
        self.assertIn('["mkfs.ext4", "-F", "-q", device + "2"]',
                      self.python_source)
        self.assertIn('gpt_bytes_before_formats == gpt_bytes_after_formats',
                      self.python_source)
        self.assertIn('preformat_proof = {', self.python_source)
        self.assertNotIn('fat32:mount=/boot/efi', self.python_source)

    def test_target_identity_and_tracefs_fail_closed_before_writer(self):
        self.assertLess(self.python_source.index("def preflight()"),
                        self.python_source.index("def run_distinst()"))
        self.assertIn('EXPECTED_DEVICE = "/dev/vdc"', self.python_source)
        self.assertIn('EXPECTED_SERIAL = "GASLUX_POP_DIST"', self.python_source)
        self.assertIn('EXPECTED_DISK_GUID = "7d6e5c4b-3a29-4876-9abc-def012345678"',
                      self.python_source)
        self.assertIn('"block/block_bio_queue"', self.python_source)
        self.assertIn('"block/block_bio_complete"', self.python_source)
        self.assertIn('event["ioError"] = int(status.group(1))', self.python_source)
        self.assertIn('"block/block_rq_issue"', self.python_source)
        self.assertIn('"sched/sched_process_exec"', self.python_source)
        self.assertIn('need(not other_writes,', self.python_source)

    def test_mount_and_unmount_syscalls_are_observed_when_tracepoints_exist(self):
        self.assertIn('"syscalls/sys_enter_mount"', self.python_source)
        self.assertIn('"syscalls/sys_exit_mount"', self.python_source)
        self.assertIn('"syscalls/sys_enter_umount2"', self.python_source)
        self.assertIn('"syscalls/sys_exit_umount2"', self.python_source)
        self.assertIn('mountTraceEventsAvailable', self.python_source)
        self.assertIn('mountObservations', self.python_source)
        self.assertIn('"targetArgumentsResolved": False', self.python_source)
        self.assertIn('"distinstPhase": "partition-reuse-test"', self.python_source)
        self.assertIn('mount tracepoint availability changed after preflight',
                      self.python_source)

    def test_no_windows_or_host_device_path_is_embedded(self):
        for forbidden in ("/dev/sda", "/dev/nvme0n1", "/mnt/c/", "C:\\\\"):
            self.assertNotIn(forbidden, self.source)


if __name__ == "__main__":
    unittest.main()
