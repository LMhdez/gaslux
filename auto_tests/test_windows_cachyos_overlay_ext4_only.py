"""Fifth-partition-only ext4 preflight and negative tests. No guest or disk."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(ROOT))
sp = importlib.util.spec_from_file_location("fifth_ext4", ROOT/"windows_cachyos_overlay_ext4_only.py")
assert sp and sp.loader
lab = importlib.util.module_from_spec(sp)
sp.loader.exec_module(lab)

class Guest:
    def __init__(self, kind="unknown", size=24*1024**3, extra=False,
                 change_windows=False, change_gpt=False):
        self.kind, self.size, self.extra = kind, size, extra
        self.change_windows, self.change_gpt = change_windows, change_gpt
        self.writes = []
        self.synced = False
    def list_devices(self): return ["/dev/sda"]
    def blockdev_getsize64(self, dev):
        return lab.VIRTUAL_BYTES if dev == "/dev/sda" else self.size
    def list_partitions(self):
        return [f"/dev/sda{i}" for i in range(1, 7 if self.extra else 6)]
    def pread_device(self, dev, count, offset):
        assert dev == "/dev/sda" and count == lab.WINDOW_BYTES
        return (b"X" if self.change_gpt and self.synced
                else (b"A" if offset == 0 else b"B")) * count
    def vfs_type(self, dev):
        assert dev == "/dev/sda5"
        return self.kind
    def checksum_device(self, algo, dev):
        assert algo == "sha256" and dev in self.list_partitions()[:4]
        return ("b" if self.synced and self.change_windows else "a") * 64
    def mkfs(self, fs, dev):
        self.writes.append((fs,dev)); self.kind=fs
    def sync(self): self.synced=True
    def vfs_uuid(self, dev): return "10b4c954-43e7-4d49-a92a-d03f850ed72a"

class Ext4SafetyTests(unittest.TestCase):
    front = b"A"*lab.WINDOW_BYTES
    back = b"B"*lab.WINDOW_BYTES
    def test_only_owned_fifth_is_formatted(self):
        g=Guest(); proof=lab.format_only_fifth(g,self.front,self.back)
        self.assertEqual(g.writes,[("ext4","/dev/sda5")])
        self.assertEqual(proof["windowsFourPartitionSha256"],["a"*64]*4)
    def test_foreign_sixth_rejected_without_write(self):
        g=Guest(extra=True)
        with self.assertRaisesRegex(lab.Ext4SafetyError,"extra, missing"):
            lab.format_only_fifth(g,self.front,self.back)
        self.assertEqual(g.writes,[])
    def test_formatted_foreign_root_rejected_without_write(self):
        g=Guest(kind="ext4")
        with self.assertRaisesRegex(lab.Ext4SafetyError,"foreign"):
            lab.format_only_fifth(g,self.front,self.back)
        self.assertEqual(g.writes,[])
    def test_wrong_root_size_rejected_before_write(self):
        g=Guest(size=24*1024**3-4096)
        with self.assertRaisesRegex(lab.Ext4SafetyError,"extent"):
            lab.format_only_fifth(g,self.front,self.back)
        self.assertEqual(g.writes,[])
    def test_windows_changed_rejected_after_write(self):
        g=Guest(change_windows=True)
        with self.assertRaisesRegex(lab.Ext4SafetyError,"Windows partition changed"):
            lab.format_only_fifth(g,self.front,self.back)
        self.assertEqual(g.writes,[("ext4","/dev/sda5")])
    def test_gpt_changed_rejected_after_write(self):
        g=Guest(change_gpt=True)
        with self.assertRaisesRegex(lab.Ext4SafetyError,"GPT changed"):
            lab.format_only_fifth(g,self.front,self.back)
        self.assertEqual(g.writes,[("ext4","/dev/sda5")])
    def test_unconsented_refused_before_file_access(self):
        with patch.dict(os.environ, {"GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT": ""}):
            with patch.object(lab,"validate_workspace",
                              side_effect=AssertionError("disk opened")):
                with self.assertRaisesRegex(lab.Ext4SafetyError,"separate hosted"):
                    lab.format_owned_fifth(Path("/invalid"),Path("/invalid"),
                                           {},{},{},{})
    def test_no_third_boot_refused_before_file_access(self):
        env={"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted",
             "GITHUB_REPOSITORY":"LMhdez/gaslux",
             "GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT":lab.CONSENT,
             "GASLUX_CACHYOS_OVERLAY_GPT_CONSENT":lab.GPT_CONSENT,
             "GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT":lab.BOOT_CONSENT}
        with patch.dict(os.environ,env):
            with patch.object(lab,"validate_workspace",
                              side_effect=AssertionError("disk opened")):
                with self.assertRaisesRegex(lab.Ext4SafetyError,"successful genuine"):
                    lab.format_owned_fifth(Path("/invalid"),Path("/invalid"),
                                           {},{},{},{"windowsBootAfterOverlayMutationVerified":False})
    def test_never_claim_linux_boot_or_rollback(self):
        content=(ROOT/"windows_cachyos_overlay_ext4_only.py").read_text()
        for flag in ("cachyosInstalled","cachyosFirstBootVerified",
                     "windowsRecoveryAfterLinuxVerified","rollbackProven",
                     "sameDiskDualBootVerified","releaseEligible"):
            self.assertIn('"'+flag+'": False',content)
        self.assertNotIn("sgdisk --clear",content)
if __name__ == "__main__": unittest.main()
