"""Negative fourth-boot safety gates: no host I/O or guests."""
from __future__ import annotations
import importlib.util,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent/"tools"
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location("post_ext4",ROOT/"windows_cachyos_postext4_windows.py")
assert spec and spec.loader
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
class FourthBootContracts(unittest.TestCase):
    def args(self):return ([],Path("/invalid"),Path("/invalid"),{},{},{},{},{})
    def test_no_separate_consent_denied_before_file_or_guest(self):
        with patch.dict(os.environ,{},clear=True):
            with patch.object(lab,"validate_workspace",side_effect=AssertionError("disk")):
                with self.assertRaisesRegex(lab.FourthBootError,"dedicated"):
                    lab.verify_windows_post_ext4(*self.args())
    def test_missing_genuine_ext4_and_thirdboot_denied_without_file_io(self):
        env={"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted",
             "GITHUB_REPOSITORY":"LMhdez/gaslux",
             "GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT":lab.CONSENT,
             "GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT":lab.THIRD_BOOT_CONSENT,
             "GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT":lab.EXT4_CONSENT}
        with patch.dict(os.environ,env):
            with patch.object(lab,"validate_workspace",side_effect=AssertionError("disk")):
                with self.assertRaisesRegex(lab.FourthBootError,"genuine Windows"):
                    lab.verify_windows_post_ext4(*self.args())
    def test_invalid_timeout_denied_without_file_io(self):
        env={"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted",
             "GITHUB_REPOSITORY":"LMhdez/gaslux",
             "GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT":lab.CONSENT,
             "GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT":lab.THIRD_BOOT_CONSENT,
             "GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT":lab.EXT4_CONSENT}
        with patch.dict(os.environ,env):
            for bad in (0,-1,1801,120.0):
                with self.subTest(bad=bad),self.assertRaisesRegex(
                    lab.FourthBootError,"dedicated"
                ):lab.verify_windows_post_ext4(*self.args(),timeout=bad)
    def test_no_linux_or_rollback_claims(self):
        s=(ROOT/"windows_cachyos_postext4_windows.py").read_text()
        for flag in ("cachyosInstalled","cachyosFirstBootVerified",
                     "windowsRecoveryAfterLinuxVerified","rollbackProven",
                     "sameDiskDualBootVerified","storageWritesAuthorized",
                     "releaseEligible"):
            self.assertIn('"'+flag+'":False',s)
        self.assertNotIn("sgdisk --clear",s)
        self.assertNotIn("pacstrap -K",s)
if __name__=="__main__":unittest.main()
