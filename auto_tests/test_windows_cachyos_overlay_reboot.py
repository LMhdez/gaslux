"""VM-only Windows reboot on staged fifth GPT: fail-closed synthetic regressions."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'tools'))
import windows_cachyos_overlay_reboot as boot
import windows_x64_tcg_firstboot as windows


class ThirdBootOverlaySafetyTests(unittest.TestCase):
    def setUp(self):
        p = Path('/home/runner/work/_temp/gaslux-win-x64-test')
        self.disk = p/'only-disposable-windows-target.qcow2'
        self.nvram = p/'ovmf-variables.fd'
        checkpoint=p/'windows-uefi-cow-checkpoint'
        self.overlay=checkpoint/'cachyos-unwritten-trial-overlay.qcow2'
        self.trial=checkpoint/'trial-ovmf-variables.fd'
        self.serial=p/'third-overlay-windows-serial.log'
        self.original=[
            'qemu-system-x86_64','-drive',
            'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF_CODE.fd',
            '-drive',f'if=pflash,format=raw,file={self.nvram}',
            '-drive',f'if=none,id=only_windows,format=qcow2,file={self.disk}',
            '-device','ide-hd,drive=only_windows,bus=lab_sata.0',
            '-drive','if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file=/tmp/official.iso',
            '-device','ide-cd,drive=verified_iso,bus=lab_sata.1',
            '-drive','if=floppy,format=raw,file=/tmp/disposable-answer.img',
            '-serial',f'file:{self.disk.parent/"win-guest-serial.log"}',
            '-monitor','unix:/home/runner/work/_temp/gaslux-win-x64-test/hmp.sock,server,nowait',
            '-boot','order=dc',
        ]

    def test_third_boot_qemu_uses_overlay_and_trial_nvram_only(self):
        cmd=boot.third_guest_args(
            self.original,self.disk,self.nvram,self.overlay,self.trial,self.serial)
        packed=' '.join(cmd)
        self.assertIn('file='+str(self.overlay),packed)
        self.assertIn('file='+str(self.trial),packed)
        self.assertNotIn('file='+str(self.disk),packed)
        self.assertNotIn('file='+str(self.nvram),packed)
        self.assertNotIn('verified_iso',packed)
        self.assertNotIn('official.iso',packed)
        self.assertNotIn('if=floppy',packed)
        self.assertNotIn('disposable-answer.img',packed)
        self.assertIn('order=c',packed)
        self.assertIn('file:'+str(self.serial),packed)

    def test_refuse_ambiguous_windows_backing_or_uefi_devices(self):
        extra=['-drive',f'if=pflash,format=raw,file={self.nvram}']
        with self.assertRaisesRegex(boot.OverlayBootError,'ambiguous'):
            boot.third_guest_args(
                self.original+extra,self.disk,self.nvram,self.overlay,
                self.trial,self.serial)

    def test_task_script_provisions_hash_checked_vm_only_startup_audit(self):
        digest='a'*64
        code=boot.first_logon_task(digest)
        self.assertIn("Get-FileHash",code)
        self.assertIn('schtasks.exe /Create',code)
        self.assertIn('ONSTART',code)
        self.assertIn('/RU SYSTEM',code)
        self.assertIn(digest,code)
        self.assertIn('GasluxCIThirdBootAudit',code)
        self.assertNotIn('C:\\Windows\\System32\\config\\SYSTEM',code)
        with self.assertRaises(boot.OverlayBootError):
            boot.first_logon_task('invalid')

    def test_default_first_logon_remains_unchanged(self):
        default=windows.witness_powershell(
            'win10_22h2_en_us_x64','19045')
        self.assertNotIn('Register-ScheduledTask',default)
        armed=windows.witness_powershell(
            'win10_22h2_en_us_x64','19045',overlay_reboot_script_sha256='a'*64)
        self.assertIn('schtasks.exe /Create',armed)
        self.assertIn('GASLUX_WINDOWS_X64_BCD_ENUMERATED=1',armed)

    def test_guest_script_checks_fifth_partition_bcd_and_winre(self):
        script=boot.guest_reboot_script()
        for required in (
            'Get-Partition -DiskNumber 0',
            'PartitionNumber -ne 5',
            '24GB','bcdedit.exe','reagentc.exe',
            'Windows RE status:', 'GASLUX_COW_WIN10_REBOOT_FAIL',
            'schtasks.exe /Delete',
        ):
            self.assertIn(required,script)

    def test_no_guest_started_when_explicit_reboot_consent_absent(self):
        with patch.dict(os.environ,{},clear=True),patch.object(
                boot.subprocess,'Popen',
                side_effect=AssertionError('VM was started without consent')),patch.object(
                boot.subprocess,'run',
                side_effect=AssertionError('QEMU ran without consent')):
            with self.assertRaisesRegex(boot.OverlayBootError,'consent'):
                boot.verify_third_windows_boot(
                    self.original,self.disk,self.nvram,{}, {}, {},timeout=120)

    def test_incorrect_reboot_plan_fails_before_qemu(self):
        env={'GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT':boot.CONSENT,
             'GASLUX_CACHYOS_OVERLAY_GPT_CONSENT':
             'I_ACCEPT_DISPOSABLE_QCOW2_OVERLAY_GPT_ONLY',
             'RUNNER_ENVIRONMENT':'github-hosted','GITHUB_ACTIONS':'true',
             'GITHUB_REPOSITORY':'LMhdez/gaslux'}
        with patch.dict(os.environ,env,clear=True),patch.object(
                boot.subprocess,'run',side_effect=AssertionError('unexpected I/O')):
            with self.assertRaisesRegex(boot.OverlayBootError,'prerequisite'):
                boot.verify_third_windows_boot(
                    self.original,self.disk,self.nvram,{}, {}, {},timeout=120)


if __name__=='__main__':
    unittest.main()
