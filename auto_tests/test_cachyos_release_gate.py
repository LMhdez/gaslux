"""Fail-closed release gates until the full CachyOS boot/rollback matrix passes.

These tests deliberately block accidentally advertising an experimental
backend as a production-ready distribution.
"""
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "assets/live/cachyos-stage-target.sh"


class CachyosReleaseGateTests(unittest.TestCase):
    def test_release_catalog_does_not_advertise_experimental_backend(self):
        config = json.loads((ROOT / 'release-config.json').read_text())
        names = {item['id'] for item in config['distributions']}
        self.assertNotIn('cachyos', names)

    def test_production_installer_does_not_dispatch_to_lab_stage(self):
        for file in (
            'assets/live/libertix-install-main.sh',
            'assets/live/libertix-target-common.sh',
            'assets/live/configure-target-main.sh',
        ):
            with self.subTest(file=file):
                self.assertNotIn('cachyos-stage-target', (ROOT / file).read_text())

    def test_lab_stage_has_no_disk_or_firmware_mutators(self):
        code = STAGE.read_text()
        for prohibited in ('wipefs ', 'mkfs.', 'parted ', 'sfdisk ', 'grub-install ',
                           'efibootmgr -c', 'efibootmgr -o', 'sgdisk ', 'dd if=',
                           'bootctl install', 'sbctl enroll-keys'):
            with self.subTest(command=prohibited):
                # Check executable statements, not comments/documentation.
                commands = '\n'.join(
                    line for line in code.splitlines()
                    if line.strip() and not line.lstrip().startswith('#')
                )
                self.assertNotIn(prohibited, commands)

    def test_install_is_rejected_without_disposable_vm_sentinel(self):
        import os
        env = os.environ.copy()
        env.pop('GASLUX_DISPOSABLE_VM', None)
        command = ['bash', str(STAGE), '--install',
                   'testuser', 'testhost', 'pt_PT.UTF-8',
                   'Europe/Lisbon', '/tmp/no-such-password-secret',
                   'run-id-12345678', '01234567-89ab-cdef-0123-456789abcdef']
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=5, env=env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('disposable VM', result.stderr)

    def test_stage_vm_guard_is_checked_before_host_or_disk(self):
        content = STAGE.read_text()
        start = content.index('install_target() {')
        install = content[start:content.index('\n}', start)]
        self.assertLess(install.index('check_disposable_vm'),
                        install.index('check_host'))
        self.assertLess(install.index('check_disposable_vm'),
                        install.index('check_target'))

    def test_target_provisioning_requires_cryptographic_handoff(self):
        code = STAGE.read_text()
        start = code.index('install_target() {')
        end = code.index('\n}', start)
        install = code[start:end]
        self.assertIn('check_authenticated_handoff "$run_id" "$root_uuid"', install)
        self.assertLess(install.index('check_authenticated_handoff'),
                        install.index('check_target'))
        self.assertLess(install.index('check_authenticated_handoff'),
                        install.index('pacstrap -K'))

    def test_no_legacy_unsigned_install_fallback(self):
        code = STAGE.read_text()
        self.assertIn('cachyos-handoff-auth.py', code)
        self.assertIn('GASLUX_HANDOFF_SIGNATURE', code)
        self.assertIn('GASLUX_HANDOFF_PUBLIC_KEY', code)
        self.assertIn('GASLUX_HANDOFF_ENVELOPE', code)
        self.assertNotIn('|| true\n  check_target', code)

    def test_script_requires_explicit_install_arguments(self):
        proc = subprocess.run(['bash', str(STAGE), '--install'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=5, check=False)
        self.assertNotEqual(proc.returncode, 0)


if __name__ == '__main__':
    unittest.main()
