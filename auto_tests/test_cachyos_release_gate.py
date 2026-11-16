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

    def test_script_requires_explicit_install_arguments(self):
        proc = subprocess.run(['bash', str(STAGE), '--install'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=5, check=False)
        self.assertNotEqual(proc.returncode, 0)


if __name__ == '__main__':
    unittest.main()
