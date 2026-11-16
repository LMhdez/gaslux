"""CachyOS target verifier tests; no disk, EFI or NVRAM mutations."""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'assets/live/cachyos-target-verify.py'
spec = importlib.util.spec_from_file_location('cachyos_target_verify', SOURCE)
assert spec and spec.loader
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
RUN = 'legitimate-run_12345'
USER = 'testuser'
ROOT_UUID = '01234567-89ab-cdef-0123-456789abcdef'
ESP_UUID = 'AB12-CD34'
PACKAGES = [
    'base', 'linux-cachyos', 'linux-firmware', 'cachyos-keyring',
    'cachyos-mirrorlist', 'sudo', 'grub', 'efibootmgr', 'networkmanager',
    'plasma-meta', 'sddm', 'mkinitcpio',
]


class CachyosTargetVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write('.libertix-stage-owner', RUN + '\n')
        self.write('etc/os-release', 'NAME="CachyOS Linux"\nID=cachyos\nBUILD_ID=rolling\n')
        self.write('etc/pacman.conf', '[options]\nSigLevel=Required DatabaseOptional\n[cachyos]\nServer=https://mirror.cachyos.org/repo/$arch/$repo\n')
        self.write('etc/pacman.d/mirrorlist', 'Server = https://mirror.archlinux.org/$repo/os/$arch\n')
        self.write('etc/pacman.d/cachyos-mirrorlist', 'Server = https://mirror.cachyos.org/repo/$arch/$repo\n')
        self.write('etc/passwd', 'root:x:0:0:root:/root:/bin/bash\ntestuser:x:1000:1000::/home/testuser:/bin/bash\n')
        self.write('etc/group', 'wheel:x:998:testuser\n')
        self.write('etc/shadow', 'testuser:$6$salt$' + 'a'*86 + ':12345:0:99999:7:::\n')
        sudoers = self.write('etc/sudoers.d/10-libertix-wheel', '%wheel ALL=(ALL:ALL) ALL\n')
        sudoers.chmod(0o440)
        self.write('boot/vmlinuz-linux-cachyos', 'kernel')
        self.write('boot/initramfs-linux-cachyos.img', 'initramfs')
        self.write('etc/hostname', 'testhost\n')
        self.write('etc/locale.conf', 'LANG=pt_PT.UTF-8\n')
        self.write('etc/fstab', f'UUID={ROOT_UUID} / ext4 defaults 0 1\nUUID={ESP_UUID} /boot/efi vfat umask=0077 0 1\n')
        self.write('boot/grub/grub.cfg', 'menuentry CachyOS {}\nmenuentry "Windows Boot Manager" {}\n')
        self.write('boot/efi/EFI/Libertix/grubx64.efi', b'MZ' + b'0'*62)
        for package in PACKAGES:
            self.write(f'var/lib/pacman/local/{package}-1.0-1/desc', f'%NAME%\n{package}\n%VERSION%\n1.0-1\n')

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return path

    def call(self, **kwargs):
        return verify.verify_target(self.root, RUN, USER, **kwargs)

    def test_packages_phase(self):
        result = self.call()
        self.assertEqual(result['distribution'], 'cachyos')
        self.assertFalse(result['bootable_proved'])
        self.assertFalse(result['windows_recovery_proved'])

    def test_boot_artifacts_phase(self):
        result = self.call(phase='bootable', root_uuid=ROOT_UUID, esp_uuid=ESP_UUID)
        self.assertTrue(result['ok'])
        self.assertFalse(result['bootable_proved'])

    def test_wrong_transaction(self):
        with self.assertRaisesRegex(verify.TargetError, 'not owned'):
            verify.verify_target(self.root, 'other-run-12345', USER)

    def test_live_os_rejected(self):
        self.write('etc/os-release', 'NAME=CachyOS\nID=arch\n')
        with self.assertRaisesRegex(verify.TargetError, 'not an installed'):
            self.call()

    def test_missing_cachyos_pacman_repository(self):
        self.write('etc/pacman.conf', '[options]\n[core]\n')
        with self.assertRaisesRegex(verify.TargetError, 'CachyOS repository'):
            self.call()

    def test_missing_mirrorlist(self):
        (self.root / 'etc/pacman.d/cachyos-mirrorlist').unlink()
        with self.assertRaisesRegex(verify.TargetError, 'missing required file'):
            self.call()

    def test_missing_package(self):
        shutil.rmtree(self.root / 'var/lib/pacman/local/grub-1.0-1')
        with self.assertRaisesRegex(verify.TargetError, 'grub'):
            self.call()

    def test_invalid_esp_uuid(self):
        with self.assertRaisesRegex(verify.TargetError, 'ESP FAT UUID'):
            self.call(phase='bootable', root_uuid=ROOT_UUID, esp_uuid=ROOT_UUID)

    def test_wrong_root_fstab_uuid(self):
        self.write('etc/fstab', 'UUID=whatever / ext4 defaults 0 1\n')
        with self.assertRaisesRegex(verify.TargetError, 'root fstab identity'):
            self.call(phase='bootable', root_uuid=ROOT_UUID, esp_uuid=ESP_UUID)

    def test_duplicate_mount_rejected(self):
        with (self.root / 'etc/fstab').open('a') as f:
            f.write(f'UUID={ROOT_UUID} / ext4 defaults 0 1\n')
        with self.assertRaisesRegex(verify.TargetError, 'duplicate fstab'):
            self.call(phase='bootable', root_uuid=ROOT_UUID, esp_uuid=ESP_UUID)

    def test_user_requires_wheel(self):
        self.write('etc/group', 'wheel:x:998:other\n')
        with self.assertRaisesRegex(verify.TargetError, 'wheel'):
            self.call()

    def test_sudoers_mode(self):
        (self.root / 'etc/sudoers.d/10-libertix-wheel').chmod(0o644)
        with self.assertRaisesRegex(verify.TargetError, '0440'):
            self.call()

    def test_external_symlink_rejected(self):
        path = self.root / 'etc/hostname'
        path.unlink()
        path.symlink_to('/etc/hostname')
        with self.assertRaisesRegex(verify.TargetError, 'unsafe symlink'):
            self.call()

    def test_no_windows_grub_entry(self):
        self.write('boot/grub/grub.cfg', 'menuentry CachyOS {}\n')
        with self.assertRaisesRegex(verify.TargetError, 'Windows'):
            self.call(phase='bootable', root_uuid=ROOT_UUID, esp_uuid=ESP_UUID)

    def test_root_slash_rejected(self):
        with self.assertRaisesRegex(verify.TargetError, 'non-root'):
            verify.verify_target(Path('/'), RUN, USER)

    def test_invalid_efi_loader(self):
        self.write('boot/efi/EFI/Libertix/grubx64.efi', 'NOTEFI')
        with self.assertRaisesRegex(verify.TargetError, 'PE image'):
            self.call(phase='bootable', root_uuid=ROOT_UUID, esp_uuid=ESP_UUID)

    def test_duplicate_os_release(self):
        self.write('etc/os-release', 'NAME="CachyOS Linux"\nID=cachyos\nID=arch\n')
        with self.assertRaisesRegex(verify.TargetError, 'duplicate'):
            self.call()


if __name__ == '__main__':
    unittest.main()
