#!/usr/bin/env python3
"""Read-only CachyOS target verifier, separate from Debian/Ubuntu verification.

This checks disk contents, NOT a complete Windows dual-boot installation. It
cannot prove correct NVRAM, Windows recoverability or post-reboot health.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

UUID_RE = re.compile(r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\Z")
ESP_UUID_RE = re.compile(r"[a-fA-F0-9]{4}-[a-fA-F0-9]{4}\Z")


class TargetError(Exception):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TargetError(message)


def _safe_file(root: Path, path: str) -> Path:
    destination = root / path
    _require(destination.resolve().is_relative_to(root), f"unsafe symlink: {path}")
    _require(destination.is_file(), f"missing required file: {path}")
    return destination


def _load_os_release(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in content.splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Z_]+)=(?:"([^"\n]*)"|\'([^\'\n]*)\'|([^\s]*))', line)
        _require(match is not None, 'invalid os-release entry')
        assert match is not None
        key = match.group(1)
        _require(key not in values, f'duplicate os-release key: {key}')
        values[key] = next(value for value in match.groups()[1:] if value is not None)
    return values


def _packages(root: Path) -> set[str]:
    directory = root / 'var/lib/pacman/local'
    _require(directory.is_dir() and not directory.is_symlink(), 'missing local pacman package database')
    _require(directory.resolve().is_relative_to(root), 'pacman database escapes root')
    packages: set[str] = set()
    for entry in directory.iterdir():
        if not entry.is_dir() or entry.is_symlink() or not entry.resolve().is_relative_to(root):
            continue
        desc = entry / 'desc'
        if not desc.is_file() or desc.is_symlink():
            continue
        lines = desc.read_text(encoding='utf-8').splitlines()
        for index, line in enumerate(lines[:-1]):
            if line == '%NAME%' and re.fullmatch(r'[a-z0-9][a-z0-9@._+\-]*', lines[index + 1]):
                packages.add(lines[index + 1])
    return packages


def _mount_entries(root: Path) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    content = _safe_file(root, 'etc/fstab').read_text(encoding='utf-8')
    for line in content.splitlines():
        line = line.partition('#')[0].strip()
        if not line:
            continue
        cols = line.split()
        _require(len(cols) == 6, 'malformed fstab')
        path = cols[1]
        _require(path not in result, f'duplicate fstab mount: {path}')
        result[path] = (cols[0], cols[2])
    return result


def _check_user(root: Path, username: str) -> None:
    _require(bool(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', username)) and username != 'root', 'invalid username')
    passwd = _safe_file(root, 'etc/passwd').read_text(encoding='utf-8').splitlines()
    accounts = [line.split(':') for line in passwd if line.startswith(username + ':')]
    _require(len(accounts) == 1 and len(accounts[0]) >= 7, 'desktop user not found')
    account = accounts[0]
    _require(account[2] != '0' and account[5] == '/home/' + username, 'invalid user identity/home')
    group = _safe_file(root, 'etc/group').read_text(encoding='utf-8').splitlines()
    wheel = [line.split(':') for line in group if line.startswith('wheel:')]
    _require(len(wheel) == 1 and len(wheel[0]) == 4 and username in wheel[0][3].split(','), 'user not in wheel group')
    shadow = _safe_file(root, 'etc/shadow').read_text(encoding='utf-8').splitlines()
    users = [line.split(':') for line in shadow if line.startswith(username + ':')]
    _require(len(users) == 1 and len(users[0]) > 1 and users[0][1].startswith('$6$'), 'invalid user password hash')
    sudoers = _safe_file(root, 'etc/sudoers.d/10-libertix-wheel')
    _require(sudoers.read_text(encoding='utf-8').strip() == '%wheel ALL=(ALL:ALL) ALL', 'unexpected sudo rule')
    _require(sudoers.stat().st_mode & 0o777 == 0o440, 'sudoers file mode must be 0440')


def verify_target(root: Path, run_id: str, username: str, *, phase: str = 'packages', root_uuid: str | None = None, esp_uuid: str | None = None, windows_loader_sha256: str | None = None) -> dict[str, object]:
    _require(root.is_absolute() and root != Path('/'), 'must inspect an explicit non-root absolute path')
    _require(root.is_dir() and not root.is_symlink(), 'target root missing/symlink')
    root = root.resolve()
    _require(bool(re.fullmatch(r'[A-Za-z0-9_-]{12,100}', run_id)), 'invalid transaction identity')
    _require(phase in ('packages', 'bootable'), 'invalid verification phase')
    marker = _safe_file(root, '.libertix-stage-owner')
    _require(marker.read_text(encoding='utf-8').strip() == run_id, 'target is not owned by this transaction')
    os_id = _load_os_release(_safe_file(root, 'etc/os-release').read_text(encoding='utf-8'))
    _require(os_id.get('ID') == 'cachyos' and os_id.get('NAME', '').startswith('CachyOS'), 'not an installed CachyOS target')
    pacman_config = _safe_file(root, "etc/pacman.conf").read_text(encoding="utf-8")
    _require(re.search(r"^\s*\[cachyos\]\s*$", pacman_config, re.MULTILINE) is not None,
             "installed pacman configuration lacks CachyOS repository")
    for mirror in ("mirrorlist", "cachyos-mirrorlist"):
        _require(_safe_file(root, "etc/pacman.d/" + mirror).stat().st_size > 0,
                 "empty repository mirrorlist: " + mirror)
    pkgs = _packages(root)
    required = {'base', 'linux-cachyos', 'linux-firmware', 'cachyos-keyring', 'cachyos-mirrorlist', 'sudo', 'grub', 'efibootmgr', 'networkmanager', 'plasma-meta', 'sddm', 'mkinitcpio'}
    missing = sorted(required - pkgs)
    _require(not missing, f'missing pacman packages: {", ".join(missing)}')
    _check_user(root, username)
    for rel in ('boot/vmlinuz-linux-cachyos', 'boot/initramfs-linux-cachyos.img', 'etc/locale.conf', 'etc/hostname'):
        _require(_safe_file(root, rel).stat().st_size > 0, f'empty file: {rel}')
    result = {'ok': True, 'phase': phase, 'distribution': 'cachyos', 'installed_packages_checked': len(required), 'bootable_proved': False, 'windows_recovery_proved': False}
    if phase == 'bootable':
        _require(bool(root_uuid and UUID_RE.fullmatch(root_uuid)), 'root UUID required for bootability')
        _require(bool(esp_uuid and ESP_UUID_RE.fullmatch(esp_uuid)), 'ESP FAT UUID required for bootability')
        mounts = _mount_entries(root)
        _require(mounts.get('/') == ('UUID=' + root_uuid, 'ext4'), 'root fstab identity mismatch')
        _require(mounts.get('/boot/efi') == ('UUID=' + esp_uuid, 'vfat'), 'ESP fstab identity mismatch')
        _require(bool(windows_loader_sha256 and re.fullmatch(r'[0-9a-f]{64}', windows_loader_sha256)),
                 'expected Windows Boot Manager SHA-256 required')
        grub = _safe_file(root, 'boot/grub/grub.cfg').read_text(encoding='utf-8')
        _require('Windows Boot Manager' in grub and '--id gaslux-windows' in grub,
                 'GRUB menu does not include the transaction-owned Windows entry')
        _require('vmlinuz-linux-cachyos' in grub,
                 'GRUB menu does not include the CachyOS kernel')
        efi_root = 'boot/efi/EFI/Gaslux-CachyOS/'
        efi_owner = _safe_file(root, efi_root + '.gaslux-owner')
        _require(efi_owner.read_text(encoding='utf-8').strip() == run_id,
                 'EFI loader transaction ownership mismatch')
        efi = _safe_file(root, efi_root + 'grubx64.efi')
        with efi.open('rb') as stream:
            _require(stream.read(2) == b'MZ', 'installed UEFI loader is not a PE image')
        # Protect the existing Windows boot binary against silent replacement.
        import hashlib
        windows_loader = _safe_file(root, 'boot/efi/EFI/Microsoft/Boot/bootmgfw.efi')
        _require(hashlib.sha256(windows_loader.read_bytes()).hexdigest() == windows_loader_sha256,
                 'Windows Boot Manager hash mismatch')
        # These checks do NOT prove firmware NVRAM, signatures or reboot health.
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--username', required=True)
    parser.add_argument('--phase', choices=('packages', 'bootable'), default='packages')
    parser.add_argument('--root-uuid')
    parser.add_argument('--esp-uuid')
    parser.add_argument('--windows-loader-sha256')
    args = parser.parse_args(argv)
    try:
        result = verify_target(args.root, args.run_id, args.username, phase=args.phase, root_uuid=args.root_uuid, esp_uuid=args.esp_uuid, windows_loader_sha256=args.windows_loader_sha256)
    except (TargetError, OSError, UnicodeError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
