#!/usr/bin/env bash
# Executed ONLY inside a disposable QEMU/OVMF guest booted from the pinned,
# SHA-256-verified CachyOS 260809 live ISO. No pacstrap/partitioning/EFI edits.
set -Eeuo pipefail
fail() {
  printf 'GASLUX_GUEST_PREFLIGHT_FAILURE: %s\n' "$*" >&2
  exit 1
}
[ "$(id -u)" -eq 0 ] || fail 'guest probe needs root'
[ -d /sys/firmware/efi/efivars ] || fail 'firmware is not UEFI'
[ -f /etc/os-release ] || fail 'missing real ISO identity'
# Do not source arbitrary os-release as shell code.
grep -qx 'ID=cachyos' /etc/os-release || fail 'wrong ID'
grep -qx 'ID_LIKE=arch' /etc/os-release || fail 'wrong ID_LIKE'
grep -qx 'IMAGE_ID=cachyos' /etc/os-release || fail 'wrong IMAGE_ID'
grep -qx 'IMAGE_VERSION=2026.08.09' /etc/os-release || fail 'wrong IMAGE_VERSION'
grep -qx 'NAME="CachyOS Linux"' /etc/os-release || fail 'wrong live NAME'
command -v systemd-detect-virt >/dev/null || fail 'no VM detector'
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) fail 'not an authorized virtual guest' ;; esac
for binary in pacstrap arch-chroot pacman pacman-conf findmnt blkid python3 openssl; do
  command -v "$binary" >/dev/null || fail "missing live backend dependency: $binary"
done
grep -Eq '^[[:space:]]*\[cachyos\][[:space:]]*$' /etc/pacman.conf ||
  fail 'CachyOS repository missing from pacman.conf'
[ -s /etc/pacman.d/cachyos-mirrorlist ] || fail 'no CachyOS mirrorlist'
[ -s /etc/pacman.d/mirrorlist ] || fail 'no Arch mirrorlist'
[ -f /usr/share/zoneinfo/Europe/Lisbon ] || fail 'missing timezone database'
python3 - <<'PY' || fail 'Secure Boot is enabled or unverifiable'
from pathlib import Path
root = Path('/sys/firmware/efi/efivars')
guid = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
def read_flag(name):
    path = root / f'{name}-{guid}'
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f'GASLUX_SECUREBOOT_EFIVAR: {name} missing or linked')
    data = path.read_bytes()
    # efivarfs exposes 4 bytes of variable attributes, then 1 byte of value.
    if len(data) != 5:
        raise SystemExit(f'GASLUX_SECUREBOOT_EFIVAR: {name} invalid length')
    return data[4]
secure = read_flag('SecureBoot')
setup = read_flag('SetupMode')
print(f'GASLUX_SECUREBOOT_EFIVAR: SecureBoot={secure} SetupMode={setup}')
if secure != 0:
    raise SystemExit('GASLUX_SECUREBOOT_EFIVAR: active Secure Boot refused')
if setup != 1:
    # This *specific* ephemeral OVMF VM must have no enrolled platform keys.
    # The reusable stage --check still supports genuine disabled Secure Boot
    # even on a machine with keys, but the lab fixture promises no key store.
    raise SystemExit('GASLUX_SECUREBOOT_EFIVAR: unexpected key enrollment in lab')
print('GASLUX_OVMF_SECUREBOOT_DISABLED_VERIFIED=1')
PY
[ -f /run/gaslux-lab/stage.sh ] && [ ! -L /run/gaslux-lab/stage.sh ] ||
  fail 'guarded backend script missing'
[ -f /run/gaslux-lab/stage.sha256 ] ||
  fail 'guarded backend SHA-256 missing'
(cd /run/gaslux-lab && sha256sum -c stage.sha256) ||
  fail 'guarded backend hash mismatch'
bash /run/gaslux-lab/stage.sh --check ||
  fail 'production-isolated guarded backend rejected the real live environment'
printf 'GASLUX_GUEST_READONLY_PREFLIGHT_PASS=1\n'
