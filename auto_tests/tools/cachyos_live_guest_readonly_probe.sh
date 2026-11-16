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
p = list(Path('/sys/firmware/efi/efivars').glob(
    'SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'))
if len(p) != 1 or len(p[0].read_bytes()) != 5 or p[0].read_bytes()[4] != 0:
    raise SystemExit(1)
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
