#!/usr/bin/env bash
# Runs ONLY from the installed Pop target on the SECOND QEMU boot. This is a
# laboratory proof service, not part of a distributable Gaslux installation.
set -Eeuo pipefail
fail() {
  printf 'GASLUX_POP_NATIVE_FIRSTBOOT_FAILURE=%s\n' "$*" > /dev/ttyS0
  exit 1
}
[[ "$(id -u)" == 0 ]] || fail 'no root privileges'
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) fail 'not isolated QEMU' ;; esac
. /etc/os-release
[[ "${ID:-}" == pop && "${VERSION_ID:-}" == 24.04 ]] ||
  fail 'not installed Pop 24.04'
[[ -d /var/lib/dpkg ]] || fail 'installed dpkg database missing'
[[ -x /usr/bin/apt-get ]] || fail 'installed apt missing'
[[ "$(findmnt -n -o FSTYPE /)" == ext4 ]] || fail 'unexpected root type'
[[ "$(findmnt -n -o FSTYPE /boot/efi)" == vfat ]] ||
  fail 'installed ESP is not mounted'
by_id=/dev/disk/by-id/virtio-GASLUXPOPFULLVM
[[ -b "$by_id" && -b "$by_id-part2" ]] || fail 'VM target disk missing'
root="$(readlink -e "$by_id-part2")"
mounted="$(readlink -e "$(findmnt -n -o SOURCE /)")"
[[ "$root" == "$mounted" ]] || fail 'not booted from the installed root'
[[ "$(blockdev --getsize64 "$by_id")" == 34359738368 ]] ||
  fail 'target disk capacity differs'
[[ "$(lsblk -dn -o SERIAL "$by_id" | tr -d '[:space:]')" == GASLUXPOPFULLVM ]] ||
  fail 'wrong installed disk serial'
disks="$(lsblk -dn -o NAME,TYPE |
  awk '$2=="disk" && $1 !~ /^(zram|ram)[0-9]+$/ {n++} END {print n+0}')"
[[ "$disks" == 1 ]] ||
  fail 'live ISO or extra disk attached on installed first boot'
[[ -s /boot/efi/EFI/systemd/systemd-bootx64.efi ]] ||
  fail 'native systemd-boot missing'
[[ -s /boot/efi/EFI/BOOT/BOOTX64.EFI ]] ||
  fail 'fallback EFI loader missing'
[[ ! -e /run/gaslux-pop-lab/probe.sh && ! -e /cdrom/casper/filesystem.squashfs ]] ||
  fail 'live source still mounted'
printf 'GASLUX_POP_NATIVE_FIRSTBOOT_OS_ID=pop\n' > /dev/ttyS0
printf 'GASLUX_POP_NATIVE_FIRSTBOOT_KERNEL=%s\n' "$(uname -r)" > /dev/ttyS0
printf 'GASLUX_POP_NATIVE_FIRSTBOOT_ROOT_PARTUUID=%s\n' \
  "$(blkid -s PARTUUID -o value "$root")" > /dev/ttyS0
printf 'GASLUX_POP_NATIVE_FIRSTBOOT_VERIFIED=1\n' > /dev/ttyS0
