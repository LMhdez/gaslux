#!/usr/bin/env bash
# Installed Pop-only firstboot proof in a disposable Windows 10 QCOW2 child.
# This is not a stable production boot integration or an OS update test.
set -Eeuo pipefail
fail() { printf 'GASLUX_POP_NATIVE_FIRSTBOOT_FAILURE=%s\n' "$*" > /dev/ttyS0; exit 1; }

[[ "$(id -u)" == 0 ]] || fail 'installed proof is not root'
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) fail 'not QEMU' ;; esac
. /etc/os-release
[[ "$ID" == pop && "$VERSION_ID" == 24.04 ]] ||
  fail 'OS is not natively installed Pop 24.04'
[[ -d /var/lib/dpkg && -x /usr/bin/apt-get ]] ||
  fail 'native Pop installed package manager absent'
[[ "$(findmnt -n -o FSTYPE /)" == ext4 ]] ||
  fail 'installed root not ext4'
[[ "$(findmnt -n -o FSTYPE /boot/efi)" == vfat ]] ||
  fail 'installed Pop ESP not mounted FAT'
disk=/dev/disk/by-id/virtio-GASLUX_POP_WIN10_COW
[[ -b "$disk" && -b "$disk-part1" && -b "$disk-part3" &&
   -b "$disk-part5" && -b "$disk-part6" ]] ||
  fail 'installed real-Windows/Pop disk missing or replaced'
[[ "$(blockdev --getsize64 "$disk")" == 137438953472 ]] ||
  fail 'installed disk not exact 128GiB VM child'
[[ "$(lsblk -dn -o SERIAL "$disk" | tr -d '[:space:]')" ==
    GASLUX_POP_WIN10_COW ]] ||
  fail 'installed target virtio identity mismatch'
root="$(readlink -e "$disk-part6")"
mounted="$(readlink -e "$(findmnt -n -o SOURCE /)")"
[[ "$root" == "$mounted" ]] || fail 'kernel is not booted from Pop partition 6'
[[ "$(blkid -s TYPE -o value "$disk-part1")" == vfat ]] ||
  fail 'genuine Windows ESP filesystem missing'
[[ "$(blkid -s TYPE -o value "$disk-part3")" == ntfs ]] ||
  fail 'genuine Windows NTFS filesystem missing'
[[ "$(blkid -s TYPE -o value "$disk-part5")" == vfat ]] ||
  fail 'native Pop ESP FAT missing'
[[ -s /boot/efi/EFI/systemd/systemd-bootx64.efi ]] ||
  fail 'Pop systemd-boot native loader absent'
[[ -s /boot/efi/EFI/BOOT/BOOTX64.EFI ]] ||
  fail 'Pop fallback UEFI binary absent'
[[ ! -e /boot/efi/EFI/Microsoft/Boot/bootmgfw.efi ]] ||
  fail 'unowned Microsoft EFI file unexpectedly in Pop-only ESP'
[[ "$(readlink -e "$disk-part1")" != "$(readlink -e "$disk-part5")" ]] ||
  fail 'Pop and genuine Windows ESPs unexpectedly overlap'
command -v bootctl >/dev/null || fail 'native bootctl missing'
bootctl --no-pager --esp-path=/boot/efi list >/run/gaslux-pop-entries.txt 2>&1 ||
  fail 'installed systemd-boot entry enumeration failed'
[[ -s /run/gaslux-pop-entries.txt ]] ||
  fail 'installed Pop boot menu empty'
[[ ! -e /cdrom/casper/filesystem.squashfs ]] ||
  fail 'live ISO unexpectedly still mounted'
printf 'GASLUX_POP_REALWIN10_NATIVE_FIRSTBOOT_OS_ID=pop\n' > /dev/ttyS0
printf 'GASLUX_POP_REALWIN10_NATIVE_FIRSTBOOT_KERNEL=%s\n' "$(uname -r)" > /dev/ttyS0
printf 'GASLUX_POP_REALWIN10_NATIVE_FIRSTBOOT_ROOT_PARTUUID=%s\n' \
  "$(blkid -s PARTUUID -o value "$root")" > /dev/ttyS0
printf 'GASLUX_POP_REALWIN10_NATIVE_FIRSTBOOT_VERIFIED=1\n' > /dev/ttyS0
sync
systemctl poweroff -i --no-block || fail 'native Pop guest shutdown failed'
