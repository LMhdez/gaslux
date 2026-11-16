#!/usr/bin/env bash
# VM-only unattended update/power-cut experiment; never runs on Windows.
# Executes on a disposable overlay of a previously installed CachyOS disk.
set -Eeuo pipefail
trap 'printf "GASLUX_VM_UPDATE_FAILURE: line=%s\n" "$LINENO" > /dev/ttyS0' ERR
fail() { printf "GASLUX_VM_UPDATE_FAILURE: %s\n" "$*" > /dev/ttyS0; exit 1; }
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) exit 0 ;; esac
command -v modprobe >/dev/null && modprobe qemu_fw_cfg 2>/dev/null || true
request=/sys/firmware/qemu_fw_cfg/by_name/opt/gaslux/ci-mode/raw
# Without the special QEMU firmware request, this experimental service is
# a read-only no-op; in particular the initially proved baseline stays intact.
[[ -f "$request" && ! -L "$request" ]] || exit 0
mode="$(tr -d '\000' < "$request")"
[[ "$mode" == GASLUX_CI_UPDATE || "$mode" == GASLUX_CI_POWERCUT ]] ||
  fail 'unexpected QEMU update phase'
[[ "$(id -u)" == 0 ]] || fail 'must execute as installed guest root'
[[ -d /sys/firmware/efi/efivars ]] || fail 'UEFI absent'
grep -qx ID=cachyos /etc/os-release || fail 'CachyOS identity missing'
grep -qx ID_LIKE=arch /etc/os-release || fail 'Arch lineage missing'
[[ -f /.libertix-stage-owner && ! -L /.libertix-stage-owner ]] ||
  fail 'transaction ownership file missing'
[[ "$(cat /.libertix-stage-owner)" == lab-real-iso-signed-20261116 ]] ||
  fail 'wrong installed transaction'
[[ "$(findmnt -rn -M / -o FSTYPE)" == ext4 ]] || fail 'wrong root filesystem'
root="$(findmnt -rn -M / -o SOURCE)"
[[ "$(blkid -s UUID -o value "$root")" == 01234567-89ab-cdef-0123-456789abcdef ]] ||
  fail 'wrong installed root UUID'
[[ "$(findmnt -rn -M /boot/efi -o FSTYPE)" == vfat ]] || fail 'ESP absent'
[[ -s /boot/efi/EFI/BOOT/BOOTX64.EFI ]] || fail 'GRUB EFI loader absent'
pacman -Q linux-cachyos-lts grub base cachyos-hooks >/dev/null ||
  fail 'native installed packages missing'
mkdir -p /var/lib/gaslux-ci
if [[ "$mode" == GASLUX_CI_POWERCUT ]]; then
  [[ ! -e /var/lib/gaslux-ci/update-complete ]] ||
    fail 'refusing to power-cut an already updated image'
  printf 'interrupted-before-package-changes\n' > /var/lib/gaslux-ci/powercut-armed
  sync
  printf 'GASLUX_VM_UPDATE_POWERCUT_ARMED=1\n' > /dev/ttyS0
  # The QEMU host forcibly cuts power with SIGKILL; no graceful shutdown.
  sleep 1200
  fail 'host did not deliver expected disposable VM power loss'
fi
if [[ -f /var/lib/gaslux-ci/update-complete ]]; then
  [[ "$(cat /var/lib/gaslux-ci/update-complete)" == lab-real-iso-signed-20261116 ]] ||
    fail 'postupdate owner marker differs'
  [[ -s /boot/vmlinuz-linux-cachyos-lts &&
     -s /boot/initramfs-linux-cachyos-lts.img ]] ||
    fail 'updated kernel/initramfs missing'
  grub-script-check /boot/grub/grub.cfg || fail 'installed GRUB config invalid'
  [[ "$(uname -r)" == *cachyos* ]] || fail 'updated boot not running CachyOS kernel'
  pacman -Q linux-cachyos-lts grub base cachyos-hooks >/dev/null ||
    fail 'updated pacman DB invalid'
  printf 'GASLUX_VM_UPDATED_REBOOT_VERIFIED=1\n' > /dev/ttyS0
  exit 0
fi
# Validate effective installed package signing policy before any network update.
command -v pacman-conf >/dev/null || fail 'pacman-conf missing'
mapfile -t repos < <(pacman-conf --repo-list)
(( ${#repos[@]} >= 3 )) || fail 'too few enabled repositories'
for repo in "${repos[@]}"; do
  [[ "$repo" =~ ^[a-zA-Z0-9_-]+$ ]] || fail 'unsafe repository name'
  level="$(pacman-conf --repo "$repo" SigLevel)" ||
    fail "cannot inspect signature policy in $repo"
  [[ "$level" == *Required* ]] || fail "package signatures not mandatory in $repo"
  [[ "$level" != *Never* && "$level" != *TrustAll* &&
     "$level" != *PackageOptional* ]] ||
    fail "weak signing policy in $repo"
  # DatabaseOptional is allowed by pacman; package files still require trust.
  [[ "$level" != *" Optional"* || "$level" == *DatabaseOptional* ]] ||
    fail "unsigned package policy in $repo"
done
printf 'GASLUX_VM_UPDATE_TRUST_POLICY_VERIFIED=1\n' > /dev/ttyS0
[[ -L /etc/resolv.conf || -s /etc/resolv.conf ]] || fail 'no DNS resolver'
# Official package repositories and normal pacman signature checks.
# -Syu refreshes+upgrades all; explicit kernel+GRUB arguments force the
# critical package hooks even when pacstrap installed the latest versions.
pacman -Syu --noconfirm linux-cachyos-lts grub ||
  fail 'full signed pacman upgrade/kernel+GRUB transaction failed'
mkinitcpio -P || fail 'native initramfs regeneration failed'
grub-install --target=x86_64-efi --efi-directory=/boot/efi \
  --bootloader-id=GasluxLab --no-nvram --removable --recheck ||
  fail 'postupdate GRUB EFI installation failed'
grub-mkconfig -o /boot/grub/grub.cfg || fail 'GRUB configuration generation failed'
grub-script-check /boot/grub/grub.cfg || fail 'GRUB syntax invalid after update'
[[ -s /boot/vmlinuz-linux-cachyos-lts &&
   -s /boot/initramfs-linux-cachyos-lts.img &&
   -s /boot/efi/EFI/BOOT/BOOTX64.EFI ]] ||
  fail 'updated kernel/initramfs/EFI files missing'
pacman -Q linux-cachyos-lts grub base cachyos-hooks >/dev/null ||
  fail 'updated package database invalid'
printf '%s\n' lab-real-iso-signed-20261116 > /var/lib/gaslux-ci/update-complete
sync
printf 'GASLUX_VM_UPDATE_APPLIED=1\n' > /dev/ttyS0
systemctl --no-block reboot || fail 'guest reboot failed'
