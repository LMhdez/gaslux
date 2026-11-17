#!/usr/bin/env bash
# LAB-ONLY safe replacements for Q4OS process hooks 2,3,5. These phases run
# ONLY inside the installed, single-disk, no-network disposable QEMU guest.
# NEVER execute the upstream debian_adjust*.sh from Calamares: those infer a
# target from /proc mounts and can modify foreign EFI files or purge packages.
set -Eeuo pipefail

refuse() {
  printf 'GASLUX_Q4OS_OWNED_HOOK_REFUSED=%s\n' "$*" > /dev/ttyS0 2>/dev/null || true
  printf 'GASLUX_Q4OS_OWNED_HOOK_REFUSED: %s\n' "$*" >&2
  exit 1
}
[[ $# -eq 1 ]] || refuse 'phase-argument-required'
phase="$1"
case "$phase" in hook2|hook3|hook5|verify) ;; *) refuse 'unknown-phase' ;; esac
[[ "$EUID" -eq 0 && -d /sys/firmware/efi && -c /dev/ttyS0 ]] ||
  refuse 'requires-UEFI-root-and-guest-serial'
grep -Eiq 'QEMU|Bochs|Standard PC \(Q35' \
  /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor ||
  refuse 'not-disposable-QEMU-guest'
[[ "$(cat /etc/q4os_version)" == '6.10-deb13u1' ]] ||
  refuse 'Q4OS-installed-root-not-verified'
[[ -r /etc/gaslux-q4os-lab-transaction.id && -r /etc/gaslux-q4os-lab-root.uuid && -r /etc/gaslux-q4os-lab-esp.uuid && -r /etc/gaslux-q4os-lab-iso.sha256 ]] ||
  refuse 'missing-durable-lab-transaction'
transaction="$(cat /etc/gaslux-q4os-lab-transaction.id)"
[[ "$transaction" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$ ]] ||
  refuse 'invalid-transaction-identity'
[[ "$(cat /etc/gaslux-q4os-lab-iso.sha256)" == '1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d' ]] ||
  refuse 'not-pinned-Q4OS-ISO'
[[ "$(lsblk -dn -o NAME,TYPE | awk '$2 == "disk" { print $1 }')" == vda ]] ||
  refuse 'unexpected-additional-guest-disk'
root_device="$(findmnt -nro SOURCE /)"
esp_device="$(findmnt -nro SOURCE /boot/efi)"
[[ "$root_device" == /dev/vda2 && "$esp_device" == /dev/vda1 ]] ||
  refuse 'target-mount-does-not-belong-to-guest'
[[ "$(lsblk -nro PARTLABEL "$root_device")" == GASLUX-Q4OS-ROOT && "$(lsblk -nro PARTLABEL "$esp_device")" == GASLUX-Q4OS-ESP ]] ||
  refuse 'target-partition-label-not-owned'
[[ "$(findmnt -nro FSTYPE /)" == ext4 && "$(findmnt -nro FSTYPE /boot/efi)" == vfat ]] ||
  refuse 'wrong-filesystem-or-ESP-mount'
[[ "$(blkid -s UUID -o value "$root_device")" == "$(cat /etc/gaslux-q4os-lab-root.uuid)" ]] ||
  refuse 'root-uuid-changed'
[[ "$(blkid -s UUID -o value "$esp_device")" == "$(cat /etc/gaslux-q4os-lab-esp.uuid)" ]] ||
  refuse 'ESP-uuid-changed'
[[ ! -e /boot/efi/EFI/Microsoft && ! -L /boot/efi/EFI/Microsoft && ! -e /boot/efi/EFI/BOOT/bootmgfw.efi && ! -L /boot/efi/EFI/BOOT/bootmgfw.efi ]] ||
  refuse 'Windows-ESP-resource-present'
[[ ! -L /boot/efi/EFI && ! -L /boot/efi/EFI/BOOT ]] ||
  refuse 'symlink-into-unowned-ESP'
state='/var/lib/gaslux-q4os-owned-hooks'
[[ ! -L /var/lib/gaslux-q4os-owned-hooks ]] ||
  refuse 'transaction-state-symlink'
if [[ -e "$state/transaction.id" ]]; then
  [[ -f "$state/transaction.id" && ! -L "$state/transaction.id" && "$(cat "$state/transaction.id")" == "$transaction" ]] ||
    refuse 'transaction-state-owned-by-other-install'
else
  [[ "$phase" == hook2 && ! -e "$state" ]] ||
    refuse 'missing-prior-transaction-state'
fi

# Every phase is deliberately an explicit, bounded substitute; no CHROOT
# discovery, no raw native hook execution and no forced dpkg essential purge.
case "$phase" in
  hook2)
    [[ ! -e "$state" ]] || refuse 'hook2-already-started'
    [[ ! -e /home/gasluxlab ]] || refuse 'test-account-home-collision'
    if id gasluxlab >/dev/null 2>&1; then refuse 'test-account-collision'; fi
    for group in sudo audio video plugdev; do
      getent group "$group" >/dev/null || refuse "missing-target-group-$group"
    done
    # This is a *locked lab account*, never a deployable password/account flow.
    useradd -m -s /bin/bash -G sudo,audio,video,plugdev gasluxlab ||
      refuse 'locked-lab-account-creation-failed'
    passwd --lock gasluxlab >/dev/null || refuse 'locked-lab-account-failed'
    install -d -m 0700 "$state"
    printf '%s\n' "$transaction" > "$state/transaction.id"
    printf 'account=gasluxlab,locked=yes,root=UUID:%s\n' \
      "$(cat /etc/gaslux-q4os-lab-root.uuid)" > "$state/hook2"
    printf 'GASLUX_Q4OS_OWNED_HOOK2=%s\n' "$transaction" > /dev/ttyS0
    ;;
  hook3)
    [[ -s "$state/hook2" && ! -e "$state/hook3" ]] ||
      refuse 'hook3-out-of-order-or-replayed'
    [[ -s /boot/grub/grub.cfg && -s /boot/efi/EFI/GasluxQ4OSLab/grubx64.efi ]] ||
      refuse 'missing-package-owned-native-GRUB-before-hook3'
    [[ ! -e /boot/efi/EFI/debian ]] ||
      refuse 'upstream-legacy-EFI-directory-not-owned'
    # Upstream profile installer and apt purges remain BLOCKED because their
    # dependency/effect set is not yet proven safe. Do not pretend they ran.
    printf 'aptCleanup=blocked;profileInstaller=blocked;legacyEFI=blocked\n' > "$state/hook3"
    printf 'GASLUX_Q4OS_OWNED_HOOK3=%s\n' "$transaction" > /dev/ttyS0
    ;;
  hook5)
    [[ -s "$state/hook3" && ! -e "$state/hook5" ]] ||
      refuse 'hook5-out-of-order-or-replayed'
    [[ -s /var/lib/gaslux-q4os-native-grub.sha256 ]] ||
      refuse 'missing-native-GRUB-ownership-proof'
    existing="$(sha256sum /boot/efi/EFI/BOOT/BOOTX64.EFI | cut -d' ' -f1)"
    [[ "$existing" == "$(cat /var/lib/gaslux-q4os-native-grub.sha256)" ]] ||
      refuse 'unowned-GRUB-fallback-mutation'
    # Q4OS hook5's useful effect: refresh grub.cfg. The EFI binaries must
    # remain bit-for-bit intact; grub-install/efibootmgr are never used here.
    update-grub > /var/log/gaslux-q4os-owned-hook5.log 2>&1 || {
      tail -n 40 /var/log/gaslux-q4os-owned-hook5.log > /dev/ttyS0 || true
      refuse 'owned-update-grub-failed'
    }
    cmp -s /boot/efi/EFI/BOOT/BOOTX64.EFI \
      /boot/efi/EFI/GasluxQ4OSLab/grubx64.efi ||
      refuse 'EFI-binary-changed-by-update-grub'
    [[ "$(sha256sum /boot/efi/EFI/BOOT/BOOTX64.EFI | cut -d' ' -f1)" == "$existing" ]] ||
      refuse 'EFI-fallback-changed-by-update-grub'
    [[ -s /boot/grub/grub.cfg ]] || refuse 'missing-refreshed-GRUB-config'
    printf 'grubCfgRefreshed=yes;efiUnchanged=yes\n' > "$state/hook5"
    printf 'GASLUX_Q4OS_OWNED_HOOK5=%s\n' "$transaction" > /dev/ttyS0
    ;;
  verify)
    for n in hook2 hook3 hook5; do
      [[ -s "$state/$n" && ! -L "$state/$n" ]] ||
        refuse "missing-durable-hook-$n"
    done
    [[ "$(getent passwd gasluxlab | cut -d: -f6)" == '/home/gasluxlab' ]] ||
      refuse 'locked-test-user-missing'
    [[ -d /home/gasluxlab ]] || refuse 'locked-user-home-missing'
    [[ "$(passwd -S gasluxlab | awk '{print $2}')" == L ]] ||
      refuse 'test-account-was-unlocked'
    [[ "$(cat "$state/hook3")" == 'aptCleanup=blocked;profileInstaller=blocked;legacyEFI=blocked' ]] ||
      refuse 'unreviewed-hook-effects-must-stay-blocked'
    printf 'GASLUX_Q4OS_OWNED_HOOKS_VERIFIED=%s\n' "$transaction" > /dev/ttyS0
    ;;
esac
