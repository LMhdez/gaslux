#!/usr/bin/env bash
# Deliberately not wired into the production Libertix installer.
# Requires an already formatted, transaction-owned target on CachyOS Archiso.
# Does NOT touch partitions, EFI files, NVRAM, Windows or GRUB installations.
set -Eeuo pipefail

usage() {
  echo 'Usage: cachyos-stage-target.sh --check'
  echo '       cachyos-stage-target.sh --install USER HOST LOCALE TIMEZONE HASH_FILE RUN_ID ROOT_UUID'
  echo 'Experimental laboratory staging only. --install installs packages but no bootloader.'
}
die() { printf 'CACHYOS_STAGE_ERROR: %s\n' "$*" >&2; exit 1; }
readonly TARGET=/mnt/target

check_host() {
  [ "$(id -u)" -eq 0 ] || die 'root privileges required'
  [ -r /etc/os-release ] || die 'os-release missing'
  local host_id host_name
  host_id="$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')"
  host_name="$(sed -n 's/^NAME=//p' /etc/os-release | head -n 1 | tr -d '"')"
  [ "$host_id" = cachyos ] && [ "$host_name" = 'CachyOS Linux' ] ||
    die 'CachyOS Archiso identity does not match the verified ISO'
  grep -qx 'ID_LIKE=arch' /etc/os-release ||
    die 'CachyOS Archiso has no matching Arch compatibility identity'
  grep -qx 'IMAGE_ID=cachyos' /etc/os-release ||
    die 'CachyOS Archiso image identifier mismatch'
  [ -d /sys/firmware/efi/efivars ] || die 'UEFI-only staging'
  python3 - <<'PY' || die 'Secure Boot not provably disabled'
from pathlib import Path
p = list(Path('/sys/firmware/efi/efivars').glob('SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'))
if len(p) != 1 or len(p[0].read_bytes()) != 5 or p[0].read_bytes()[4] != 0:
    raise SystemExit('Secure Boot enabled/unknown')
PY
  for cmd in pacstrap arch-chroot pacman findmnt blkid; do
    command -v "$cmd" >/dev/null || die "required command missing: $cmd"
  done
  grep -Eq '^[[:space:]]*\[cachyos\][[:space:]]*$' /etc/pacman.conf || die 'CachyOS pacman repo missing'
}

check_target() {
  local run_id="$1" root_uuid="$2" source observed
  [[ "$run_id" =~ ^[A-Za-z0-9_-]{12,100}$ ]] || die 'invalid transaction id'
  [[ "$root_uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die 'invalid root UUID'
  [ -d "$TARGET" ] && [ ! -L "$TARGET" ] || die 'target missing or a symlink'
  [ "$(findmnt -rn -M "$TARGET" -o TARGET 2>/dev/null)" = "$TARGET" ] || die 'target must be a distinct mountpoint'
  [ "$(findmnt -rn -M "$TARGET" -o FSTYPE)" = ext4 ] || die 'target filesystem is not ext4'
  source="$(findmnt -rn -M "$TARGET" -o SOURCE)"
  [[ "$source" == /dev/* ]] && [ -b "$source" ] || die 'target is not a block device'
  observed="$(blkid -s UUID -o value "$source")"
  [ "${observed,,}" = "${root_uuid,,}" ] || die 'target UUID does not match transaction'
  [ -f "$TARGET/.libertix-stage-owner" ] && [ ! -L "$TARGET/.libertix-stage-owner" ] || die 'missing transaction ownership marker'
  [ "$(cat "$TARGET/.libertix-stage-owner")" = "$run_id" ] || die 'transaction ownership mismatch'
  [ ! -e "$TARGET/etc/os-release" ] || die 'refusing to overwrite an installed OS'
  [ -z "$(ls -A "$TARGET" | grep -vE '^(lost\+found|\.libertix-stage-owner)$' || true)" ] || die 'target contains unrelated files'
}

check_identity() {
  local username="$1" hostname="$2" locale="$3" timezone="$4" secret="$5" hash
  [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] && [ "$username" != root ] || die 'invalid username'
  [[ "$hostname" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || die 'invalid hostname'
  [[ "$locale" =~ ^[a-z]{2,3}_[A-Z]{2}\.UTF-8$ ]] || die 'invalid locale'
  [[ "$timezone" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)+$ ]] && [ -f "/usr/share/zoneinfo/$timezone" ] || die 'invalid timezone'
  [ -f "$secret" ] && [ ! -L "$secret" ] && [ "$(stat -c %a "$secret")" = 600 ] && [ "$(stat -c %u "$secret")" -eq 0 ] || die 'secret must be a root-owned 0600 regular file'
  IFS= read -r hash < "$secret" || true
  [[ "$hash" =~ ^\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{40,120}$ ]] || die 'invalid SHA512-crypt password hash'
}

check_disposable_vm() {
  [ "${GASLUX_DISPOSABLE_VM:-}" = I_ACCEPT_DISPOSABLE_VM_ONLY ] ||
    die 'CachyOS installation is restricted to an explicitly consented disposable VM'
  command -v systemd-detect-virt >/dev/null ||
    die 'cannot verify the virtualization environment'
  case "$(systemd-detect-virt --vm 2>/dev/null)" in
    kvm|qemu) ;;
    *) die 'refusing CachyOS target provisioning outside QEMU/KVM' ;;
  esac
}

install_target() {
  local username="$1" hostname="$2" locale="$3" timezone="$4" secret="$5" run_id="$6" root_uuid="$7" hash
  check_disposable_vm
  check_host
  check_target "$run_id" "$root_uuid"
  check_identity "$username" "$hostname" "$locale" "$timezone" "$secret"
  # The official pinned live ISO is known to allow weak CachyOS package
  # signatures. Never use its pacman.conf for pacstrap or target updates.
  # A separate strict config and HTTPS-only mirrorlists are generated solely
  # on VM tmpfs and checked with the REAL pacman-conf parser.
  local trust_guard=/usr/local/lib/libertix/cachyos-pacman-trust.py
  local strict_builder=/usr/local/lib/libertix/cachyos-strict-pacman.py
  for trusted in "$trust_guard" "$strict_builder"; do
    [ -f "$trusted" ] && [ ! -L "$trusted" ] &&
      [ "$(stat -c %u "$trusted")" -eq 0 ] ||
      die "maintainer-provisioned trust asset missing: $trusted"
  done
  local strict_dir="/run/gaslux-pacman-$run_id"
  python3 "$strict_builder" --prepare-vm --run-id "$run_id" >/dev/null ||
    die 'cannot prepare strict signed-only pacman configuration in VM tmpfs'
  [ -f "$strict_dir/pacman-install.conf" ] &&
    [ -f "$strict_dir/pacman-target.conf" ] || die 'strict config incomplete'
  python3 "$trust_guard" --config "$strict_dir/pacman-install.conf" >/dev/null ||
    die 'strict CachyOS pacman package signing policy could not be verified'
  pacstrap -K -C "$strict_dir/pacman-install.conf" "$TARGET" \
    base linux-cachyos linux-firmware mkinitcpio \
    cachyos-keyring cachyos-mirrorlist cachyos-settings \
    pacman sudo networkmanager grub efibootmgr os-prober \
    e2fsprogs dosfstools ntfs-3g \
    plasma-meta sddm konsole dolphin xorg-server xorg-xwayland python
  [ -f "$TARGET/etc/os-release" ] || die 'pacstrap did not create the target OS'
  # Install the verified strict target config; never copy the live ISO
  # pacman.conf or unfiltered HTTP/FTP mirrors into the installed system.
  install -d -m 0755 "$TARGET/etc/pacman.d"
  install -m 0644 "$strict_dir/pacman-target.conf" "$TARGET/etc/pacman.conf"
  for mirror in mirrorlist cachyos-mirrorlist; do
    install -m 0644 "$strict_dir/$mirror" "$TARGET/etc/pacman.d/$mirror"
  done
  cmp -s "$strict_dir/pacman-target.conf" "$TARGET/etc/pacman.conf" ||
    die 'installed pacman signature configuration differs from audited candidate'
  [ -s "$TARGET/etc/pacman.d/mirrorlist" ] || die 'Arch repository mirrorlist missing'
  [ -s "$TARGET/etc/pacman.d/cachyos-mirrorlist" ] || die 'CachyOS repository mirrorlist missing'
  grep -Eq '^[[:space:]]*\[cachyos\][[:space:]]*$' "$TARGET/etc/pacman.conf" || die 'CachyOS repository missing from target'
  python3 "$trust_guard" --config "$TARGET/etc/pacman.conf" >/dev/null ||
    die 'installed pacman configuration would permit unsigned packages'
  printf '%s\n' "$hostname" > "$TARGET/etc/hostname"
  printf '127.0.0.1 localhost\n::1 localhost\n127.0.1.1 %s.localdomain %s\n' "$hostname" "$hostname" > "$TARGET/etc/hosts"
  printf 'LANG=%s\n' "$locale" > "$TARGET/etc/locale.conf"
  printf '%s UTF-8\n' "$locale" >> "$TARGET/etc/locale.gen"
  arch-chroot "$TARGET" locale-gen
  arch-chroot "$TARGET" ln -sfn "/usr/share/zoneinfo/$timezone" /etc/localtime
  arch-chroot "$TARGET" hwclock --systohc
  arch-chroot "$TARGET" useradd -m -s /bin/bash -G wheel "$username"
  IFS= read -r hash < "$secret" || true
  printf '%s:%s\n' "$username" "$hash" | arch-chroot "$TARGET" chpasswd --encrypted
  hash=''
  install -d -m 0750 "$TARGET/etc/sudoers.d"
  printf '%%wheel ALL=(ALL:ALL) ALL\n' > "$TARGET/etc/sudoers.d/10-libertix-wheel"
  chmod 0440 "$TARGET/etc/sudoers.d/10-libertix-wheel"
  arch-chroot "$TARGET" visudo -cf /etc/sudoers
  arch-chroot "$TARGET" mkinitcpio -P
  arch-chroot "$TARGET" systemctl enable NetworkManager.service sddm.service
  echo 'Target configured, but deliberately not bootable: EFI/GRUB not installed.'
}

case "${1:---help}" in
  --check) [ "$#" -eq 1 ] || { usage; exit 2; }; check_host ;;
  --install) [ "$#" -eq 8 ] || { usage; exit 2; }; install_target "$2" "$3" "$4" "$5" "$6" "$7" "$8" ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
