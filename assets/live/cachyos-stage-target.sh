#!/usr/bin/env bash
# Deliberately not wired into the production Libertix installer.
# Requires an already formatted, transaction-owned target on CachyOS Archiso.
# Does NOT touch partitions, EFI files, NVRAM, Windows or GRUB installations.
set -Eeuo pipefail

usage() {
  echo 'Usage: cachyos-stage-target.sh --check'
  echo '       cachyos-stage-target.sh --validate-target RUN_ID ROOT_UUID'
  echo '       cachyos-stage-target.sh --install USER HOST LOCALE TIMEZONE HASH_FILE RUN_ID ROOT_UUID'
  echo 'Experimental laboratory staging only. --install installs packages but no bootloader.'
}
die() { printf 'CACHYOS_STAGE_ERROR: %s\n' "$*" >&2; exit 1; }
readonly TARGET=/mnt/target

check_host() {
  [ "$(id -u)" -eq 0 ] || die 'root privileges required'
  [ -r /etc/os-release ] || die 'os-release missing'
  local host_id host_name host_like
  host_id="$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')"
  host_name="$(sed -n 's/^NAME=//p' /etc/os-release | head -n 1 | tr -d '"')"
  host_like="$(sed -n 's/^ID_LIKE=//p' /etc/os-release | head -n 1 | tr -d '"')"
  # Verified 260809 identity matches the earlier live QEMU probe.
  [ "$host_id" = cachyos ] && [ "$host_like" = arch ] &&
    [ "$host_name" = 'CachyOS Linux' ] ||
    die 'CachyOS Archiso identity does not match verified ISO'
  grep -qx 'IMAGE_ID=cachyos' /etc/os-release ||
    die 'CachyOS Archiso image identifier differs from verified ISO'
  grep -qx 'IMAGE_VERSION=2026.08.09' /etc/os-release ||
    die 'CachyOS Archiso image version differs from pinned ISO 260809'
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

# Transaction markers alone do not prove ownership. Restrict pacstrap to
# a dedicated secondary virtio partition of a disposable QEMU/KVM guest.
check_target_isolated_disk() {
  local source="$1" parent_name live_source live_parent mounts disk_type options
  for cmd in lsblk readlink; do
    command -v "$cmd" >/dev/null || die "missing disk identity tool: $cmd"
  done
  source="$(readlink -f -- "$source")" || die 'cannot canonicalize target'
  [ -b "$source" ] || die 'target is not a block device'
  [[ "$source" =~ ^/dev/vd[b-z][1-9][0-9]*$ ]] ||
    die 'target must be a secondary virtio disk partition'
  disk_type="$(lsblk -dn -o TYPE "$source")" || die 'cannot read disk type'
  [ "$disk_type" = part ] || die 'target must be a partition'
  parent_name="$(lsblk -dn -o PKNAME "$source")" || die 'cannot identify parent disk'
  [[ "$parent_name" =~ ^vd[b-z]$ ]] || die 'unexpected parent disk'
  [ -b "/dev/$parent_name" ] || die 'parent disk missing'
  [ "$(lsblk -nr -o TYPE "/dev/$parent_name" | grep -cx part)" -eq 1 ] ||
    die 'target disk contains additional partitions'
  live_source="$(findmnt -rn -M / -o SOURCE)" || die 'live root unavailable'
  live_source="$(readlink -f -- "$live_source")" || die 'cannot identify live root'
  [ "$live_source" != "$source" ] || die 'target is the live root'
  if [ -b "$live_source" ]; then
    live_parent="$(lsblk -dn -o PKNAME "$live_source" 2>/dev/null || true)"
    [ "$live_parent" != "$parent_name" ] || die 'target shares live root disk'
  fi
  mounts="$(findmnt -rn -S "$source" -o TARGET)" || die 'mount list unavailable'
  [ "$mounts" = "$TARGET" ] || die 'target has foreign or multiple mountpoints'
  options="$(findmnt -rn -M "$TARGET" -o OPTIONS)" || die 'mount options unavailable'
  [[ ",$options," == *,rw,* ]] || die 'target must be mounted read-write'
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
  check_target_isolated_disk "$source"
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

check_authenticated_handoff() {
  local run_id="$1" root_uuid="$2"
  local auth_tool=/usr/local/lib/libertix/cachyos-handoff-auth.py
  local envelope="${GASLUX_HANDOFF_ENVELOPE:-}"
  local signature="${GASLUX_HANDOFF_SIGNATURE:-}"
  local public_key="${GASLUX_HANDOFF_PUBLIC_KEY:-}"
  [ -f "$auth_tool" ] && [ ! -L "$auth_tool" ] ||
    die 'authenticated Archiso handoff verifier has not been provisioned'
  [ -n "$envelope" ] && [ -n "$signature" ] && [ -n "$public_key" ] ||
    die 'missing signed transaction envelope, signature or public key'
  command -v openssl >/dev/null ||
    die 'OpenSSL signature verifier is missing'
  # Bind the signed envelope to the caller's expected run/root and /proc/cmdline.
  # The public key is pinned by the boot arguments, not trusted by file path.
  python3 "$auth_tool" \
    --envelope "$envelope" --signature "$signature" \
    --public-key "$public_key" \
    --run-id "$run_id" --root-uuid "$root_uuid" >/dev/null ||
    die 'signed Windows-to-Archiso transaction authentication failed'
}

install_target() {
  local username="$1" hostname="$2" locale="$3" timezone="$4" secret="$5" run_id="$6" root_uuid="$7" hash
  check_disposable_vm
  check_host
  check_authenticated_handoff "$run_id" "$root_uuid"
  check_target "$run_id" "$root_uuid"
  check_identity "$username" "$hostname" "$locale" "$timezone" "$secret"
  pacstrap -K "$TARGET" \
    base linux-cachyos linux-firmware mkinitcpio \
    cachyos-keyring cachyos-mirrorlist cachyos-settings cachyos-hooks \
    pacman sudo networkmanager grub efibootmgr os-prober \
    e2fsprogs dosfstools ntfs-3g \
    plasma-meta sddm konsole dolphin xorg-server xorg-xwayland python
  [ -f "$TARGET/etc/os-release" ] || die 'pacstrap did not create the target OS'
  # Preserve signed CachyOS repositories and mirror configuration after pacstrap.
  [ -f /etc/pacman.conf ] && [ ! -L /etc/pacman.conf ] || die 'trusted pacman configuration missing'
  install -m 0644 /etc/pacman.conf "$TARGET/etc/pacman.conf"
  install -d -m 0755 "$TARGET/etc/pacman.d"
  for mirror in mirrorlist cachyos-mirrorlist cachyos-v3-mirrorlist cachyos-v4-mirrorlist; do
    if [ -f "/etc/pacman.d/$mirror" ] && [ ! -L "/etc/pacman.d/$mirror" ]; then
      install -m 0644 "/etc/pacman.d/$mirror" "$TARGET/etc/pacman.d/$mirror"
    fi
  done
  [ -s "$TARGET/etc/pacman.d/mirrorlist" ] || die 'Arch repository mirrorlist missing'
  [ -s "$TARGET/etc/pacman.d/cachyos-mirrorlist" ] || die 'CachyOS repository mirrorlist missing'
  grep -Eq '^[[:space:]]*\[cachyos\][[:space:]]*$' "$TARGET/etc/pacman.conf" || die 'CachyOS repository missing from target'
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
  --validate-target)
    [ "$#" -eq 3 ] || { usage; exit 2; }
    check_disposable_vm
    check_host
    check_target "$2" "$3"
    echo 'PASS: disposable VM target isolation verified (read-only).'
    ;;
  --install) [ "$#" -eq 8 ] || { usage; exit 2; }; install_target "$2" "$3" "$4" "$5" "$6" "$7" "$8" ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
