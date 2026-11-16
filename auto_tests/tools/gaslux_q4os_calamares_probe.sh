#!/usr/bin/env bash
# Inspect Calamares configuration from one independently SHA-256-pinned Q4OS ISO.
# LAB ONLY: reads a loop-mounted ISO; never runs Calamares or writes a target.
set -Eeuo pipefail
die() { printf 'GASLUX_Q4OS_CALAMARES_REFUSED: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 3 ]] || die 'Usage: probe.sh ISO PINNED_SHA256 EVIDENCE_DIR'
[[ -f "$1" && ! -L "$1" ]] || die 'ISO must be an ordinary, non-symlink regular file'
iso="$(realpath -e -- "$1")"
expected="$2"
[[ "$expected" =~ ^[a-f0-9]{64}$ ]] || die 'Missing independently pinned ISO digest'
[[ -d "$3" && ! -L "$3" ]] || die 'Evidence directory must exist and not be a symlink'
evidence="$(realpath -e -- "$3")"
for tool in sha256sum sudo mount umount findmnt unsquashfs; do
  command -v "$tool" >/dev/null || die "Missing lab-only utility: $tool"
done
printf '%s  %s\n' "$expected" "$iso" | sha256sum -c --status ||
  die 'Full official ISO SHA-256 mismatch'
work="$(mktemp -d -t gaslux-q4os-calamares-XXXXXX)"
mounted=0
cleanup() {
  if [[ "$mounted" -eq 1 ]]; then sudo umount "$work/iso" >/dev/null 2>&1 || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir "$work/iso"
sudo mount -o loop,ro,nosuid,nodev,noexec "$iso" "$work/iso"
mounted=1
[[ "$(findmnt -rn -M "$work/iso" -o FSTYPE)" == iso9660 ]] ||
  die 'Verified source must mount as ISO9660'
# Exactly the one native image known in the full verified media.
[[ -f "$work/iso/live/filesystem.squashfs" &&
   ! -L "$work/iso/live/filesystem.squashfs" ]] ||
  die 'No native live SquashFS at the expected ISO path'
squash="$work/iso/live/filesystem.squashfs"
files=(
  etc/os-release
  etc/q4os_version
  etc/calamares/settings.conf
  etc/calamares/modules/partition.conf
  etc/calamares/modules/unpackfs.conf
  etc/calamares/modules/mount.conf
  etc/calamares/modules/fstab.conf
  etc/calamares/modules/bootloader.conf
  etc/calamares/modules/grubcfg.conf
  etc/calamares/modules/users.conf
  etc/calamares/modules/packages.conf
  etc/calamares/modules/displaymanager.conf
)
for file in "${files[@]}"; do
  dest="$evidence/${file//\//__}"
  [[ ! -e "$dest" && ! -L "$dest" ]] || die "Evidence collision: $file"
  unsquashfs -cat "$squash" "$file" > "$dest" ||
    die "Missing configuration in pinned Q4OS live root: $file"
  [[ -s "$dest" ]] || die "Empty pinned configuration: $file"
done
grep -Eq '^ID="?debian"?$' "$evidence/etc__os-release" ||
  die 'Live root is not Debian'
grep -Eq '^VERSION_ID="?13"?$' "$evidence/etc__os-release" ||
  die 'Debian base is not 13'
grep -Eq '^6[.]10' "$evidence/etc__q4os_version" ||
  die 'Pinned native ISO has unexpected Q4OS release'
( cd "$evidence" && sha256sum etc__* > calamares-files.sha256 )
printf 'GASLUX_Q4OS_PINNED_ISO_SHA256=%s\n' "$expected"
printf 'GASLUX_Q4OS_CALAMARES_SOURCE=verified-iso/live/filesystem.squashfs\n'
printf 'GASLUX_Q4OS_VERSION='
head -c 128 "$evidence/etc__q4os_version"
printf '\n--- Actual Q4OS Calamares settings.conf ---\n'
sed -n '1,150p' "$evidence/etc__calamares__settings.conf"
printf '\n--- Actual Q4OS Calamares unpackfs.conf ---\n'
cat "$evidence/etc__calamares__modules__unpackfs.conf"
printf '\n--- Actual Q4OS Calamares bootloader.conf ---\n'
sed -n '1,140p' "$evidence/etc__calamares__modules__bootloader.conf"
printf '\nGASLUX_Q4OS_INSTALLATION_AUTHORIZED=false\n'
