#!/usr/bin/env bash
# Run only inside disposable QEMU/OVMF with three virtual disks and no network.
# Native --test may mutate the target: never attach a host or production disk.
set -Eeuo pipefail
die() { printf 'GASLUX_POP_GUEST_DISTINST_FAILURE: %s\n' "$*" > /dev/ttyS0; exit 1; }
[[ $# -eq 1 && "$1" =~ ^[a-f0-9]{64}$ ]] || die 'native-agent pin missing'
[[ "$(id -u)" -eq 0 ]] || die 'VM root is required'
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) die 'not a QEMU/KVM VM' ;; esac
. /etc/os-release
[[ "${ID:-}" == pop && "${VERSION_ID:-}" == 24.04 ]] ||
  die 'not the verified Pop 24.04 live OS'
[[ "$(sha256sum /usr/bin/distinst | awk '{print $1}')" == "$1" ]] ||
  die 'native distinst bytes differ from signed ISO'
[[ "$(findmnt -rn -M /run/gaslux-pop-lab -o FSTYPE)" == vfat ]] ||
  die 'control probe is not on FAT media'
findmnt -rn -M /run/gaslux-pop-lab -o OPTIONS | tr , '\n' | grep -qx ro ||
  die 'probe is not mounted read-only'

target=/dev/disk/by-id/virtio-GASLUXPOPTARGET
[[ -b "$target" ]] || die 'unique owned virtual target missing'
[[ "$(blockdev --getsize64 "$target")" == 34359738368 ]] ||
  die 'wrong virtual target size'
[[ "$(lsblk -dn -o RO "$target" | tr -d '[:space:]')" == 0 ]] ||
  die 'target disk cannot be written'
for part in 1 2 3; do
  [[ -b "$target-part$part" ]] || die "missing virtual partition $part"
done
[[ "$(blkid -s TYPE -o value "$target-part1")" == vfat ]] ||
  die 'mock Windows ESP not FAT'
[[ "$(blkid -s TYPE -o value "$target-part2")" == ntfs ]] ||
  die 'mock Windows volume not NTFS'

[[ -d /cdrom ]] || die 'verified Pop ISO not mounted at /cdrom'
mapfile -t squashfs_paths < <(find /cdrom -mindepth 2 -maxdepth 3 -type f \
  -name filesystem.squashfs -print | sort)
[[ "${#squashfs_paths[@]}" -eq 1 ]] || die 'ambiguous Pop rootfs squashfs'
squashfs="${squashfs_paths[0]}"
remove="${squashfs%/*}/filesystem.manifest-remove"
[[ -s "$squashfs" && -s "$remove" ]] || die 'Pop install manifest missing'
output="$(mktemp -p /run -t gaslux-distinst-vm-stage.XXXXXX)"
trap 'rm -f -- "$output"' EXIT
# Windows-like mock volumes are deliberately omitted from --use.
# Existing ESP must be reused, NEVER requested as fat32 formatting.
if ! timeout --kill-after=5s 240s /usr/bin/distinst \
  --test --no-efi-vars --squashfs "$squashfs" --remove "$remove" \
  --hostname gaslux-pop-vm --keyboard us --lang en_US.UTF-8 \
  --block "$target" \
  --use "$target:1:reuse:mount=/boot/efi" \
  --use "$target:3:ext4:mount=/" \
  > "$output" 2>&1; then
  tail -n 25 "$output" > /dev/ttyS0
  die 'distinst --test did not accept the isolated native target'
fi
printf 'GASLUX_POP_DISTINST_VM_TARGET_TEST_PASS=1\n' > /dev/ttyS0
