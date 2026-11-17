#!/usr/bin/env bash
# Disposable Zorin 18.1 installed-root trial, never Windows coexistence.
# Only the SHA-pinned upstream ISO and a fresh raw image in RUNNER_TEMP are used.
set -Eeuo pipefail

die() { echo "GASLUX_ZORIN_INSTALLED_LAB_ERROR: $*" >&2; exit 1; }
[[ $# -eq 2 ]] || die 'Usage: script ISO SHA256'
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" ]] ||
  die 'A real GitHub Actions RUNNER_TEMP is required'
iso="$(realpath -e "$1")"
digest="$2"
[[ "$digest" =~ ^[0-9a-f]{64}$ && -f "$iso" && ! -L "$iso" ]] ||
  die 'Invalid ISO or unsigned SHA-256'
printf '%s  %s\n' "$digest" "$iso" | sha256sum -c --status ||
  die 'Pinned Zorin media has changed'
[[ -r "$iso" && "$(stat -c %s "$iso")" == 3909091328 ]] ||
  die 'The pinned 18.1 Core ISO has an unexpected byte count'
for cmd in sudo findmnt mountpoint losetup sgdisk mkfs.vfat mkfs.ext4 \
  unsquashfs grub-mkstandalone qemu-system-x86_64 timeout blkid sha256sum; do
  command -v "$cmd" >/dev/null || die "Missing lab dependency: $cmd"
done

work="$(mktemp -d "$RUNNER_TEMP/gaslux-zorin-installed-XXXXXXXX")"
[[ "$work" == "$RUNNER_TEMP"/gaslux-zorin-installed-* && ! -L "$work" ]] ||
  die 'Owned ephemeral workspace creation failed'
chmod 700 "$work"
mkdir -p "$work/iso" "$work/target" "$work/esp" "$work/evidence"
loop=''
qemu=''
root_mounted=0
esp_mounted=0
iso_mounted=0
chroot_mounted=0
# NEVER recursively delete an owned workspace while any of its paths
# contain a host mount (including bind-mounted /dev, proc or sysfs).
# On failure the runner can reclaim it after teardown; our script must not
# traverse external filesystems through a leaked guest mount.
lab_mounts_remaining() {
  local target
  while IFS= read -r target; do
    case "$target" in
      "$work"/*) echo "ACTIVE_LAB_MOUNT=$target" >&2; return 0 ;;
    esac
  done < <(findmnt -rn -o TARGET)
  return 1
}

release_chroot_mounts_or_die() {
  local attempt path still=0
  for attempt in $(seq 1 12); do
    still=0
    for path in "$work/target/dev/pts" "$work/target/dev" \
      "$work/target/proc" "$work/target/sys"; do
      if findmnt -rn -M "$path" >/dev/null 2>&1; then
        sudo umount "$path" 2>/dev/null || still=1
      fi
    done
    [[ "$still" -eq 0 ]] && {
      for path in "$work/target/dev/pts" "$work/target/dev" \
        "$work/target/proc" "$work/target/sys"; do
        findmnt -rn -M "$path" >/dev/null 2>&1 && still=1
      done
    }
    [[ "$still" -eq 0 ]] && return 0
    sleep 1
  done
  echo 'GASLUX_ZORIN_INSTALLED_LAB_ERROR: could not release chroot mounts' >&2
  return 1
}

cleanup() {
  if [[ -n "$qemu" ]]; then
    kill "$qemu" 2>/dev/null || true
    wait "$qemu" 2>/dev/null || true
  fi
  if [[ "$chroot_mounted" -eq 1 ]]; then
    release_chroot_mounts_or_die || true
  fi
  [[ "$esp_mounted" -eq 1 ]] && sudo umount "$work/esp" 2>/dev/null || true
  [[ "$root_mounted" -eq 1 ]] && sudo umount "$work/target" 2>/dev/null || true
  [[ "$iso_mounted" -eq 1 ]] && sudo umount "$work/iso" 2>/dev/null || true

  if [[ -n "${GASLUX_ZORIN_INSTALLED_EVIDENCE:-}" ]]; then
    mkdir -p "$GASLUX_ZORIN_INSTALLED_EVIDENCE"
    for name in serial.log grub.cfg installed-check.txt disk-layout.txt; do
      [[ ! -f "$work/$name" ]] ||
        cp -- "$work/$name" "$GASLUX_ZORIN_INSTALLED_EVIDENCE/$name" || true
    done
    (cd "$GASLUX_ZORIN_INSTALLED_EVIDENCE" &&
      sha256sum ./* > evidence.sha256) 2>/dev/null || true
  fi

  # Mandatory mount-table check precedes both loop detach and directory
  # deletion. Refuse deletion if any mount, including nested binds, persists.
  if lab_mounts_remaining; then
    echo '::error::Owned Zorin lab still has active mounts. Never deleting it.' >&2
    return 0
  fi
  if [[ -n "$loop" ]]; then
    sudo losetup -d "$loop" 2>/dev/null || {
      echo '::error::Owned loop image could not be detached; preserving workspace.' >&2
      return 0
    }
  fi
  [[ "$work" == "$RUNNER_TEMP"/gaslux-zorin-installed-* && ! -L "$work" ]] ||
    return 0
  sudo rm -rf --one-file-system -- "$work"
}
trap cleanup EXIT

sudo mount -t iso9660 -o ro,loop,nosuid,nodev,noexec "$iso" "$work/iso"
iso_mounted=1
source assets/live/libertix-distribution-common.sh
source assets/live/libertix-install-runtime-common.sh
rootfs="$(resolve_distribution_rootfs_or_die "$work/iso")" ||
  die 'ISO has no unique native squashfs root'
assert_distribution_rootfs_compatible_or_die "$rootfs" zorin ||
  die 'Official ISO fails production distribution capability gate'
[[ "$(findmnt -rn -M "$work/iso" -o FSTYPE)" == iso9660 ]] ||
  die 'The Zorin image was not mounted as ISO9660'

# The whole target is a fresh private file. Never select an actual disk.
# Require sufficient free host capacity before allocating/unsquashing.
free_kb="$(df -Pk "$RUNNER_TEMP" | awk 'END {print $4}')"
[[ "$free_kb" =~ ^[0-9]+$ && "$free_kb" -ge 9000000 ]] ||
  die 'At least 9 GB of remaining free runner scratch space is required'
disk="$work/zorin-only.raw"
truncate -s 16G "$disk"
[[ -f "$disk" && ! -L "$disk" ]] || die 'Lab image identity failure'
sgdisk --zap-all --new=1:2048:+512M --typecode=1:EF00 --change-name=1:LAB-ESP \
  --new=2:0:0 --typecode=2:8300 --change-name=2:LAB-ZORIN-ROOT "$disk" >/dev/null
loop="$(sudo losetup --find --show --partscan "$disk")"
[[ "$loop" == /dev/loop* && -b "$loop" ]] || die 'No owned loop block image'
[[ "$(sudo losetup --noheadings --output BACK-FILE "$loop" | xargs)" == "$disk" ]] ||
  die 'Loop backing identity does not match the owned image'
sudo udevadm settle --timeout=20
esp_part="${loop}p1"
root_part="${loop}p2"
[[ -b "$esp_part" && -b "$root_part" ]] || die 'Owned GPT partitions not exposed'
[[ "$(sudo sgdisk -i 1 "$loop" | grep -c 'EFI system partition')" -eq 1 ]] ||
  die 'Private ESP type verification failed'
sudo mkfs.vfat -F 32 -n GASLUXLAB "$esp_part" >/dev/null
sudo mkfs.ext4 -F -L GASLUXZORIN "$root_part" >/dev/null
sudo mount -t ext4 "$root_part" "$work/target"
root_mounted=1

echo 'Extracting the genuine, previously SHA-verified squashfs into the ONLY owned rootfs'
sudo unsquashfs -f -processors 2 -d "$work/target" "$rootfs" >/dev/null ||
  die 'Genuine installed-root extraction failed'
sudo umount "$work/iso"
iso_mounted=0
mapfile -t kernels < <(
  find "$work/target/boot" -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' | sort
)
[[ "${#kernels[@]}" -eq 1 ]] || {
  printf 'Extracted /boot kernel candidates: %s\n' "${kernels[*]}" >&2
  die 'The extracted native root lacks a unique installed kernel'
}
kernel="${kernels[0]}"
version="${kernel#vmlinuz-}"
[[ "$version" =~ ^[A-Za-z0-9.+_-]+$ ]] ||
  die 'Installed kernel version has unsafe filename'
[[ -d "$work/target/lib/modules/$version" ||
   -d "$work/target/usr/lib/modules/$version" ]] ||
  die 'Extracted installed kernel lacks its versioned modules'

root_uuid="$(sudo blkid -s UUID -o value "$root_part")"
esp_uuid="$(sudo blkid -s UUID -o value "$esp_part")"
[[ "$root_uuid" =~ ^[0-9a-f-]{36}$ && -n "$esp_uuid" ]] ||
  die 'Owned formatted disk has missing filesystem UUIDs'
sudo tee "$work/target/etc/fstab" >/dev/null <<EOF
UUID=$root_uuid / ext4 defaults 0 1
UUID=$esp_uuid /boot/efi vfat umask=0077 0 1
EOF
echo GASLUXZORIN | sudo tee "$work/target/etc/hostname" >/dev/null

# Native initramfs must reference the actual installed ext4 root, not Casper.
# Set cleanup ownership before the first mount so partial mount failures
# are also safely released without traversing a host bind filesystem.
chroot_mounted=1
sudo mount -t proc proc "$work/target/proc"
sudo mount -t sysfs sysfs "$work/target/sys"
sudo mount --bind /dev "$work/target/dev"
sudo mount --bind /dev/pts "$work/target/dev/pts"
sudo chroot "$work/target" /usr/bin/env -u CASPER_GENERATE_UUID \
  update-initramfs -u -k "$version" ||
  die 'Target initramfs rebuild failed; cannot treat Casper initrd as installed'
initrd="$work/target/boot/initrd.img-$version"
[[ -s "$initrd" ]] || die 'Target has no generated installed initramfs'
sudo chroot "$work/target" lsinitramfs "/boot/initrd.img-$version" > "$work/initrd-files.txt"
if grep -Eq '(^|/)(conf/conf.d/default-boot-to-casper.conf|conf/conf.d/live-initrd.conf|conf/uuid.conf)$' "$work/initrd-files.txt"; then
  die 'Installed initramfs is configured to boot back to Casper'
fi
sync
sudo udevadm settle --timeout=20 || true
release_chroot_mounts_or_die || die 'Native target mounts remained busy after initramfs rebuild'
chroot_mounted=0

sudo mount -t vfat "$esp_part" "$work/esp"
esp_mounted=1
cat > "$work/grub.cfg" <<EOF
serial --unit=0 --speed=115200
terminal_input serial
terminal_output serial
set timeout=0
insmod part_gpt
insmod ext2
insmod search_fs_uuid
search --no-floppy --fs-uuid --set=root $root_uuid
menuentry 'Genuine Zorin 18.1 on disposable private disk' {
  linux /boot/$kernel root=UUID=$root_uuid rw console=tty0 console=ttyS0,115200n8 systemd.unit=multi-user.target systemd.wants=serial-getty@ttyS0.service
  initrd /boot/initrd.img-$version
}
EOF
grub-mkstandalone --format=x86_64-efi --output="$work/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$work/grub.cfg"
sudo install -d "$work/esp/EFI/BOOT"
sudo install -m 0644 "$work/BOOTX64.EFI" "$work/esp/EFI/BOOT/BOOTX64.EFI"
sudo umount "$work/esp"
esp_mounted=0
sudo umount "$work/target"
root_mounted=0
sudo sgdisk -p "$loop" > "$work/disk-layout.txt"
sudo losetup -d "$loop"
loop=''

code=''
vars=''
for suffix in _4M ''; do
  [[ ! -f "/usr/share/OVMF/OVMF_CODE${suffix}.fd" ||
     ! -f "/usr/share/OVMF/OVMF_VARS${suffix}.fd" ]] || {
    code="/usr/share/OVMF/OVMF_CODE${suffix}.fd"
    vars="/usr/share/OVMF/OVMF_VARS${suffix}.fd"
    break
  }
done
[[ -n "$code" && -n "$vars" ]] || die 'OVMF is missing'
cp "$vars" "$work/nvram.fd"
echo "GASLUX_ZORIN_INSTALLED_KERNEL=$kernel"
echo "GASLUX_ZORIN_INSTALLED_ROOT_UUID=$root_uuid"
echo 'Booting disposable installed-root GPT disk with ISO disconnected'
timeout --kill-after=5s 420s qemu-system-x86_64 \
  -machine q35,accel=tcg -cpu max -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -net none \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$work/nvram.fd" \
  -drive if=none,id=installed,format=raw,file="$disk" \
  -device virtio-blk-pci,drive=installed,bootindex=1 \
  -boot order=c,menu=off \
  -serial "file:$work/serial.log" &
qemu="$!"
verified=0
for _ in $(seq 1 82); do
  sleep 5
  if [[ -s "$work/serial.log" ]] &&
     grep -Eiq 'Linux version|Freeing unused kernel|systemd\[1\]' "$work/serial.log" &&
     grep -Eq '(^|[^[:alpha:]])GASLUXZORIN login:' "$work/serial.log"; then
    verified=1
    break
  fi
  kill -0 "$qemu" 2>/dev/null || break
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true
qemu=''
if [[ "$verified" -ne 1 ]]; then
  tail -c 8000 "$work/serial.log" >&2 || true
  die 'No genuine installed Zorin ext4-root login proof; do not claim firstboot'
fi
printf 'installedZorinFirstBootVerified=true\nisoSha256=%s\nrootUuid=%s\nkernel=%s\n' \
  "$digest" "$root_uuid" "$kernel" > "$work/installed-check.txt"
echo 'PASS: genuine Zorin extracted root reached installed-disk serial login without attached ISO'
echo 'NOT TESTED: Windows dual boot, Windows recovery, real Gaslux bootloader, kernel update, uninstall'
