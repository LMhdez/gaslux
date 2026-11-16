#!/usr/bin/env bash
# LAB-ONLY: materialize Q4OS's Calamares unpackfs payload into an ephemeral GPT
# image, then attempt an OVMF boot from that image WITHOUT the ISO attached.
# This does not execute Calamares' other jobs or prove the production backend.
# Every format operation is limited to verified partitions on our own loop file.
set -Eeuo pipefail

die() { printf 'GASLUX_Q4OS_INSTALLED_LAB_REFUSED: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 3 ]] || die 'Usage: installed_lab.sh ISO PINNED_SHA256 EVIDENCE_DIR'
[[ "${GASLUX_Q4OS_ALLOW_DISPOSABLE_INSTALL:-}" == yes ]] ||
  die 'Disposable virtual-disk write requires explicit laboratory opt-in'
[[ -f "$1" && ! -L "$1" ]] || die 'ISO is not a non-symlink regular file'
iso="$(realpath -e -- "$1")"
digest="$2"
[[ "$digest" =~ ^[a-f0-9]{64}$ ]] || die 'No pinned official ISO digest'
[[ -d "$3" && ! -L "$3" ]] || die 'Evidence path must be a non-symlink directory'
evidence="$(realpath -e -- "$3")"
for tool in sha256sum sudo mount umount findmnt unsquashfs sgdisk losetup blkid \
            mkfs.ext4 mkfs.vfat grub-mkstandalone qemu-system-x86_64 timeout; do
  command -v "$tool" >/dev/null || die "Missing guest-only lab tool: $tool"
done
[[ "$iso" != *,* ]] || die 'Unsafe ISO path for tooling'
printf '%s  %s\n' "$digest" "$iso" | sha256sum -c --status ||
  die 'Actual official ISO bytes do not match independently pinned digest'
[[ -s "$evidence/etc__calamares__modules__unpackfs.conf" ]] ||
  die 'No verified native Calamares unpackfs evidence'
grep -Fxq '    -   source: "/run/live/medium/live/filesystem.squashfs"' \
  "$evidence/etc__calamares__modules__unpackfs.conf" ||
  die 'Calamares payload source changed; guest disk writes refused'
[[ -s "$evidence/native-calamares-audit.json" ]] ||
  die 'Native Calamares semantic policy has not passed'
# Audit is an observation only. This root-materialization *experiment* never
# invokes interactive Calamares, arbitrary q4oshook jobs or a Windows writer.
work="$(mktemp -d -t gaslux-q4os-installed-lab-XXXXXX)"
loop=''
mounted_iso=0
mounted_root=0
mounted_efi=0
guest=''
cleanup() {
  if [[ -n "$guest" ]]; then
    kill "$guest" >/dev/null 2>&1 || true
    wait "$guest" >/dev/null 2>&1 || true
  fi
  if [[ "$mounted_efi" -eq 1 ]]; then sudo umount "$work/root/boot/efi" >/dev/null 2>&1 || true; fi
  if [[ "$mounted_root" -eq 1 ]]; then sudo umount "$work/root" >/dev/null 2>&1 || true; fi
  if [[ -n "$loop" ]]; then sudo losetup -d "$loop" >/dev/null 2>&1 || true; fi
  if [[ "$mounted_iso" -eq 1 ]]; then sudo umount "$work/iso" >/dev/null 2>&1 || true; fi
  for filename in serial-installed.log grub-installed.cfg installed-result.txt; do
    if [[ -f "$work/$filename" ]]; then
      cp -- "$work/$filename" "$evidence/$filename" || true
    fi
  done
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir "$work/iso" "$work/root"
sudo mount -o loop,ro,nosuid,nodev,noexec "$iso" "$work/iso"
mounted_iso=1
[[ "$(findmnt -rn -M "$work/iso" -o FSTYPE)" == iso9660 ]] ||
  die 'Mounted official source is not ISO9660'
squash="$work/iso/live/filesystem.squashfs"
[[ -f "$squash" && ! -L "$squash" ]] || die 'Calamares unpackfs source missing'
# The target file is created by us INSIDE this invocation's private temp dir.
# No command accepts a caller-supplied disk, volume, /dev/sdX or /dev/nvmeXnY.
disk="$work/guest-q4os-gpt.raw"
truncate -s 12G "$disk"
[[ -f "$disk" && ! -L "$disk" ]] || die 'Disposable target file creation failed'
# sgdisk operates on a regular file before any loop device is obtained.
sgdisk --clear \
  --new=1:2048:+512M --typecode=1:EF00 --change-name=1:GASLUX-Q4OS-ESP \
  --new=2:0:0 --typecode=2:8300 --change-name=2:GASLUX-Q4OS-ROOT \
  "$disk" >/dev/null
sgdisk --verify "$disk" >/dev/null || die 'Disposable GPT verification failed'
loop="$(sudo losetup --find --show --partscan "$disk")"
[[ "$loop" =~ ^/dev/loop[0-9]+$ ]] || die 'Unexpected loop block-device identity'
actual="$(sudo losetup -n -O BACK-FILE "$loop" | xargs)"
[[ "$actual" == "$disk" ]] || die 'Loop device does not belong to disposable image'
sudo udevadm settle || true
root_dev="${loop}p2"
efi_dev="${loop}p1"
[[ -b "$root_dev" && -b "$efi_dev" ]] || die 'Private GPT partitions not enumerated'
# Recheck loop ownership immediately before destructive mkfs operations.
[[ "$(sudo losetup -n -O BACK-FILE "$loop" | xargs)" == "$disk" ]] ||
  die 'Virtual target loop ownership changed'
sudo mkfs.vfat -F 32 -n GASLUXEFI "$efi_dev" >/dev/null
sudo mkfs.ext4 -F -q -L GASLUXQ4OS "$root_dev"
sudo mount "$root_dev" "$work/root"
mounted_root=1
[[ "$(findmnt -rn -M "$work/root" -o SOURCE)" == "$root_dev" ]] ||
  die 'Root target mount is not the owned GPT partition'
sudo unsquashfs -no-progress -f -d "$work/root" "$squash" >/dev/null
[[ "$(sudo cat "$work/root/etc/q4os_version")" == "6.10-deb13u1" ]] ||
  die 'Materialized target is not official pinned Q4OS root'
root_uuid="$(sudo blkid -s UUID -o value "$root_dev")"
esp_uuid="$(sudo blkid -s UUID -o value "$efi_dev")"
[[ "$root_uuid" =~ ^[0-9a-f-]{36}$ && "$esp_uuid" =~ ^[0-9A-F]{4}-[0-9A-F]{4}$ ]] ||
  die 'Guest partition UUID measurement invalid'
sudo tee "$work/root/etc/fstab" >/dev/null <<EOF
UUID=$root_uuid / ext4 defaults 0 1
UUID=$esp_uuid /boot/efi vfat umask=0077 0 2
EOF
printf 'gaslux-q4os-lab\n' | sudo tee "$work/root/etc/hostname" >/dev/null
# A guest-only systemd unit prints a marker ONLY if the installed root (not
# the live medium) was actually mounted by Linux and its identity matches.
sudo tee "$work/root/etc/systemd/system/gaslux-q4os-lab-proof.service" >/dev/null <<EOF
[Unit]
Description=Gaslux disposable installed-root proof
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'test "\$(cat /etc/q4os_version)" = "6.10-deb13u1" && printf "GASLUX_Q4OS_INSTALLED_ROOT_PROOF=6.10-deb13u1\\n" > /dev/ttyS0'
[Install]
WantedBy=multi-user.target
EOF
sudo mkdir -p "$work/root/etc/systemd/system/multi-user.target.wants"
sudo ln -s /etc/systemd/system/gaslux-q4os-lab-proof.service \
  "$work/root/etc/systemd/system/multi-user.target.wants/gaslux-q4os-lab-proof.service"
sudo mkdir -p "$work/root/boot/efi"
sudo mount "$efi_dev" "$work/root/boot/efi"
mounted_efi=1
[[ "$(findmnt -rn -M "$work/root/boot/efi" -o SOURCE)" == "$efi_dev" ]] ||
  die 'ESP mount is not the owned GPT partition'
kernel='6.12.111+deb13-amd64'
[[ -s "$work/root/boot/vmlinuz-$kernel" && -s "$work/root/boot/initrd.img-$kernel" ]] ||
  die 'Official installed source missing native Q4OS kernel and initramfs'
# Temporary lab GRUB, built using the runner; not claimed as a native,
# package-managed Q4OS bootloader. It exists ONLY in the guest-owned ESP.
cat > "$work/grub-installed.cfg" <<EOF
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
insmod part_gpt
insmod ext2
if ! search --no-floppy --fs-uuid --set=installedroot $root_uuid; then
  echo 'Installed Q4OS root UUID not found'; halt
fi
menuentry 'Disposable Q4OS installed-root lab only' {
  linux (\$installedroot)/boot/vmlinuz-$kernel root=UUID=$root_uuid ro console=ttyS0,115200n8 console=tty0 systemd.unit=multi-user.target systemd.wants=serial-getty@ttyS0.service
  initrd (\$installedroot)/boot/initrd.img-$kernel
}
EOF
grub-mkstandalone --format=x86_64-efi --output="$work/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$work/grub-installed.cfg"
sudo mkdir -p "$work/root/boot/efi/EFI/BOOT"
sudo cp "$work/BOOTX64.EFI" "$work/root/boot/efi/EFI/BOOT/BOOTX64.EFI"
sync
sudo umount "$work/root/boot/efi"
mounted_efi=0
sudo umount "$work/root"
mounted_root=0
sudo losetup -d "$loop"
loop=''
sudo umount "$work/iso"
mounted_iso=0

code=''
vars=''
for suffix in _4M ''; do
  if [[ -f "/usr/share/OVMF/OVMF_CODE${suffix}.fd" &&
        -f "/usr/share/OVMF/OVMF_VARS${suffix}.fd" ]]; then
    code="/usr/share/OVMF/OVMF_CODE${suffix}.fd"
    vars="/usr/share/OVMF/OVMF_VARS${suffix}.fd"
    break
  fi
done
[[ -n "$code" && -n "$vars" ]] || die 'Missing disposable OVMF firmware'
cp "$vars" "$work/guest-vars.fd"
printf 'GASLUX_Q4OS_DISPOSABLE_TARGET=own-temporary-12GiB-GPT-file\n'
printf 'GASLUX_Q4OS_GUEST_ROOT_UUID=%s\n' "$root_uuid"
printf 'GASLUX_Q4OS_ISO_ATTACHED_TO_INSTALLED_BOOT=false\n'
printf 'GASLUX_Q4OS_BOOTLOADER_PROVENANCE=temporary-lab-grub-not-Q4OS-package\n'
timeout --kill-after=5s 480s qemu-system-x86_64 \
  -machine q35,accel=tcg -cpu max -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -net none \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$work/guest-vars.fd" \
  -drive if=none,id=guesttarget,format=raw,file="$disk" \
  -device virtio-blk-pci,drive=guesttarget,bootindex=1 \
  -boot order=c,menu=off -serial "file:$work/serial-installed.log" &
guest="$!"
verified=0
for _ in $(seq 1 94); do
  sleep 5
  if [[ -s "$work/serial-installed.log" ]] &&
     grep -Fq 'GASLUX_Q4OS_INSTALLED_ROOT_PROOF=6.10-deb13u1' "$work/serial-installed.log" &&
     grep -Eiq 'Linux version|Freeing unused kernel|systemd\[1\]' "$work/serial-installed.log"; then
    verified=1
    break
  fi
  kill -0 "$guest" >/dev/null 2>&1 || break
done
kill "$guest" >/dev/null 2>&1 || true
wait "$guest" >/dev/null 2>&1 || true
guest=''
if [[ "$verified" -eq 1 ]]; then
  printf 'PASS: pinned Q4OS root filesystem booted from disposable GPT disk without ISO.\n' |
    tee "$work/installed-result.txt"
  printf 'NOT TESTED: complete Calamares jobs, native bootloader maintenance, Windows dual boot, rollback.\n' |
    tee -a "$work/installed-result.txt"
else
  tail -c 9000 "$work/serial-installed.log" >&2 || true
  die 'No installed Q4OS root boot proof; disposable experiment failed'
fi
