#!/usr/bin/env bash
# Real CachyOS Archiso live-kernel smoke, from ISO file on a disposable
# ext4 QEMU disk. Never uses any host or Windows physical block device.
set -Eeuo pipefail
[[ $# -eq 2 ]] || { echo 'Usage: smoke.sh ISO PINNED_SHA256' >&2; exit 2; }
iso="$(realpath "$1")"
hash="$2"
[[ "$hash" =~ ^[0-9a-f]{64}$ ]] || exit 2
[[ -f "$iso" && ! -L "$iso" ]] || exit 2
printf '%s  %s\n' "$hash" "$iso" | sha256sum --check --status || {
  echo 'ISO hash mismatch; refusing VM boot' >&2; exit 1;
}
for tool in grub-mkstandalone qemu-system-x86_64 mkfs.ext4 debugfs \
            mkfs.vfat mcopy mmd python3 timeout; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done
w="$(mktemp -d -t cachyos-real-boot-XXXXXX)"
trap 'rm -rf "$w"' EXIT
uuid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
disk="$w/ext4.img"
truncate -s 5G "$disk"
mkfs.ext4 -q -F -U "$uuid" "$disk"
debugfs -w -R "write $iso /cachyos.iso" "$disk" > "$w/write.log" 2>&1
debugfs -R "stat /cachyos.iso" "$disk" > "$w/stat.log" 2>&1
grep -Eq 'Size: [1-9][0-9]+' "$w/stat.log" || {
  echo 'No ISO in disposable virtual ext4 volume' >&2; exit 1;
}
cat > "$w/grub.cfg" <<GRUB
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set default=0
set timeout=0
menuentry 'CachyOS real Archiso kernel validation' {
  insmod ext2
  insmod iso9660
  search --no-floppy --fs-uuid --set=srcdev $uuid
  loopback iso (\$srcdev)/cachyos.iso
  linux (iso)/arch/boot/x86_64/vmlinuz-linux-cachyos-lts archisobasedir=arch img_dev=UUID=$uuid img_loop=/cachyos.iso cow_spacesize=4G copytoram=auto console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.log_level=info systemd.unit=multi-user.target
  initrd (iso)/arch/boot/x86_64/initramfs-linux-cachyos-lts.img
}
GRUB
grub-mkstandalone --format=x86_64-efi --output="$w/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$w/grub.cfg"
fat="$w/boot.img"
truncate -s 96M "$fat"
mkfs.vfat -F 32 "$fat" >/dev/null
mmd -i "$fat" ::/EFI
mmd -i "$fat" ::/EFI/BOOT
mcopy -i "$fat" "$w/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
code=''
vars=''
for suff in _4M ''; do
  c="/usr/share/OVMF/OVMF_CODE"$suff".fd"
  v="/usr/share/OVMF/OVMF_VARS"$suff".fd"
  if [[ -f "$c" && -f "$v" ]]; then code="$c"; vars="$v"; break; fi
done
[[ -n "$code" && -n "$vars" ]] || { echo 'No OVMF' >&2; exit 2; }
cp "$vars" "$w/nvram.fd"
timeout --kill-after=5s 380s qemu-system-x86_64 \
  -machine q35,accel=tcg -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -boot order=c \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$w/nvram.fd" \
  -device qemu-xhci \
  -drive if=none,id=bootimg,format=raw,file="$fat" \
  -device usb-storage,drive=bootimg \
  -drive if=none,id=isoimg,format=raw,readonly=on,file="$disk" \
  -device virtio-blk-pci,drive=isoimg \
  -serial file:"$w/serial.log" &
vm_pid=$!
# Stop early once both kernel and userspace evidence are captured.
for _ in $(seq 1 76); do
  sleep 5
  if grep -Eq 'Linux version [0-9]' "$w/serial.log" 2>/dev/null &&
     grep -Eq 'systemd\[1\]|systemd[ -]udevd|Welcome to CachyOS' "$w/serial.log" 2>/dev/null; then
    kill "$vm_pid" 2>/dev/null || true
    break
  fi
  kill -0 "$vm_pid" 2>/dev/null || break
done
set +e
wait "$vm_pid"
rc=$?
set -e
# Preserve the disposable VM's serial witness even when boot assertions fail.
if [[ -n "${GASLUX_BOOT_EVIDENCE_DIR:-}" && -f "$w/serial.log" ]]; then
  mkdir -p -- "$GASLUX_BOOT_EVIDENCE_DIR"
  install -m 0600 -- "$w/serial.log" "$GASLUX_BOOT_EVIDENCE_DIR/cachyos-live-serial.log"
  ( cd "$GASLUX_BOOT_EVIDENCE_DIR" && sha256sum cachyos-live-serial.log > cachyos-live-serial.sha256 )
fi
if ! grep -Eq 'Linux version [0-9]' "$w/serial.log"; then
  echo "FAIL: real CachyOS kernel execution unverified (QEMU status=$rc)" >&2
  tail -c 5000 "$w/serial.log" >&2 || true
  exit 1
fi
echo 'PASS: real CachyOS live Linux kernel executed in QEMU/OVMF.'
if ! grep -Eq 'systemd\[1\]|systemd[ -]udevd|Welcome to CachyOS' "$w/serial.log"; then
  echo 'INCOMPLETE: no Archiso userspace/init evidence' >&2
  tail -c 5000 "$w/serial.log" >&2 || true
  exit 1
fi
echo 'PASS: CachyOS live init/userspace emitted serial evidence.'
echo 'NOT TESTED: Windows dual boot, target installation or WinRE recovery.'
