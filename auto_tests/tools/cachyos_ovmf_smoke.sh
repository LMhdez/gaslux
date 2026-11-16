#!/usr/bin/env bash
# Boots a standalone GRUB EFI image under OVMF/QEMU and checks serial output.
# This validates UEFI execution, NOT a CachyOS installation or Windows recovery.
set -Eeuo pipefail

for cmd in grub-mkstandalone qemu-system-x86_64 mmd mcopy mkfs.vfat timeout; do
    command -v "$cmd" >/dev/null || {
        echo "Missing required UEFI smoke test command: $cmd" >&2
        exit 2
    }
done

workspace="$(mktemp -d -t gaslux-ovmf-XXXXXX)"
trap 'rm -rf "$workspace"' EXIT
cat > "$workspace/grub.cfg" <<'GRUB'
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
echo GASLUX_OVMF_UEFI_EXECUTED
halt
GRUB

grub-mkstandalone --format=x86_64-efi \
    --output="$workspace/BOOTX64.EFI" \
    "boot/grub/grub.cfg=$workspace/grub.cfg"

fat_image="$workspace/fat.img"
truncate -s 96M "$fat_image"
mkfs.vfat -F 32 -n GASLUXUEFI "$fat_image" >/dev/null
mmd -i "$fat_image" ::/EFI
mmd -i "$fat_image" ::/EFI/BOOT
mcopy -i "$fat_image" "$workspace/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI

code=""
vars=""
for suffix in _4M ""; do
    code_candidate="/usr/share/OVMF/OVMF_CODE"$suffix".fd"
    vars_candidate="/usr/share/OVMF/OVMF_VARS"$suffix".fd"
    if [ -f "$code_candidate" ] && [ -f "$vars_candidate" ]; then
        code="$code_candidate"
        vars="$vars_candidate"
        break
    fi
done
[ -n "$code" ] && [ -n "$vars" ] || {
    echo "Matching OVMF CODE/VARS not installed" >&2
    exit 2
}
cp "$vars" "$workspace/OVMF_VARS.fd"
serial_log="$workspace/serial.log"

# Software emulation (TCG), not host firmware.
set +e
timeout --kill-after=2s 55s qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -m 512 \
    -display none \
    -monitor none \
    -no-reboot \
    -boot order=d \
    -drive if=pflash,format=raw,readonly=on,file="$code" \
    -drive if=pflash,format=raw,file="$workspace/OVMF_VARS.fd" \
    -device qemu-xhci \
    -drive if=none,format=raw,id=usbdisk,file="$fat_image" \
    -device usb-storage,drive=usbdisk \
    -serial file:"$serial_log"
rc=$?
set -e

if ! grep -Fq GASLUX_OVMF_UEFI_EXECUTED "$serial_log"; then
    echo "OVMF/QEMU did not execute the standalone GRUB EFI image (exit=$rc)" >&2
    tail -c 3000 "$serial_log" >&2 || true
    exit 1
fi

echo "PASS: OVMF executed GRUB x86_64 EFI and emitted expected serial marker."
echo "NOTE: No CachyOS kernel, Windows Boot Manager or recovery was booted."
