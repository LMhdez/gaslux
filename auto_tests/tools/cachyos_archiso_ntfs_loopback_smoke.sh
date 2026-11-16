#!/usr/bin/env bash
# Synthetic Archiso loopback integration smoke in QEMU/OVMF.
# It DOES NOT boot an authentic CachyOS kernel or run any Windows installation.
set -Eeuo pipefail

for binary in grub-mkstandalone qemu-system-x86_64 xorriso mksquashfs \
              unsquashfs mkntfs ntfscp blkid mkfs.vfat mmd mcopy python3; do
  command -v "$binary" >/dev/null || { echo "Missing $binary" >&2; exit 2; }
done

w="$(mktemp -d -t gaslux-archiso-smoke-XXXXXX)"
trap 'rm -rf "$w"' EXIT
mkdir -p "$w/source/etc" "$w/source/usr/bin" \
  "$w/iso-tree/arch/x86_64" "$w/iso-tree/arch/boot/x86_64" \
  "$w/storage"

cat > "$w/source/etc/os-release" <<'EOF'
NAME="CachyOS"
ID=arch
BUILD_ID=rolling
EOF
printf '[options]\n' > "$w/source/etc/pacman.conf"
printf '#!/bin/sh\nexit 0\n' > "$w/source/usr/bin/pacman"
chmod +x "$w/source/usr/bin/pacman"

mksquashfs "$w/source" "$w/iso-tree/arch/x86_64/airootfs.sfs" \
  -noappend -processors 1 -comp gzip >/dev/null
printf 'synthetic kernel file only\n' > "$w/iso-tree/arch/boot/x86_64/vmlinuz-linux-cachyos"
printf 'synthetic initramfs file only\n' > "$w/iso-tree/arch/boot/x86_64/initramfs-linux-cachyos.img"

archive="$w/storage/cachyos.iso"
xorriso -as mkisofs -quiet -iso-level 3 -o "$archive" "$w/iso-tree"
disk="$w/storage-disk.img"
truncate -s 128M "$disk"
mkntfs --fast --force --label GASLUXISO "$disk" >/dev/null 2>&1
uuid="$(blkid -p -s UUID -o value "$disk")"
[[ "$uuid" =~ ^[0-9A-F]{16}$ ]] || { echo "NTFS UUID is not 16 uppercase hex digits: $uuid" >&2; exit 2; }
ntfscp -f "$disk" "$archive" /cachyos.iso

python3 - "$w" "$uuid" <<'PY'
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

w = Path(sys.argv[1])
uuid = sys.argv[2]
archive = w / "storage/cachyos.iso"
plan = {
    "schemaVersion": 1,
    "firmware": "uefi",
    "secureBootEnabled": False,
    "runId": "archiso-vm-smoke-2026",
    "isoStorageFilesystem": "ntfs",
    "isoStorageUuid": uuid,
    "isoRelativePath": "/cachyos.iso",
    "isoSha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "isoSizeBytes": archive.stat().st_size,
}
(w / "handoff-plan.json").write_text(json.dumps(plan), encoding="utf-8")
script = Path("assets/live/cachyos-archiso-handoff.py").resolve()
spec = importlib.util.spec_from_file_location("gaslux_handoff_smoke", script)
assert spec and spec.loader
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)
result = handoff.prepare(plan, storage_root=w / "storage", iso_root=w / "iso-tree")
assert result["ok"] and result["isoSha256Verified"]
assert result["isoLayoutVerified"] and not result["productionInstallSupported"]

# The test replaces ONLY the final kernel invocation with a serial marker:
# it verifies that a real EFI GRUB can search the exact ext4 UUID, loop-mount
# the synthetic ISO, and discover the kernel, initramfs, and Archiso rootfs.
lines = []
kernel_seen = False
initrd_seen = False
for line in result["grubEntry"].splitlines():
    if line.startswith("    linux (gaslux_iso)/"):
        assert not kernel_seen
        kernel_seen = True
        lines.extend([
            "    if [ -f (gaslux_iso)/arch/boot/x86_64/initramfs-linux-cachyos.img ] && "
            "[ -f (gaslux_iso)/arch/x86_64/airootfs.sfs ]; then",
            "        echo GASLUX_ARCHISO_LOOPBACK_VERIFIED",
            "        halt",
            "    else",
            "        echo GASLUX_ARCHISO_COMPONENT_MISSING",
            "        halt",
            "    fi",
        ])
    elif line.startswith("    initrd (gaslux_iso)/"):
        assert not initrd_seen
        initrd_seen = True
    else:
        lines.append(line)
assert kernel_seen and initrd_seen

grub = (
    "serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\n"
    "terminal_input serial\nterminal_output serial\n"
    "set timeout=0\nset default=gaslux-cachyos-archiso\n"
    + "\n".join(lines) + "\n"
)
(w / "grub.cfg").write_text(grub, encoding="utf-8")
PY

grub-mkstandalone --format=x86_64-efi \
  --output="$w/BOOTX64.EFI" "boot/grub/grub.cfg=$w/grub.cfg"

bootdisk="$w/boot-fat.img"
truncate -s 96M "$bootdisk"
mkfs.vfat -F 32 -n GASLUXEFI "$bootdisk" >/dev/null
mmd -i "$bootdisk" ::/EFI
mmd -i "$bootdisk" ::/EFI/BOOT
mcopy -i "$bootdisk" "$w/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI

code=""
vars=""
for suffix in _4M ""; do
  c="/usr/share/OVMF/OVMF_CODE"$suffix".fd"
  v="/usr/share/OVMF/OVMF_VARS"$suffix".fd"
  if [ -f "$c" ] && [ -f "$v" ]; then code="$c"; vars="$v"; break; fi
done
[ -n "$code" ] && [ -n "$vars" ] || { echo "Missing OVMF firmware" >&2; exit 2; }
cp "$vars" "$w/OVMF_VARS.fd"

set +e
timeout --kill-after=2s 65s qemu-system-x86_64 \
  -machine q35,accel=tcg \
  -m 768 -display none -monitor none -no-reboot -boot order=c \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$w/OVMF_VARS.fd" \
  -device qemu-xhci \
  -drive if=none,format=raw,id=usbdisk,file="$bootdisk" \
  -device usb-storage,drive=usbdisk \
  -drive if=none,format=raw,id=storagedisk,file="$disk" \
  -device virtio-blk-pci,drive=storagedisk \
  -serial file:"$w/serial.log"
rc=$?
set -e

if ! grep -Fq GASLUX_ARCHISO_LOOPBACK_VERIFIED "$w/serial.log"; then
  echo "QEMU/OVMF did not resolve Archiso inside the NTFS disk ISO (exit=$rc)." >&2
  tail -c 5000 "$w/serial.log" >&2 || true
  exit 1
fi
echo "PASS: UEFI GRUB searched the expected NTFS UUID and accessed files inside the loopback ISO."
echo "NOT TESTED: actual CachyOS kernel boot, Windows dual boot, final installer, WinRE recovery."
