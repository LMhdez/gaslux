#!/usr/bin/env bash
# Prove QEMU/OVMF 'once=d,order=c' from two synthetic GRUB EFI media only.
# Windows ISO, Windows target disk and production firmware are NOT used.
set -Eeuo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${RUNNER_OS:-}" == Linux && "${GITHUB_REPOSITORY:-}" == LMhdez/gaslux &&
   "$(uname -m)" == x86_64 ]] || {
  echo "Refusing one-shot OVMF smoke outside trusted GitHub-hosted CI" >&2
  exit 2
}
[[ -c /dev/kvm && ! -L /dev/kvm ]] || exit 2
for cmd in qemu-system-x86_64 grub-mkrescue grub-mkstandalone \
           sgdisk mformat mmd mcopy timeout python3; do
  command -v "$cmd" >/dev/null || exit 2
done
[[ "${RUNNER_TEMP:-}" == /home/runner/work/_temp ]] || exit 2
work="$(mktemp -d -p "$RUNNER_TEMP" gaslux-win-x64-one-shot-XXXXXX)"
[[ -d "$work" && ! -L "$work" ]] || exit 2
trap 'rm -rf -- "$work"' EXIT

mkdir -p "$work/iso-root/boot/grub"
cat >"$work/iso-root/boot/grub/grub.cfg" <<'GRUB'
serial --unit=0 --speed=115200
terminal_output serial
echo GASLUX_ONESHOT_INITIAL_DVD_GRUB_UEFI=1
reboot
GRUB
grub-mkrescue --xorriso=xorriso -o "$work/first-dvd.iso" \
  "$work/iso-root" >/dev/null 2>"$work/grub-mkrescue.err"

cat >"$work/disk.cfg" <<'GRUB'
serial --unit=0 --speed=115200
terminal_output serial
echo GASLUX_ONESHOT_SECOND_DISK_GRUB_UEFI=1
sleep 12
halt
GRUB
grub-mkstandalone -O x86_64-efi -o "$work/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$work/disk.cfg"
# Model the Windows installation target as a *real GPT with ESP* on
# a SATA hard drive, never as an unpartitioned removable USB FAT image.
truncate -s 128M "$work/only-synthetic-gpt-sata.img"
sgdisk --clear --new=1:2048:+96M --typecode=1:EF00 \
  "$work/only-synthetic-gpt-sata.img" >/dev/null
fat_at_esp="$work/only-synthetic-gpt-sata.img@@1048576"
mformat -i "$fat_at_esp" -F -v GASLUXVM ::
mmd -i "$fat_at_esp" ::/EFI ::/EFI/BOOT
mcopy -i "$fat_at_esp" \
  "$work/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI

cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/vars.fd"
set +e
timeout -s TERM -k 3 105s qemu-system-x86_64 \
    -machine q35,accel=kvm,smm=on \
    -global driver=cfi.pflash01,property=secure,value=on \
    -cpu host -smp 2 -m 1024 \
    -display none -vga std -monitor none -net none \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
    -drive "if=pflash,format=raw,file=$work/vars.fd" \
    -device ich9-ahci,id=lab_sata \
    -drive "if=none,id=synthetic_disk,format=raw,file=$work/only-synthetic-gpt-sata.img" \
    -device ide-hd,drive=synthetic_disk,bus=lab_sata.0 \
    -drive "if=none,id=synthetic_dvd,media=cdrom,readonly=on,format=raw,file=$work/first-dvd.iso" \
    -device ide-cd,drive=synthetic_dvd,bus=lab_sata.1 \
    -boot order=c,once=d \
    -serial "file:$work/serial.log" \
    >"$work/qemu-stdout.log" 2>"$work/qemu-stderr.log"
rc=$?
set -e
python3 - "$work/serial.log" "$rc" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
rc = int(sys.argv[2])
if not p.is_file():
    raise SystemExit(f"QEMU produced no guest serial (exit={rc})")
data = p.read_bytes()
dvd = b"GASLUX_ONESHOT_INITIAL_DVD_GRUB_UEFI=1"
disk = b"GASLUX_ONESHOT_SECOND_DISK_GRUB_UEFI=1"
if data.count(dvd) != 1 or data.count(disk) != 1 or data.index(dvd) >= data.index(disk):
    print(data[-16000:].decode(errors="replace"))
    raise SystemExit(
        f"one-shot UEFI DVD -> subsequent disk boot was not proven (exit={rc})"
    )
print("GASLUX_SYNTHETIC_OVMF_ONE_SHOT_DVD_THEN_DISK_BOOT_PASS=1")
print("NOTE: both boot media contained only synthetic GRUB, no Windows.")
PY
