#!/usr/bin/env bash
# Prove controlled QEMU/OVMF two-process DVD then disk boot with synthetic EFI.
# Windows ISO, Windows target disk and production firmware are NOT used.
set -Eeuo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${RUNNER_OS:-}" == Linux && "${GITHUB_REPOSITORY:-}" == LMhdez/gaslux &&
   "$(uname -m)" == x86_64 ]] || {
  echo "Refusing two-stage OVMF smoke outside trusted GitHub-hosted CI" >&2
  exit 2
}
[[ -c /dev/kvm && ! -L /dev/kvm ]] || exit 2
for cmd in qemu-system-x86_64 grub-mkrescue grub-mkstandalone \
           sgdisk mformat mmd mcopy timeout python3; do
  command -v "$cmd" >/dev/null || exit 2
done
[[ "${RUNNER_TEMP:-}" == /home/runner/work/_temp ]] || exit 2
work="$(mktemp -d -p "$RUNNER_TEMP" gaslux-win-x64-two-stage-XXXXXX)"
[[ -d "$work" && ! -L "$work" ]] || exit 2
trap 'rm -rf -- "$work"' EXIT

mkdir -p "$work/iso-root/boot/grub"
cat >"$work/iso-root/boot/grub/grub.cfg" <<'GRUB'
serial --unit=0 --speed=115200
terminal_output serial
echo GASLUX_TWOSTAGE_INITIAL_DVD_GRUB_UEFI=1
reboot
GRUB
grub-mkrescue --xorriso=xorriso -o "$work/first-dvd.iso" \
  "$work/iso-root" >/dev/null 2>"$work/grub-mkrescue.err"

cat >"$work/disk.cfg" <<'GRUB'
serial --unit=0 --speed=115200
terminal_output serial
echo GASLUX_TWOSTAGE_SECOND_DISK_GRUB_UEFI=1
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
# Stage 1 boots ONLY the trusted synthetic DVD and new GPT SATA disk. QEMU
# exits on the EFI GRUB reboot instead of returning to the DVD a second time.
set +e
timeout -s TERM -k 3 45s qemu-system-x86_64 \
    -machine q35,accel=kvm,smm=on \
    -global driver=cfi.pflash01,property=secure,value=on \
    -cpu host -smp 2 -m 1024 \
    -display none -vga std -monitor none -net none -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
    -drive "if=pflash,format=raw,file=$work/vars.fd" \
    -device ich9-ahci,id=lab_sata \
    -drive "if=none,id=synthetic_disk,format=raw,file=$work/only-synthetic-gpt-sata.img" \
    -device ide-hd,drive=synthetic_disk,bus=lab_sata.0 \
    -drive "if=none,id=synthetic_dvd,media=cdrom,readonly=on,format=raw,file=$work/first-dvd.iso" \
    -device ide-cd,drive=synthetic_dvd,bus=lab_sata.1 \
    -boot order=d \
    -serial "file:$work/dvd-serial.log" \
    >"$work/dvd-stdout.log" 2>"$work/dvd-stderr.log"
rc_dvd=$?
set -e
if [[ "$rc_dvd" != 0 ]]; then
  echo "First guest did not exit cleanly after its explicit EFI reboot (rc=$rc_dvd)" >&2
  tail -c 2500 "$work/dvd-serial.log" >&2 || true
  exit 1
fi
grep -Fq GASLUX_TWOSTAGE_INITIAL_DVD_GRUB_UEFI=1 "$work/dvd-serial.log"

# Stage 2 intentionally starts a completely new VM with the owned GPT SATA
# disk and private OVMF state, but NO DVD or answer-file media AT ALL.
# No stale ISO can be booted, regardless of the firmware's BootOrder.
set +e
timeout -s TERM -k 3 45s qemu-system-x86_64 \
    -machine q35,accel=kvm,smm=on \
    -global driver=cfi.pflash01,property=secure,value=on \
    -cpu host -smp 2 -m 1024 \
    -display none -vga std -monitor none -net none \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
    -drive "if=pflash,format=raw,file=$work/vars.fd" \
    -device ich9-ahci,id=lab_sata \
    -drive "if=none,id=synthetic_disk,format=raw,file=$work/only-synthetic-gpt-sata.img" \
    -device ide-hd,drive=synthetic_disk,bus=lab_sata.0 \
    -boot order=c \
    -serial "file:$work/disk-serial.log" \
    >"$work/disk-stdout.log" 2>"$work/disk-stderr.log"
rc_disk=$?
set -e
python3 - "$work/dvd-serial.log" "$work/disk-serial.log" "$rc_disk" <<'PY'
from pathlib import Path
import sys
first, second = (Path(sys.argv[i]).read_bytes() for i in (1, 2))
disk_rc = int(sys.argv[3])
dvd = b"GASLUX_TWOSTAGE_INITIAL_DVD_GRUB_UEFI=1"
disk = b"GASLUX_TWOSTAGE_SECOND_DISK_GRUB_UEFI=1"
if first.count(dvd) != 1 or disk in first:
    raise SystemExit("first DVD guest did not reboot exactly once")
if second.count(disk) != 1 or dvd in second:
    print(second[-6000:].decode(errors="replace"))
    raise SystemExit(
        f"second fresh OVMF guest did not boot the same GPT ESP without DVD (rc={disk_rc})"
    )
print("GASLUX_SYNTHETIC_OVMF_TWO_STAGE_DVD_EXIT_AND_DISK_REBOOT_PASS=1")
print("The second QEMU instance has NO Windows ISO and NO installer media.")
PY
