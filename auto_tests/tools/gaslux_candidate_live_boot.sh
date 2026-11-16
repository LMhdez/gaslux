#!/usr/bin/env bash
# Disposable QEMU/OVMF real live-kernel smoke for Pop!_OS and Q4OS.
# Real ISO stays read-only on an emulated optical drive. This neither
# installs a target OS nor starts a Windows VM.
set -Eeuo pipefail

die() { printf '%s\n' "GASLUX_LIVE_BOOT_ERROR: $*" >&2; exit 1; }
[[ $# -eq 3 ]] || die 'Usage: gaslux_candidate_live_boot.sh popos|q4os ISO PINNED_SHA256'
distro="$1"
iso="$(realpath -e "$2")"
digest="$3"
[[ "$distro" == popos || "$distro" == q4os ]] || die 'Unknown backend'
[[ "$digest" =~ ^[a-f0-9]{64}$ ]] || die 'Missing pinned sha256'
[[ -f "$iso" && ! -L "$iso" ]] || die 'Refuse symlink/non-regular ISO'
printf '%s  %s\n' "$digest" "$iso" | sha256sum -c --status ||
  die 'Actual ISO bytes differ from independently pinned SHA-256'
for tool in qemu-system-x86_64 grub-mkstandalone mkfs.vfat mcopy mmd timeout sudo; do
  command -v "$tool" >/dev/null || die "Missing laboratory tool: $tool"
done

work="$(mktemp -d -t gaslux-candidate-live-XXXXXX)"
mounted=0
guest=''
cleanup() {
  if [[ -n "$guest" ]]; then
    kill "$guest" >/dev/null 2>&1 || true
    wait "$guest" >/dev/null 2>&1 || true
  fi
  if [[ "$mounted" -eq 1 ]]; then sudo umount "$work/iso-root" >/dev/null 2>&1 || true; fi
  if [[ -n "${GASLUX_CANDIDATE_BOOT_EVIDENCE_DIR:-}" ]]; then
    mkdir -p "$GASLUX_CANDIDATE_BOOT_EVIDENCE_DIR"
    for path in "$work"/serial.log "$work"/grub.cfg "$work"/qemu.rc; do
      [[ -f "$path" ]] && cp "$path" "$GASLUX_CANDIDATE_BOOT_EVIDENCE_DIR/" || true
    done
    (cd "$GASLUX_CANDIDATE_BOOT_EVIDENCE_DIR" &&
      sha256sum ./*.log ./*.cfg ./*.rc > evidence.sha256 2>/dev/null) || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir "$work/iso-root"
sudo mount -o loop,ro,nosuid,nodev,noexec "$iso" "$work/iso-root"
mounted=1
mount_type="$(findmnt -rn -M "$work/iso-root" -o FSTYPE)"
[[ "$mount_type" == iso9660 ]] || die 'Guest source is not an ISO9660 mount'

if [[ "$distro" == popos ]]; then
  boot='boot=casper'
  prefix=casper
  pairs=('casper/vmlinuz:casper/initrd' 'casper/vmlinuz:casper/initrd.gz')
else
  boot='boot=live components'
  prefix=live
  pairs=('live/vmlinuz:live/initrd.img' 'live/vmlinuz:live/initrd')
fi

kernel=''
initrd=''
for candidate in "${pairs[@]}"; do
  k="${candidate%%:*}"
  i="${candidate#*:}"
  if [[ -f "$work/iso-root/$k" && ! -L "$work/iso-root/$k" &&
        -f "$work/iso-root/$i" && ! -L "$work/iso-root/$i" ]]; then
    if [[ -n "$kernel" ]]; then die 'Multiple kernel/initramfs candidates'; fi
    kernel="$k"
    initrd="$i"
  fi
done
if [[ -z "$kernel" || -z "$initrd" ]]; then
  echo "Found ISO boot files:" >&2
  find "$work/iso-root/$prefix" -maxdepth 2 -type f 2>/dev/null |
    sed "s|$work/iso-root/||" | head -50 >&2 || true
  die 'Verified ISO boot kernel/initramfs pair not recognized'
fi
[[ "$kernel" =~ ^[A-Za-z0-9._/-]+$ && "$initrd" =~ ^[A-Za-z0-9._/-]+$ ]] ||
  die 'Unsafe kernel/initramfs path'
[[ -s "$work/iso-root/$kernel" && -s "$work/iso-root/$initrd" ]] ||
  die 'Kernel/initramfs is empty'
sudo umount "$work/iso-root"
mounted=0

code=''
vars=''
for suffix in _4M ''; do
  c="/usr/share/OVMF/OVMF_CODE${suffix}.fd"
  v="/usr/share/OVMF/OVMF_VARS${suffix}.fd"
  if [[ -f "$c" && -f "$v" ]]; then code="$c"; vars="$v"; break; fi
done
[[ -n "$code" && -n "$vars" ]] || die 'OVMF firmware not installed'
cp "$vars" "$work/nvram.fd"

cat > "$work/grub.cfg" <<EOF
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
set default=0
menuentry 'Gaslux $distro real live-kernel lab boot' {
  insmod iso9660
  insmod part_gpt
  search --no-floppy --file --set=source /$kernel
  if [ ! -f (\$source)/$initrd ]; then
    echo 'Pinned guest live initramfs not found'
    halt
  fi
  linux (\$source)/$kernel $boot console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.log_level=info systemd.unit=multi-user.target systemd.wants=serial-getty@ttyS0.service
  initrd (\$source)/$initrd
}
EOF
grub-mkstandalone --format=x86_64-efi --output="$work/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$work/grub.cfg"
truncate -s 128M "$work/efi.img"
mkfs.vfat -F 32 -n GASLUXLAB "$work/efi.img" >/dev/null
mmd -i "$work/efi.img" ::/EFI
mmd -i "$work/efi.img" ::/EFI/BOOT
mcopy -i "$work/efi.img" "$work/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI

echo "GASLUX_GUEST_DISTRO=$distro"
echo "GASLUX_GUEST_KERNEL=$kernel"
echo "GASLUX_GUEST_INITRD=$initrd"
# No host block devices are attached. ISO is emulated read-only CD-ROM.
timeout --kill-after=5s 320s qemu-system-x86_64 \
  -machine q35,accel=tcg -cpu max -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -net none \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$work/nvram.fd" \
  -device qemu-xhci \
  -drive if=none,id=labefi,format=raw,file="$work/efi.img" \
  -device usb-storage,drive=labefi \
  -drive if=none,id=labcd,format=raw,readonly=on,media=cdrom,file="$iso" \
  -device ide-cd,bus=ide.1,unit=0,drive=labcd \
  -serial "file:$work/serial.log" &
guest="$!"
guest_verified=0
for _ in $(seq 1 62); do
  sleep 5
  if [[ -s "$work/serial.log" ]]; then
    if grep -Eiq '(^|[^A-Za-z])login:|login: $' "$work/serial.log" &&
       grep -Eiq 'Linux version|Freeing unused kernel|systemd\[1\]' "$work/serial.log"; then
      guest_verified=1
      break
    fi
  fi
  kill -0 "$guest" >/dev/null 2>&1 || break
done
kill "$guest" >/dev/null 2>&1 || true
set +e
wait "$guest"
rc="$?"
set -e
printf '%s\n' "$rc" > "$work/qemu.rc"
if [[ "$guest_verified" -eq 1 ]]; then
  echo "PASS: real $distro live kernel and userspace reached QEMU serial login."
  echo 'NOT TESTED: installed target, Windows boot, updates, uninstall or rollback.'
else
  tail -c 5000 "$work/serial.log" >&2 || true
  die "NO REAL GUEST LOGIN PROOF (QEMU status=$rc); do not report successful live boot"
fi
