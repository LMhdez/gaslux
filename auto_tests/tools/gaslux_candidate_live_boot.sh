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
for tool in qemu-system-x86_64 grub-mkstandalone mkfs.vfat mcopy mmd sgdisk dd timeout sudo; do
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
    for path in "$work"/serial.log "$work"/pop-guest-console.log "$work"/grub.cfg "$work"/qemu.rc \
      "$work"/target-protected.before.sha256 "$work"/target-protected.after.sha256; do
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

kernel=''
initrd=''
if [[ "$distro" == popos ]]; then
  # Official signed Pop!_OS 24.04 media has a per-build casper directory.
  mapfile -t roots < <(find "$work/iso-root" -mindepth 1 -maxdepth 1 -type d \
    -name 'casper_pop-os_24.04_amd64_intel_*' -printf '%f\n' | sort)
  [[ ${#roots[@]} -eq 1 ]] || die 'Pop ISO has missing or ambiguous live-root directories'
  prefix="${roots[0]}"
  [[ "$prefix" =~ ^casper_pop-os_24[.]04_amd64_intel_[A-Za-z0-9_.-]+$ ]] ||
    die 'Unexpected System76 casper directory name'
  kernel="$prefix/vmlinuz.efi"
  initrd="$prefix/initrd.gz"
  boot="boot=casper live-media-path=/$prefix"
else
  # Debian/Q4OS native live media uses release-versioned vmlinuz/initrd pairs.
  mapfile -t kernels < <(find "$work/iso-root/live" -mindepth 1 -maxdepth 1 \
    -type f -name 'vmlinuz-*' -printf '%f\n' | sort)
  [[ ${#kernels[@]} -eq 1 ]] || die 'Q4OS ISO has missing or ambiguous kernel versions'
  suffix="${kernels[0]#vmlinuz}"
  [[ "$suffix" =~ ^-[0-9a-zA-Z.+_-]+$ ]] || die 'Unsafe Q4OS kernel version'
  kernel="live/${kernels[0]}"
  initrd="live/initrd.img$suffix"
  boot='boot=live components'
fi

if [[ -z "$kernel" || -z "$initrd" ]]; then
  echo "Found ISO boot files:" >&2
  find "$work/iso-root" -maxdepth 6 -type f \
    \( -iname '*vmlinuz*' -o -iname '*initrd*' -o -iname '*kernel*' -o -iname '*linux*' -o -iname '*.squashfs' \) \
    2>/dev/null | sed "s|$work/iso-root/||" | head -80 >&2 || true
  die 'Verified ISO boot kernel/initramfs pair not recognized'
fi
[[ "$kernel" =~ ^[A-Za-z0-9._/+\-]+$ && "$initrd" =~ ^[A-Za-z0-9._/+\-]+$ ]] ||
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

serial_boot_args='systemd.wants=serial-getty@ttyS0.service'
if [[ "${GASLUX_POP_GUEST_DISTINST_PROBE:-0}" == 1 ||
      "${GASLUX_POP_GUEST_DISTINST_TARGET_TEST:-0}" == 1 ]]; then
  [[ "$distro" == popos ]] || die 'Debug shell confined to Pop disposable lab'
  serial_boot_args='systemd.debug_shell=ttyS0 systemd.mask=serial-getty@ttyS0.service'
fi

cat > "$work/grub.cfg" <<EOF
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
set default=0
menuentry 'Gaslux $distro real live-kernel lab boot' {
  insmod iso9660
  insmod part_gpt
  if ! search --no-floppy --file --set=source /$kernel; then
    echo 'Verified live kernel is not visible on any guest block device'
    ls
    halt
  fi
  if [ ! -f (\$source)/$initrd ]; then
    echo 'Pinned guest live initramfs not found'
    halt
  fi
  linux (\$source)/$kernel $boot console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.log_level=info systemd.unit=multi-user.target $serial_boot_args
  initrd (\$source)/$initrd
}
EOF
grub-mkstandalone --format=x86_64-efi --output="$work/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$work/grub.cfg"
# Create an actual GPT disk image containing one 128-MiB EFI System Partition.
# Raw FAT "superfloppy" media are not reliably boot-enumerated by QEMU/OVMF.
truncate -s 256M "$work/efi-disk.img"
sgdisk --zap-all --new=1:2048:+128M --typecode=1:EF00 \
  --change-name=1:GASLUX-LAB-ESP "$work/efi-disk.img" >/dev/null
truncate -s 128M "$work/efi-part.img"
mkfs.vfat -F 32 -n GASLUXLAB "$work/efi-part.img" >/dev/null
mmd -i "$work/efi-part.img" ::/EFI
mmd -i "$work/efi-part.img" ::/EFI/BOOT
mcopy -i "$work/efi-part.img" "$work/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
guest_probe=0
target_probe=0
if [[ "${GASLUX_POP_GUEST_DISTINST_TARGET_TEST:-0}" == 1 ]]; then
  [[ "${GASLUX_POP_GUEST_DISTINST_PROBE:-0}" != 1 ]] ||
    die 'VM target test and CLI help probe are mutually exclusive'
  target_probe=1
fi
if [[ "${GASLUX_POP_GUEST_DISTINST_PROBE:-0}" == 1 || "$target_probe" -eq 1 ]]; then
  [[ "$distro" == popos ]] || die 'Native guest probe requires official Pop ISO'
  [[ "${GASLUX_POP_NATIVE_DISTINST_SHA256:-}" =~ ^[a-f0-9]{64}$ ]] ||
    die 'Official native distinst hash missing'
  guest_probe=1
  script="$PWD/auto_tests/tools/gaslux_popos_vm_guest_probe.sh"
  if [[ "$target_probe" -eq 1 ]]; then
    script="$PWD/auto_tests/tools/gaslux_popos_vm_target_test.sh"
  fi
  [[ -f "$script" && ! -L "$script" ]] || die 'Missing tracked VM-only guest probe'
  sha256sum "$script" | awk '{print $1 "  probe.sh"}' > "$work/probe.sha256"
  mcopy -i "$work/efi-part.img" "$script" ::/probe.sh
  mcopy -i "$work/efi-part.img" "$work/probe.sha256" ::/probe.sha256
fi
dd if="$work/efi-part.img" of="$work/efi-disk.img" bs=512 seek=2048 conv=notrunc status=none

# VM-only: synthetic GPT disk, containing fake protected Windows ESP + NTFS
# and an unrelated transaction-owned Linux root. No host devices are attached.
target_args=()
if [[ "$target_probe" -eq 1 ]]; then
  command -v mkfs.ntfs >/dev/null || die 'Missing mock Windows NTFS formatter'
  truncate -s 32G "$work/pop-target.raw"
  sgdisk --zap-all \
    --new=1:2048:+512M --typecode=1:EF00 --change-name=1:GASLUX-MOCK-WIN-ESP \
    --new=2:0:+512M --typecode=2:0700 --change-name=2:GASLUX-MOCK-WIN-NTFS \
    --new=3:0:+28G --typecode=3:8300 --change-name=3:GASLUX-OWNED-ROOT \
    "$work/pop-target.raw" >/dev/null
  for index in 1 2 3; do
    start="$(sgdisk --info="$index" "$work/pop-target.raw" |
      awk '/First sector:/ {print $3; exit}')"
    case "$index:$start" in
      1:2048|2:1050624|3:2099200) ;;
      *) die "Unexpected lab disk GPT layout: $index:$start" ;;
    esac
  done
  truncate -s 512M "$work/mock-esp.part"
  mkfs.vfat -F 32 -n GXMCKESP "$work/mock-esp.part" >/dev/null
  mmd -i "$work/mock-esp.part" ::/EFI
  mmd -i "$work/mock-esp.part" ::/EFI/Microsoft
  mmd -i "$work/mock-esp.part" ::/EFI/Microsoft/Boot
  printf 'GASLUX MOCK WINDOWS FILE, NOT A REAL BOOTLOADER\n' > "$work/mock-win.efi"
  mcopy -i "$work/mock-esp.part" "$work/mock-win.efi" ::/EFI/Microsoft/Boot/bootmgfw.efi
  truncate -s 512M "$work/mock-ntfs.part"
  mkfs.ntfs -F -Q -L GXMCKWIN "$work/mock-ntfs.part" >/dev/null
  dd if="$work/mock-esp.part" of="$work/pop-target.raw" \
    bs=1M seek=1 conv=notrunc status=none
  dd if="$work/mock-ntfs.part" of="$work/pop-target.raw" \
    bs=1M seek=513 conv=notrunc status=none
  rm -f -- "$work/mock-esp.part" "$work/mock-ntfs.part"
  sgdisk --backup="$work/target.gpt.before" "$work/pop-target.raw" >/dev/null
  {
    dd if="$work/pop-target.raw" bs=1M skip=1 count=512 status=none | sha256sum
    dd if="$work/pop-target.raw" bs=1M skip=513 count=512 status=none | sha256sum
  } > "$work/target-protected.before.sha256"
  target_args=(-drive "if=none,id=pop_target,format=raw,file=$work/pop-target.raw"
               -device virtio-blk-pci,drive=pop_target,serial=GASLUXPOPTARGET,bootindex=3)
  echo 'GASLUX_MOCK_WINDOWS_TARGET=ephemeral-qemu-gpt-only'
fi

echo "GASLUX_GUEST_DISTRO=$distro"
echo "GASLUX_GUEST_KERNEL=$kernel"
echo "GASLUX_GUEST_INITRD=$initrd"
# No host block devices are attached. The ESP and NVRAM are temporary.
# Only the Pop!_OS lab maps the SHA-256 verified official ISO read-only through
# virtio-blk; retain the original optical-device behavior for Q4OS experiments.
[[ "$iso" != *,* ]] || die 'Unsafe ISO path delimiter for QEMU drive options'
if [[ "$distro" == popos ]]; then
  iso_args=(-drive "if=none,id=officialiso,readonly=on,format=raw,file=$iso"
            -device virtio-blk-pci,drive=officialiso,bootindex=2)
else
  iso_args=(-cdrom "$iso")
fi
serial_args=(-serial "file:$work/serial.log")
if [[ "$guest_probe" -eq 1 ]]; then
  serial_args=(-chardev "socket,id=pop_serial,path=$work/pop-serial.sock,server=on,wait=off,logfile=$work/serial.log" -serial chardev:pop_serial)
fi
guest_timeout=375
if [[ "$target_probe" -eq 1 ]]; then guest_timeout=650; fi
timeout --kill-after=5s "${guest_timeout}s" qemu-system-x86_64 \
  -machine q35,accel=tcg -cpu max -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -net none \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$work/nvram.fd" \
  -drive if=none,id=labefi,format=raw,file="$work/efi-disk.img" \
  -device virtio-blk-pci,drive=labefi,bootindex=1 \
  "${iso_args[@]}" \
  "${target_args[@]}" \
  -boot order=c,menu=off \
  "${serial_args[@]}" &
guest="$!"
guest_verified=0
if [[ "$guest_probe" -eq 1 ]]; then
  set +e
  serial_mode=()
  if [[ "$target_probe" -eq 1 ]]; then serial_mode=(--target-test); fi
  python3 auto_tests/tools/gaslux_popos_guest_serial.py \
    --socket "$work/pop-serial.sock" \
    --trace "$work/pop-guest-console.log" \
    --distinst-sha256 "$GASLUX_POP_NATIVE_DISTINST_SHA256" \
    "${serial_mode[@]}"
  probe_rc=$?
  set -e
  if [[ "$probe_rc" -eq 0 ]]; then guest_verified=1; fi
else
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
fi
kill "$guest" >/dev/null 2>&1 || true
set +e
wait "$guest"
rc="$?"
set -e
printf '%s\n' "$rc" > "$work/qemu.rc"
if [[ "$target_probe" -eq 1 ]]; then
  sgdisk --backup="$work/target.gpt.after" "$work/pop-target.raw" >/dev/null
  {
    dd if="$work/pop-target.raw" bs=1M skip=1 count=512 status=none | sha256sum
    dd if="$work/pop-target.raw" bs=1M skip=513 count=512 status=none | sha256sum
  } > "$work/target-protected.after.sha256"
  cmp -s "$work/target-protected.before.sha256" "$work/target-protected.after.sha256" ||
    die 'VM mock Windows ESP or NTFS changed: do not authorize installation'
  cmp -s "$work/target.gpt.before" "$work/target.gpt.after" ||
    die 'VM GPT changed: native test is not safe for Windows'
  echo 'GASLUX_POP_MOCK_WINDOWS_PARTITIONS_UNCHANGED=1'
fi
if [[ "$guest_verified" -eq 1 ]]; then
  if [[ "$guest_probe" -eq 1 ]]; then
    if [[ "$target_probe" -eq 1 ]]; then
      echo 'PASS: native distinst --test completed; mock Windows ESP, NTFS and GPT unchanged.'
    else
      echo "PASS: native System76 distinst --help executed in verified disposable live QEMU guest."
    fi
  else
    echo "PASS: real $distro live kernel and userspace reached QEMU serial login."
  fi
  echo 'NOT TESTED: installed target, Windows boot, updates, uninstall or rollback.'
else
  tail -c 5000 "$work/serial.log" >&2 || true
  die "NO REAL GUEST LOGIN PROOF (QEMU status=$rc); do not report successful live boot"
fi
