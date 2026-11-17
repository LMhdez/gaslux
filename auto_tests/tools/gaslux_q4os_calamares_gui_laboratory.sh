#!/usr/bin/env bash
# Q4OS graphical first-run dialog lab, SHA-bound VNC action; NO Calamares install.
# Official ISO is attached read-only through a disposable guest virtio block bus.
# No host devices, Windows, network, native Calamares execution, or disk partitioning by guest.
set -Eeuo pipefail

die() { printf '%s\n' "GASLUX_LIVE_BOOT_ERROR: $*" >&2; exit 1; }
[[ $# -eq 3 ]] || die 'Usage: gaslux_candidate_live_boot.sh popos|q4os ISO PINNED_SHA256'
distro="$1"
[[ "${GASLUX_Q4OS_GRAPHICS_LAB_ONLY:-}" == "1" && "${GITHUB_ACTIONS:-}" == "true" ]] ||
  die 'Explicit disposable GitHub Actions graphics lab authorization missing'
# Reject symlink inputs *before* canonicalization; realpath otherwise hides them.
[[ -f "$2" && ! -L "$2" ]] || die 'Refuse symlink/non-regular ISO'
iso="$(realpath -e -- "$2")"
digest="$3"
[[ "$distro" == q4os ]] || die 'Only the pinned Q4OS laboratory source is allowed'
launch_installer="${GASLUX_Q4OS_LAUNCH_INSTALLER:-no}"
[[ "$launch_installer" == yes || "$launch_installer" == no ]] ||
  die 'Unrecognized Q4OS GUI launch laboratory mode'
[[ "$digest" == '1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d' ]] ||
  die 'Official Q4OS 6.10 r2 SHA-256 is not the independently pinned digest'
printf '%s  %s\n' "$digest" "$iso" | sha256sum -c --status ||
  die 'Actual ISO bytes differ from independently pinned SHA-256'
for tool in qemu-system-x86_64 grub-mkstandalone mkfs.vfat mcopy mmd sgdisk dd timeout sudo vncdo; do
  command -v "$tool" >/dev/null || die "Missing laboratory tool: $tool"
done

work="$(mktemp -d -t gaslux-q4os-graphics-XXXXXX)"
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
    for path in "$work"/serial.log "$work"/grub.cfg "$work"/qemu.rc "$work"/vnc-*.png; do
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
  linux (\$source)/$kernel $boot console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.log_level=info systemd.unit=graphical.target systemd.setenv=KWIN_COMPOSE=N systemd.wants=serial-getty@ttyS0.service
  initrd (\$source)/$initrd
}
EOF
grub-mkstandalone --format=x86_64-efi --output="$work/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$work/grub.cfg"
# Create an actual GPT disk image containing one 128-MiB EFI System Partition.
# Raw FAT "superfloppy" media are not reliably boot-enumerated by QEMU/OVMF.
truncate -s 32G "$work/efi-disk.img"
sgdisk --zap-all --new=1:2048:+512M --typecode=1:EF00 \
  --change-name=1:GASLUX-LAB-ESP "$work/efi-disk.img" >/dev/null
truncate -s 512M "$work/efi-part.img"
mkfs.vfat -F 32 -n GASLUXLAB "$work/efi-part.img" >/dev/null
mmd -i "$work/efi-part.img" ::/EFI
mmd -i "$work/efi-part.img" ::/EFI/BOOT
mcopy -i "$work/efi-part.img" "$work/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
dd if="$work/efi-part.img" of="$work/efi-disk.img" bs=512 seek=2048 conv=notrunc status=none

echo "GASLUX_GUEST_DISTRO=$distro"
echo "GASLUX_GUEST_KERNEL=$kernel"
echo "GASLUX_GUEST_INITRD=$initrd"
echo 'GASLUX_GUEST_MEDIA=isolated-virtio-readonly-iso'
# QEMU/OVMF GRUB does not consistently enumerate the emulated CD-ROM on the
# hosted runner. Attach the independently SHA-256-verified hybrid ISO as a
# second, explicit read-only virtio-blk device instead (same as Pop!_OS lab).
# The first virtio image remains the temporary, guest-only ESP. No host devices.
[[ "$iso" != *,* ]] || die 'Unsafe ISO path delimiter for QEMU drive options'
iso_args=(-drive "if=none,id=officialiso,readonly=on,format=raw,file=$iso"
          -device virtio-blk-pci,drive=officialiso,bootindex=2)
qemu_accel=tcg
if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
  qemu_accel=kvm
fi
echo "GASLUX_Q4OS_ACCEL=$qemu_accel"
timeout --kill-after=5s 720s qemu-system-x86_64 \
  -machine "q35,accel=$qemu_accel" -cpu max -smp 2 -m 4096 \
  -display none -vnc 127.0.0.1:1 -vga virtio -monitor none -no-reboot -net none \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$work/nvram.fd" \
  -drive if=none,id=labefi,format=raw,file="$work/efi-disk.img" \
  -device virtio-blk-pci,drive=labefi,bootindex=1 \
  "${iso_args[@]}" \
  -boot order=c,menu=off \
  -serial "file:$work/serial.log" &
guest="$!"
guest_verified=0
frame_count=0
max_ticks=90
capture_every=18
# KVM guests boot faster than TCG; collect comparable GUI evidence sooner.
if [[ "$qemu_accel" == kvm ]]; then
  max_ticks=42
  capture_every=7
  if [[ "$launch_installer" == yes ]]; then max_ticks=56; fi
fi
# Reproduce the *exact* native Q4OS first-run language prompt captured in
# independent QEMU Actions #43964633501, artifact #14275594316. All six
# screenshots had the SAME SHA-256. Click OK ONLY after exact-byte comparison
# to that previously inspected 1280x800 screenshot. Otherwise ABORT input.
# This is NOT Calamares; no partition, account or install click is allowed.
expected_modal='da8d7c7f26051f0962152a99494001960f852f222104cb49be2a9962ef95aac8'
selected_modal=0
dismissed_modal=0
# Independently captured Q4OS desktop and its "Install Q4OS" icon from
# successful Actions #43990554360, screenshot #14287807199, 1280x800.
# Never click any installer "Install"/partition/confirmation buttons here.
expected_desktop='231a01a5e394937808d71080dbb4f1a8e9da3bc52e61d80e2e5cdebce8d638d7'
launcher_clicked=0
post_launcher_frame=0

for tick in $(seq 1 "$max_ticks"); do
  sleep 5
  if [[ -s "$work/serial.log" ]] &&
     grep -Eiq 'Linux version|Freeing unused kernel|systemd' "$work/serial.log"; then
    guest_verified=1
  fi
  if (( tick % capture_every == 0 )); then
    if timeout 20s vncdo -s 127.0.0.1:1 capture "$work/vnc-$tick.png"; then
      if [[ -s "$work/vnc-$tick.png" ]]; then
        frame_count=$((frame_count + 1))
        current="$(sha256sum "$work/vnc-$tick.png" | cut -d' ' -f1)"
        if [[ "$selected_modal" -eq 0 && "$current" == "$expected_modal" ]]; then
          printf 'GASLUX_Q4OS_PINNED_FIRST_RUN_PROMPT_VERIFIED=1280x800\n'
          timeout 20s vncdo -s 127.0.0.1:1 move 585 391 click 1 ||
            die 'Exact Q4OS first-run OK click failed'
          selected_modal=1
        elif [[ "$selected_modal" -eq 1 && "$current" != "$expected_modal" ]]; then
          dismissed_modal=1
          cp "$work/vnc-$tick.png" "$work/vnc-after-language.png"
          if [[ "$launch_installer" == yes && "$launcher_clicked" -eq 0 && "$current" == "$expected_desktop" ]]; then
            # First click closes the Q4OS welcome window, second *double*
            # click starts the already verified desktop "Install Q4OS" icon.
            # Neither of these is a Calamares install/partition confirmation.
            printf 'GASLUX_Q4OS_PINNED_DESKTOP_LAUNCHER_VERIFIED=1280x800\n'
            timeout 20s vncdo -s 127.0.0.1:1 \
              move 948 93 click 1 pause 1 move 57 39 click 1 pause 0.3 click 1 ||
              die 'SHA-verified native installer desktop icon click failed'
            launcher_clicked=1
          elif [[ "$launch_installer" == yes && "$launcher_clicked" -eq 1 && "$current" != "$expected_desktop" ]]; then
            post_launcher_frame=1
            cp "$work/vnc-$tick.png" "$work/vnc-after-installer-icon.png"
          fi
        fi
      fi
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
if [[ "$guest_verified" -eq 1 && "$frame_count" -gt 0 &&
      "$selected_modal" -eq 1 && "$dismissed_modal" -eq 1 ]] &&
   { [[ "$launch_installer" == no ]] ||
     [[ "$launcher_clicked" -eq 1 && "$post_launcher_frame" -eq 1 ]]; }; then
  echo 'PASS: Q4OS first-run modal and audited graphical desktop transitioned under SHA-bound VNC actions.'
  if [[ "$launch_installer" == yes ]]; then
    echo 'PASS: audited Install Q4OS desktop ICON was clicked and a subsequent VNC frame changed.'
    echo 'NOT PROVEN: Calamares executable actually started; screenshot must be reviewed.'
  fi
  echo "GASLUX_Q4OS_FRAME_COUNT=$frame_count"
  echo 'NOT PROVEN: native Calamares job execution, full installation, Linux/Windows dual boot or rollback.'
else
  tail -c 5000 "$work/serial.log" >&2 || true
  die "NO VERIFIED Q4OS GUI TRANSITION (QEMU status=$rc frames=$frame_count selected=$selected_modal dismissed=$dismissed_modal launched=$launcher_clicked after=$post_launcher_frame)"
fi
