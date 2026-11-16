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
            mkfs.vfat mcopy mmd python3 timeout grub-script-check; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done
w="$(mktemp -d -t cachyos-real-boot-XXXXXX)"
trap 'rm -rf "$w"' EXIT
# The signed integration CI supplies a pre-verified Ed25519 lab artifact.
# Fail closed on any missing/tampered artifact; do not fall back to the manually
# constructed smoke entry when signed mode was requested.
signed_mode=0
if [[ -n "${GASLUX_SIGNED_EVIDENCE_DIR:-}" ]]; then
  [[ "${GASLUX_LIVE_GUEST_PROBE:-0}" == 1 ]] || {
    echo 'Signed VM boot requires an observed in-guest kernel cmdline proof' >&2
    exit 2
  }
  uuid="$(python3 auto_tests/tools/cachyos_signed_grub_vm_config.py \
    --evidence-dir "$GASLUX_SIGNED_EVIDENCE_DIR" \
    --iso-sha256 "$hash" \
    --output-grub "$w/grub.cfg" \
    --output-boot-proof "$w/boot-args.json")"
  signed_mode=1
else
  uuid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
fi
# Guest installation requires a separate newly created QEMU target.
lab_install=0
lab_disks=()
lab_network=()
lab_timeout=380
if [[ "${GASLUX_LAB_FIRSTBOOT:-0}" == 1 ]]; then
  [[ "$signed_mode" == 1 && "${GASLUX_LIVE_GUEST_PROBE:-0}" == 1 ]] || {
    echo 'Refusing VM install without signed source and guest probe' >&2
    exit 2
  }
  command -v qemu-img >/dev/null || exit 2
  lab_install=1
  lab_timeout=2900
  qemu-img create -f qcow2 "$w/target.qcow2" 12G
  lab_disks=(-drive "if=none,id=gaslux_target,format=qcow2,file=$w/target.qcow2"
             -device "virtio-blk-pci,drive=gaslux_target,serial=GASLUXLABTARGET")
  lab_network=(-netdev user,id=gaslux_net
               -device virtio-net-pci,netdev=gaslux_net)
fi
disk="$w/ext4.img"
truncate -s 5G "$disk"
mkfs.ext4 -q -F -U "$uuid" "$disk"
debugfs -w -R "write $iso /cachyos.iso" "$disk" > "$w/write.log" 2>&1
debugfs -R "stat /cachyos.iso" "$disk" > "$w/stat.log" 2>&1
grep -Eq 'Size: [1-9][0-9]+' "$w/stat.log" || {
  echo 'No ISO in disposable virtual ext4 volume' >&2; exit 1;
}
if [[ "$signed_mode" -eq 0 ]]; then
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
fi
# The signed handoff must be the input to the actual EFI executable.
grub-script-check "$w/grub.cfg"
grub-mkstandalone --format=x86_64-efi --output="$w/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$w/grub.cfg"
fat="$w/boot.img"
truncate -s 96M "$fat"
mkfs.vfat -F 32 -n GASLUXLAB "$fat" >/dev/null
mmd -i "$fat" ::/EFI
mmd -i "$fat" ::/EFI/BOOT
mcopy -i "$fat" "$w/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
# In the explicit lab-only mode, inject an immutable, hash-checked copy of
# the actual guarded stage script on the VM's removable FAT boot disk.
if [[ "${GASLUX_LIVE_GUEST_PROBE:-0}" == 1 ]]; then
  stage="$PWD/assets/live/cachyos-stage-target.sh"
  guest_probe="$PWD/auto_tests/tools/cachyos_live_guest_readonly_probe.sh"
  [[ -f "$stage" && -f "$guest_probe" ]] || {
    echo 'Missing stage script or readonly guest probe' >&2; exit 2;
  }
  hash="$(sha256sum "$stage" | cut -d' ' -f1)"
  printf '%s  stage.sh\n' "$hash" > "$w/stage.sha256"
  mcopy -i "$fat" "$stage" ::/stage.sh
  mcopy -i "$fat" "$guest_probe" ::/probe.sh
  mcopy -i "$fat" "$w/stage.sha256" ::/stage.sha256
  if [[ "$signed_mode" -eq 1 ]]; then
    mcopy -i "$fat" "$w/boot-args.json" ::/boot-args.json
  fi
  if [[ "$lab_install" -eq 1 ]]; then
    lab_script="$PWD/auto_tests/tools/cachyos_guest_vm_only_install.sh"
    [[ -f "$lab_script" && ! -L "$lab_script" ]] || exit 2
    sha256sum "$lab_script" | awk '{print $1 "  install.sh"}' > "$w/install.sha256"
    mcopy -i "$fat" "$lab_script" ::/install.sh
    mcopy -i "$fat" "$w/install.sha256" ::/install.sha256
    updater="$PWD/auto_tests/tools/cachyos_vm_update_recovery_guest.sh"
    [[ -f "$updater" && ! -L "$updater" ]] || {
      echo 'Missing VM-only update recovery helper' >&2
      exit 2
    }
    sha256sum "$updater" | awk '{print $1 "  update.sh"}' > "$w/update.sha256"
    mcopy -i "$fat" "$updater" ::/update.sh
    mcopy -i "$fat" "$w/update.sha256" ::/update.sha256
  fi
fi
# The live preflight requires explicit SecureBoot=0 firmware evidence.
# The plain OVMF_CODE_4M.fd variant can omit the SecureBoot EFI variable
# entirely, making the test correctly fail as "unverifiable" even though
# unsigned code boots. Use SECURE-BOOT-CAPABLE OVMF with an EMPTY key store:
# enabled capability != active Secure Boot. Never change the guest's policy
# at runtime or weaken the production SecureBoot=0 check.
code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
vars=/usr/share/OVMF/OVMF_VARS_4M.fd
[[ -f "$code" && -f "$vars" && ! -L "$code" ]] || {
  echo 'Missing dedicated OVMF Secure Boot-capable code and empty key store' >&2
  exit 2
}
# Only this disposable VM uses the local OVMF variable template.
cp "$vars" "$w/nvram.fd"
echo 'OVMF lab mode: Secure Boot-capable firmware, fresh no-key NVRAM copy; SecureBoot=0 must still be verified IN the guest.'
serial_flags=(-serial "file:$w/serial.log")
if [[ "${GASLUX_LIVE_GUEST_PROBE:-0}" == 1 ]]; then
  serial_flags=(-chardev "socket,id=gaslux_serial,path=$w/guest-serial.sock,server=on,wait=off,logfile=$w/serial.log" -serial chardev:gaslux_serial)
fi
timeout --kill-after=5s "${lab_timeout}s" qemu-system-x86_64 \
  -machine q35,accel=tcg,smm=on -global driver=cfi.pflash01,property=secure,value=on \
  -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -boot order=c \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$w/nvram.fd" \
  -device qemu-xhci \
  -drive if=none,id=bootimg,format=raw,file="$fat" \
  -device usb-storage,drive=bootimg \
  -drive if=none,id=isoimg,format=raw,readonly=on,file="$disk" \
  -device virtio-blk-pci,drive=isoimg \
  "${lab_disks[@]}" "${lab_network[@]}" \
  "${serial_flags[@]}" &
vm_pid=$!
guest_proven=0
if [[ "${GASLUX_LIVE_GUEST_PROBE:-0}" == 1 ]]; then
  set +e
  guest_flags=()
  if [[ "$signed_mode" -eq 1 ]]; then guest_flags+=(--require-signed-entry); fi
  if [[ "$lab_install" -eq 1 ]]; then guest_flags+=(--run-lab-install); fi
  python3 auto_tests/tools/cachyos_live_guest_serial.py \
    --socket "$w/guest-serial.sock" --transcript "$w/guest-console.log" \
    --boot-timeout 345 "${guest_flags[@]}"
  guest_rc=$?
  set -e
  if [[ "$guest_rc" -eq 0 ]]; then guest_proven=1; fi
  kill "$vm_pid" 2>/dev/null || true
fi
# The pinned 260809 ISO boots with a quiet kernel console under OVMF.
# An earlier assertion looked only for "Linux version ..." and falsely
# rejected a guest that had actually reached the CachyOS serial login.
# Require an exact CachyOS login banner AND systemd's kernel/userspace
# startup timings; neither a GRUB echo nor finding the kernel file suffices.
if [[ "${GASLUX_LIVE_GUEST_PROBE:-0}" != 1 ]]; then
for _ in $(seq 1 76); do
  sleep 5
  if grep -Eq 'CachyOS [0-9]+\.[0-9]+\.[0-9]+-[0-9]+-cachyos-lts \(ttyS0\)' "$w/serial.log" 2>/dev/null &&
     grep -Fq 'CachyOS login:' "$w/serial.log" 2>/dev/null &&
     grep -Eq 'Startup finished in .* \(kernel\) \+ .* \(userspace\)' "$w/serial.log" 2>/dev/null; then
    kill "$vm_pid" 2>/dev/null || true
    break
  fi
  kill -0 "$vm_pid" 2>/dev/null || break
done
fi
set +e
wait "$vm_pid"
rc=$?
set -e
if [[ -n "${GASLUX_BOOT_EVIDENCE_DIR:-}" && -f "$w/serial.log" ]]; then
  mkdir -p "$GASLUX_BOOT_EVIDENCE_DIR"
  install -m 0600 "$w/serial.log" "$GASLUX_BOOT_EVIDENCE_DIR/cachyos-live-serial.log"
  if [[ "$signed_mode" -eq 1 ]]; then
    install -m 0600 "$w/grub.cfg" "$GASLUX_BOOT_EVIDENCE_DIR/cachyos-booted-signed-derived-grub.cfg"
    install -m 0600 "$w/boot-args.json" "$GASLUX_BOOT_EVIDENCE_DIR/cachyos-expected-boot-args.json"
  fi
  if [[ -s "$w/guest-console.log" ]]; then
    install -m 0600 "$w/guest-console.log" "$GASLUX_BOOT_EVIDENCE_DIR/cachyos-guest-probe-serial.log"
  fi
  (
    cd "$GASLUX_BOOT_EVIDENCE_DIR"
    sha256sum *.log > cachyos-live-serial.sha256
    if [[ "$signed_mode" -eq 1 ]]; then
      sha256sum *.cfg *.json > cachyos-signed-boot.sha256
    fi
  )
fi
if ! grep -Eq 'CachyOS [0-9]+\.[0-9]+\.[0-9]+-[0-9]+-cachyos-lts \(ttyS0\)' "$w/serial.log"; then
  echo "FAIL: pinned CachyOS LTS login banner not observed (QEMU status=$rc)" >&2
  tail -c 5000 "$w/serial.log" >&2 || true
  exit 1
fi
if ! grep -Fq 'CachyOS login:' "$w/serial.log"; then
  echo "INCOMPLETE: no real CachyOS live ttyS0 login prompt (QEMU status=$rc)" >&2
  tail -c 5000 "$w/serial.log" >&2 || true
  exit 1
fi
# In the interactive live-guest test, the root login and signed-stage
# preflight markers (enforced below) are stronger evidence of userspace
# than a formatting-specific systemd startup timing line. CachyOS 260809
# can print "Startup finished in 3.560s." with no "(kernel) + (userspace)".
if [[ "${GASLUX_LIVE_GUEST_PROBE:-0}" != 1 ]] &&
   ! grep -Eq 'Startup finished in .* \(kernel\) \+ .* \(userspace\)' "$w/serial.log"; then
  echo "INCOMPLETE: non-interactive live boot has no systemd startup timing evidence (QEMU status=$rc)" >&2
  tail -c 5000 "$w/serial.log" >&2 || true
  exit 1
fi
echo 'PASS: official CachyOS LTS kernel and systemd reached real serial login in QEMU/OVMF.'
if [[ "${GASLUX_LIVE_GUEST_PROBE:-0}" == 1 ]]; then
  # The Python serial controller has already independently matched BOTH
  # exact guest stdout lines after normalizing Archiso OSC terminal escapes.
  # A second unnormalized grep -Fx here falsely rejects genuine output.
  [[ "$guest_proven" -eq 1 ]] || {
    echo 'FAIL: guarded live --check OR explicit EFI SecureBoot=0 evidence missing' >&2
    exit 1
  }
  [[ -s "$w/guest-console.log" ]] || {
    echo 'FAIL: missing actual guest serial transcript' >&2
    exit 1
  }
  echo 'PASS: guarded CachyOS live --check, pacstrap dependencies and SecureBoot=0 efivar evidence.'
  if [[ "$signed_mode" -eq 1 ]]; then
    echo 'PASS: guest /proc/cmdline matched the host-verified ephemeral Ed25519 GRUB handoff.'
  fi
fi
if [[ "$lab_install" -eq 1 ]]; then
  echo 'GASLUX_LAB_STAGE_COMPLETE: now BOOT ONLY target qcow2; no live ISO and no boot FAT.'
  cp "$vars" "$w/installed-nvram.fd"
  timeout --kill-after=5s 430s qemu-system-x86_64 \
    -machine q35,accel=tcg,smm=on \
    -global driver=cfi.pflash01,property=secure,value=on \
    -smp 2 -m 4096 -display none -monitor none -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$code" \
    -drive if=pflash,format=raw,file="$w/installed-nvram.fd" \
    -drive if=none,id=only_target,format=qcow2,file="$w/target.qcow2" \
    -device virtio-blk-pci,drive=only_target,serial=GASLUXLABTARGET,bootindex=1 \
    -serial "file:$w/installed-serial.log" &
  installed_pid=$!
  installed_success=0
  for _ in $(seq 1 84); do
    sleep 5
    if [[ -f "$w/installed-serial.log" ]] &&
       tr -d '\r' < "$w/installed-serial.log" |
         grep -Fxq 'GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1'; then
      installed_success=1
      break
    fi
    kill -0 "$installed_pid" 2>/dev/null || break
  done
  kill "$installed_pid" 2>/dev/null || true
  wait "$installed_pid" || true
  if [[ -n "${GASLUX_BOOT_EVIDENCE_DIR:-}" && -f "$w/installed-serial.log" ]]; then
    install -m 0600 "$w/installed-serial.log" \
      "$GASLUX_BOOT_EVIDENCE_DIR/cachyos-installed-firstboot-serial.log"
    ( cd "$GASLUX_BOOT_EVIDENCE_DIR"
      sha256sum cachyos-installed-firstboot-serial.log > cachyos-firstboot.sha256 )
  fi
  if [[ "$installed_success" -ne 1 ]] ||
     tr -d '\r' < "$w/installed-serial.log" |
       grep -Fq 'GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_FAIL:'; then
    echo 'FAIL: installed CachyOS did not prove first boot from virtual disk' >&2
    tail -c 6000 "$w/installed-serial.log" >&2 || true
    exit 1
  fi
  echo 'PASS: independent installed CachyOS LTS kernel, ext4 root and GRUB EFI boot.'
  if [[ "${GASLUX_LAB_UPDATE_ROLLBACK:-0}" == 1 ]]; then
    [[ -n "${GASLUX_BOOT_EVIDENCE_DIR:-}" ]] || {
      echo 'VM update/recovery requires an evidence directory' >&2
      exit 2
    }
    bash auto_tests/tools/cachyos_qemu_update_rollback.sh \
      "$w/target.qcow2" "$code" "$vars" "$GASLUX_BOOT_EVIDENCE_DIR"
  fi
  echo 'NOT TESTED: full desktop, Windows dual boot, production rollback or hardware.'
else
  echo 'NOT TESTED: installed CachyOS, Windows dual boot, or Windows recovery.'
fi
