#!/usr/bin/env bash
# Real pacstrap + installed boot, ONLY on private GitHub-hosted QEMU disk images.
set -Eeuo pipefail
[[ $# -eq 2 ]] || { echo 'Usage: script PINNED_ISO SHA256' >&2; exit 2; }
iso="$(realpath -e "$1")"
hash="$2"
[[ "$iso" == */cachyos.iso && -f "$iso" && ! -L "$iso" ]] || exit 2
[[ "$hash" =~ ^[0-9a-f]{64}$ ]] || exit 2
printf '%s  %s\n' "$hash" "$iso" | sha256sum -c --status || exit 1
[[ "$GITHUB_ACTIONS" == true && "$RUNNER_OS" == Linux ]] || {
  echo 'Refusing outside ephemeral GitHub Actions Linux runner'; exit 2;
}
for tool in sgdisk losetup mkfs.ext4 mkfs.vfat debugfs grub-mkstandalone grub-script-check qemu-system-x86_64 mcopy mmd python3 timeout; do
  command -v "$tool" >/dev/null || { echo "Missing $tool"; exit 2; }
done
w="$(mktemp -d -t gaslux-private-install-XXXXXXXX)"
loop=''
mounted_iso=0
vm_pid=''
save_evidence() {
  if [[ -v GASLUX_VM_EVIDENCE_DIR && -n "$GASLUX_VM_EVIDENCE_DIR" ]]; then
    mkdir -p "$GASLUX_VM_EVIDENCE_DIR"
    for f in live-serial.log firstboot-serial.log boot-report.json grub.cfg; do
      if [[ -f "$w/$f" ]]; then cp "$w/$f" "$GASLUX_VM_EVIDENCE_DIR/$f"; fi
    done
    ( cd "$GASLUX_VM_EVIDENCE_DIR" && sha256sum ./* > SHA256SUMS ) || true
  fi
}
cleanup() {
  if [[ -n "$vm_pid" ]]; then kill "$vm_pid" 2>/dev/null || true; fi
  if [[ -n "$loop" ]]; then sudo losetup -d "$loop" || true; fi
  if (( mounted_iso )); then sudo umount "$w/iso-mounted" || true; fi
  save_evidence
  rm -rf -- "$w"
}
trap cleanup EXIT
root_uuid="$(python3 -c 'import uuid;print(uuid.uuid4())')"
iso_uuid="$(python3 -c 'import uuid;print(uuid.uuid4())')"
run_id="gaslux-vm-$(python3 -c 'import secrets;print(secrets.token_hex(8))')"
mkdir -p "$w/iso-mounted"
free_kb="$(df -Pk "$w" | awk 'END {print $4}')"
(( free_kb > 8 * 1024 * 1024 )) || { echo 'Insufficient disposable runner disk space'; exit 1; }
# All guest disk paths are new regular files under the private temp directory.
truncate -s 5G "$w/iso.raw"
mkfs.ext4 -q -F -U "$iso_uuid" "$w/iso.raw"
debugfs -w -R "write $iso /cachyos.iso" "$w/iso.raw" > "$w/iso-write.log" 2>&1
debugfs -R "stat /cachyos.iso" "$w/iso.raw" > "$w/iso-stat.log" 2>&1
grep -Eq 'Size: [1-9][0-9]+' "$w/iso-stat.log" || exit 1
truncate -s 8G "$w/root.raw"
sgdisk --clear --new=1:2048:0 --typecode=1:8300 "$w/root.raw" >/dev/null
loop="$(sudo losetup --find --show --partscan "$w/root.raw")"
sudo udevadm settle || true
for _ in 1 2 3 4 5; do
  [[ -b "$loop"p1 ]] && break
  sleep 1
done
[[ -b "$loop"p1 ]] || { echo 'Virtual GPT root partition missing'; exit 1; }
sudo mkfs.ext4 -q -F -U "$root_uuid" "$loop"p1
printf '%s\n' "$run_id" > "$w/owner"
sudo debugfs -w -R "write $w/owner /.libertix-stage-owner" "$loop"p1 >/dev/null 2>&1
sudo losetup -d "$loop"
loop=''
truncate -s 192M "$w/esp.raw"
mkfs.vfat -F 32 -n GASLUXESP "$w/esp.raw" >/dev/null
truncate -s 64M "$w/control.raw"
mkfs.vfat -F 32 -n GASLUXCTL "$w/control.raw" >/dev/null
stage=assets/live/cachyos-stage-target.sh
guest=auto_tests/tools/cachyos_vm_guest_install.sh
stage_hash="$(sha256sum "$stage" | awk '{print $1}')"
printf 'RUN_ID=%q\nROOT_UUID=%q\nSTAGE_SHA256=%q\n' \
  "$run_id" "$root_uuid" "$stage_hash" > "$w/lab.env"
mcopy -i "$w/control.raw" "$w/lab.env" ::/lab.env
mcopy -i "$w/control.raw" "$stage" ::/stage.sh
mcopy -i "$w/control.raw" "$guest" ::/gaslux-run.sh
sudo mount -o ro,loop "$iso" "$w/iso-mounted"
mounted_iso=1
python3 auto_tests/tools/cachyos_generated_boot_config.py \
  "$iso" "$hash" "$iso_uuid" "$w/iso-mounted" "$w/grub.cfg" "$w/boot-report.json"
sudo umount "$w/iso-mounted"
mounted_iso=0
python3 - "$w/grub.cfg" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1])
lines=path.read_text().splitlines(keepends=True)
entries=[i for i,line in enumerate(lines) if line.startswith('    linux (gaslux_iso)/')]
if len(entries)!=1 or 'systemd.run=' in lines[entries[0]]:
    raise SystemExit('Unexpected backend GRUB kernel line')
i=entries[0]
if not lines[i].endswith('\n'): raise SystemExit('Kernel line lacks newline')
# systemd.run-generator targets default.target, but the real Gaslux live
# kernel line selects systemd.unit=multi-user.target. Without an explicit
# systemd.wants=kernel-command-line.service, the generated service is never
# started (proven by Actions 43948740731: ISO login but no installer).
# Mount FAT controls read-only and executable under /run/gaslux-control, never
# under /mnt: /mnt is the distinct rw ext4 installation mount namespace.
# A non-executable or missing script fails closed without any disk writes.
# No raw shell commands or physical disk identifiers enter this GRUB entry.
flags=(
    ' systemd.mount-extra=LABEL=GASLUXCTL:/run/gaslux-control:vfat:ro,exec'
    ' systemd.run=/run/gaslux-control/gaslux-run.sh'
    ' systemd.wants=kernel-command-line.service'
    ' systemd.run_success_action=none systemd.run_failure_action=none'
)
lines[i]=lines[i][:-1]+flags+'\n'
path.write_text(''.join(lines))
PY
grub-script-check "$w/grub.cfg"
grub-mkstandalone --format=x86_64-efi --output="$w/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$w/grub.cfg"
truncate -s 96M "$w/liveboot.raw"
mkfs.vfat -F 32 "$w/liveboot.raw" >/dev/null
mmd -i "$w/liveboot.raw" ::/EFI
mmd -i "$w/liveboot.raw" ::/EFI/BOOT
mcopy -i "$w/liveboot.raw" "$w/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
# Secure-Boot-CAPABLE OVMF with un-enrolled keys: guest still validates state 0.
code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
vars=/usr/share/OVMF/OVMF_VARS_4M.fd
[[ -f "$code" && -f "$vars" ]] || exit 2
cp "$vars" "$w/nvram-live.fd"
# GitHub-hosted Ubuntu x64 confirmed a real diskless QEMU KVM bootstrap in
# Actions 43966109996. Grant only this ephemeral runner user access and
# dynamically test KVM initialization. Preserve TCG as an explicit fallback.
accel=tcg
cpu=qemu64
if [[ -c /dev/kvm ]] && command -v setfacl >/dev/null 2>&1 &&
   sudo test -r /dev/kvm && sudo test -w /dev/kvm; then
  sudo setfacl -m "u:$(id -un):rw" /dev/kvm
  set +e
  timeout --kill-after=2s 3s qemu-system-x86_64 \
    -machine q35,accel=kvm,smm=on -cpu host -smp 2 -m 256 \
    -S -nodefaults -display none -monitor none -serial none \
    > "$w/kvm-probe.log" 2>&1
  kvm_probe_rc=$?
  set -e
  if (( kvm_probe_rc == 124 )); then
    accel=kvm
    cpu=host
  else
    echo "QEMU KVM unsupported in this runner ($kvm_probe_rc); fail-safe TCG fallback"
    tail -c 1200 "$w/kvm-probe.log" || true
  fi
fi
echo "GASLUX_QEMU_ACCELERATOR=$accel"

echo 'GASLUX_VM_LIVE_QEMU_START'
timeout --kill-after=5s 3300s qemu-system-x86_64 \
  -machine "q35,accel=$accel,smm=on" -cpu "$cpu" \
  -global driver=cfi.pflash01,property=secure,value=on \
  -smp 2 -m 6144 -display none -monitor none -no-reboot -boot order=c \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$w/nvram-live.fd" \
  -device qemu-xhci \
  -drive if=none,id=liveefi,format=raw,file="$w/liveboot.raw",readonly=on \
  -device usb-storage,drive=liveefi \
  -drive if=none,id=source,format=raw,file="$w/iso.raw",readonly=on \
  -device virtio-blk-pci,drive=source \
  -drive if=none,id=target,format=raw,file="$w/root.raw" \
  -device virtio-blk-pci,drive=target \
  -drive if=none,id=esp,format=raw,file="$w/esp.raw" \
  -device virtio-blk-pci,drive=esp \
  -drive if=none,id=control,format=raw,file="$w/control.raw",readonly=on \
  -device virtio-blk-pci,drive=control \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -serial "file:$w/live-serial.log" &
vm_pid=$!
for attempt in $(seq 1 655); do
  sleep 5
  # A booted live ISO with no running guest installation is NOT a pass.
  # Stop promptly if the systemd hook never executes (max 15 minutes).
  if (( attempt == 180 )) && ! grep -q 'GASLUX_VM_INSTALL_BEGIN' "$w/live-serial.log" 2>/dev/null; then
    echo 'FAIL: live Archiso never executed the authenticated QEMU-only installer'
    kill "$vm_pid" 2>/dev/null || true
    break
  fi
  # Human-reviewable milestones in Actions logs; a silent QEMU never counts
  # as a passed installation. Never interpret these logs as boot proof.
  if (( attempt % 12 == 0 )); then
    echo "GASLUX_VM_PROGRESS_SECONDS=$((attempt * 5))"
    grep -aE 'GASLUX_VM_|CACHYOS_STAGE_ERROR|pacstrap|error:|failed' "$w/live-serial.log" 2>/dev/null | tail -n 14 || true
  fi
  if grep -q 'GASLUX_VM_INSTALL_FAILED:' "$w/live-serial.log" 2>/dev/null; then
    kill "$vm_pid" 2>/dev/null || true
    break
  fi
  kill -0 "$vm_pid" 2>/dev/null || break
done
set +e
wait "$vm_pid"
live_rc=$?
set -e
vm_pid=''
if ! grep -Fq "GASLUX_VM_PACSTRAP_PASS:$run_id:$root_uuid" "$w/live-serial.log"; then
  echo "FAILED: pacstrap is not proven; QEMU status=$live_rc"
  tail -c 7000 "$w/live-serial.log" || true
  exit 1
fi
[[ "$live_rc" == 0 ]] || { echo 'Guest did not power off cleanly'; exit 1; }
echo 'GASLUX_VM_PACSTRAP_PROVEN'
# Reboot from the ACTUAL installed GRUB (ESP) and pacstrapped root alone.
# No live Archiso disk and no control medium exist in the second guest.
cp "$vars" "$w/nvram-installed.fd"
echo 'GASLUX_VM_INSTALLED_QEMU_START'
timeout --kill-after=5s 900s qemu-system-x86_64 \
  -machine "q35,accel=$accel,smm=on" -cpu "$cpu" \
  -global driver=cfi.pflash01,property=secure,value=on \
  -smp 2 -m 4096 -display none -monitor none -no-reboot -boot order=c \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$w/nvram-installed.fd" \
  -device qemu-xhci \
  -drive if=none,id=installedefi,format=raw,file="$w/esp.raw" \
  -device usb-storage,drive=installedefi \
  -drive if=none,id=installedroot,format=raw,file="$w/root.raw" \
  -device virtio-blk-pci,drive=installedroot \
  -serial "file:$w/firstboot-serial.log" &
vm_pid=$!
for _ in $(seq 1 175); do
  sleep 5
  if grep -q 'GASLUX_VM_FIRSTBOOT_FAILED:' "$w/firstboot-serial.log" 2>/dev/null; then
    kill "$vm_pid" 2>/dev/null || true
    break
  fi
  kill -0 "$vm_pid" 2>/dev/null || break
done
set +e
wait "$vm_pid"
boot_rc=$?
set -e
vm_pid=''
if ! grep -E "^GASLUX_VM_FIRSTBOOT_PASS:$run_id:$root_uuid:[0-9].*cachyos" \
     "$w/firstboot-serial.log"; then
  echo "FAILED: installed root did not verify first boot; QEMU=$boot_rc"
  tail -c 7000 "$w/firstboot-serial.log" || true
  exit 1
fi
[[ "$boot_rc" == 0 ]] || exit 1
echo 'GASLUX_VM_INSTALLED_FIRSTBOOT_PROVEN'
echo 'Windows absent: no dual boot or rollback has been tested.'
