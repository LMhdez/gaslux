#!/usr/bin/env bash
# Non-production mock-Windows GPT experiment: authentic Pop distinst -> native
# systemd-boot -> OVMF restart. All disks are new disposable QEMU image files.
set -Eeuo pipefail
die() { printf 'GASLUX_POP_NATIVE_FULL_VM_ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${GASLUX_POP_NATIVE_FULL_VM:-0}" == 1 &&
   "${GASLUX_POP_NATIVE_MOCK_WINDOWS_VM:-0}" == 1 &&
   "${GITHUB_ACTIONS:-}" == true && "${CI:-}" == true ]] ||
  die 'This destructive VM-only lab is GitHub Actions opt-in only'
[[ $# == 3 ]] || die 'Usage: script VERIFIED_ISO ISO_SHA256 DISTINST_SHA256'
iso="$(realpath -e "$1")"
digest="$2"
agent="$3"
[[ -f "$iso" && ! -L "$iso" && "$iso" != *,* ]] ||
  die 'ISO must be a regular verified file without unsafe QEMU separators'
[[ "$digest" =~ ^[a-f0-9]{64}$ && "$agent" =~ ^[a-f0-9]{64}$ ]] ||
  die 'ISO or native agent digest not pinned'
printf '%s  %s\n' "$digest" "$iso" | sha256sum -c --status ||
  die 'Actual ISO bytes differ from pinned signed manifest'
[[ -d "${RUNNER_TEMP:-}" && ! -L "$RUNNER_TEMP" ]] ||
  die 'Expected GitHub disposable runner temporary directory missing'
for binary in qemu-system-x86_64 grub-mkstandalone mkfs.vfat mcopy mmd \
  sgdisk dd timeout sudo sha256sum python3 setfacl; do
  command -v "$binary" >/dev/null || die "Missing disposable VM tool: $binary"
done
# Runner /dev/kvm permissions can be reset between independent QEMU
# processes. Revalidate and regrant the runner-only ACL before EACH VM.
# Never fall back to TCG: that would make this first-boot claim unbounded.
prepare_hosted_kvm() {
  [[ -c /dev/kvm ]] || die 'Hosted runner KVM device unavailable'
  sudo setfacl -m "u:$(id -un):rw" /dev/kvm ||
    die 'Could not grant runner KVM permission'
  [[ -r /dev/kvm && -w /dev/kvm ]] ||
    die 'Hosted runner KVM access denied; no TCG fallback'
}
prepare_hosted_kvm

work="$(mktemp -d "$RUNNER_TEMP/gaslux-pop-native-mock-XXXXXX")"
guest=''
mounted=0
cleanup() {
  if [[ -n "$guest" ]]; then
    kill "$guest" >/dev/null 2>&1 || true
    wait "$guest" >/dev/null 2>&1 || true
  fi
  if [[ "$mounted" == 1 ]]; then
    sudo umount "$work/iso-root" >/dev/null 2>&1 || true
  fi
  if [[ -n "${GASLUX_POP_FULL_VM_EVIDENCE_DIR:-}" ]]; then
    mkdir -p "$GASLUX_POP_FULL_VM_EVIDENCE_DIR"
    for name in grub.cfg live.serial.log live.console.trace installed.serial.log \
      installed.normalized.log target-before.txt target-after.txt kernel-path.txt install-qemu.exit \
      installed-qemu.exit owned-gpt-before.json owned-gpt-after.json \
      owned-gpt-proof.txt owned-gpt-postboot.json owned-gpt-postboot-proof.txt; do
      [[ -f "$work/$name" ]] &&
        cp "$work/$name" "$GASLUX_POP_FULL_VM_EVIDENCE_DIR/" || true
    done
    (
      cd "$GASLUX_POP_FULL_VM_EVIDENCE_DIR"
      sha256sum ./*.txt ./*.log ./*.trace ./*.cfg ./*.exit ./*.json > evidence.sha256 2>/dev/null
    ) || true
  fi
  [[ "$work" == "$RUNNER_TEMP"/gaslux-pop-native-mock-* ]] ||
    die 'Unexpected temporary lab deletion path'
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir "$work/iso-root"
sudo mount -o loop,ro,nosuid,nodev,noexec "$iso" "$work/iso-root"
mounted=1
[[ "$(findmnt -rn -M "$work/iso-root" -o FSTYPE)" == iso9660 ]] ||
  die 'Verified media is not ISO9660'
mapfile -t roots < <(
  find "$work/iso-root" -mindepth 1 -maxdepth 1 -type d \
    -name 'casper_pop-os_24.04_amd64_intel_*' -printf '%f\n' | sort
)
[[ "${#roots[@]}" == 1 ]] || die 'Official Pop ISO live root ambiguous'
prefix="${roots[0]}"
[[ "$prefix" =~ ^casper_pop-os_24[.]04_amd64_intel_[A-Za-z0-9_.-]+$ ]] ||
  die 'Untrusted source casper path'
kernel="$prefix/vmlinuz.efi"
initrd="$prefix/initrd.gz"
[[ -s "$work/iso-root/$kernel" && -s "$work/iso-root/$initrd" ]] ||
  die 'GPG-verified ISO live kernel/initrd absent'
printf 'kernel=%s\ninitrd=%s\n' "$kernel" "$initrd" > "$work/kernel-path.txt"
sudo umount "$work/iso-root"
mounted=0

# Use Secure Boot CAPABLE firmware but CLEAN, keyless VARS in this VM.
# OVMF_CODE_4M.fd can omit SecureBoot efivars entirely; never infer disabled.
code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
vars=/usr/share/OVMF/OVMF_VARS_4M.fd
[[ -f "$code" && -f "$vars" ]] ||
  die 'No matching Secure Boot-capable OVMF firmware and blank VARS'
[[ "$vars" != *.ms.fd ]] || die 'Enrolled-key firmware variables forbidden'
cp "$vars" "$work/nvram-live.fd"
cp "$vars" "$work/nvram-installed.fd"

cat > "$work/grub.cfg" <<GRUB
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
set default=0
menuentry 'Gaslux isolated native Pop installer lab' {
  insmod iso9660
  insmod part_gpt
  if ! search --no-floppy --file --set=source /$kernel; then
    echo 'Pinned Pop kernel not available in guest'
    halt
  fi
  if [ ! -f (\$source)/$initrd ]; then
    echo 'Pinned Pop initrd not found'
    halt
  fi
  linux (\$source)/$kernel boot=casper live-media-path=/$prefix console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.unit=multi-user.target systemd.debug_shell=ttyS0 systemd.mask=serial-getty@ttyS0.service
  initrd (\$source)/$initrd
}
GRUB
grub-mkstandalone --format=x86_64-efi \
  --output="$work/BOOTX64.EFI" "boot/grub/grub.cfg=$work/grub.cfg"

# Fresh, disposable EFI control disk: NEVER reused as the installed ESP.
truncate -s 256M "$work/lab-efi.raw"
sgdisk --zap-all --new=1:2048:+128M --typecode=1:EF00 \
  --change-name=1:GASLUX-LAB-ONLY "$work/lab-efi.raw" >/dev/null
truncate -s 128M "$work/control-esp.img"
mkfs.vfat -F 32 -n GASLUXLAB "$work/control-esp.img" >/dev/null
mmd -i "$work/control-esp.img" ::/EFI
mmd -i "$work/control-esp.img" ::/EFI/BOOT
mcopy -i "$work/control-esp.img" "$work/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
for source in gaslux_popos_mock_windows_full_install_guest.sh \
  gaslux_popos_mock_windows_firstboot_guest.sh; do
  [[ -f "auto_tests/tools/$source" && ! -L "auto_tests/tools/$source" ]] ||
    die "Missing tracked VM-only installer script: $source"
done
mcopy -i "$work/control-esp.img" \
  auto_tests/tools/gaslux_popos_mock_windows_full_install_guest.sh ::/install.sh
mcopy -i "$work/control-esp.img" \
  auto_tests/tools/gaslux_popos_mock_windows_firstboot_guest.sh ::/firstboot.sh
# Bind the trusted native agent hash to the same SHA-checked read-only control
# disk, not a long shell command sent during kernel/startup console activity.
printf '%s\n' "$agent" > "$work/agent.sha256"
mcopy -i "$work/control-esp.img" "$work/agent.sha256" ::/agent.sha256
(
  cd auto_tests/tools
  sha256sum gaslux_popos_mock_windows_full_install_guest.sh \
    gaslux_popos_mock_windows_firstboot_guest.sh
) | sed -e 's/gaslux_popos_mock_windows_full_install_guest.sh/install.sh/' \
        -e 's/gaslux_popos_mock_windows_firstboot_guest.sh/firstboot.sh/' \
    > "$work/lab.sha256"
printf '%s  agent.sha256\n' "$(sha256sum "$work/agent.sha256" | awk '{print $1}')" >> "$work/lab.sha256"
mcopy -i "$work/control-esp.img" "$work/lab.sha256" ::/lab.sha256
dd if="$work/control-esp.img" of="$work/lab-efi.raw" \
  bs=1M seek=1 conv=notrunc status=none
rm -f -- "$work/control-esp.img"

# New disposable target with two MOCK Windows partitions (not bootable
# Windows) and separate Gaslux-owned ESP/root. Native distinst receives ONLY
# partition 3 (reuse, no format) and partition 4 (ext4 target).
target="$work/pop-target.raw"
truncate -s 32G "$target"
sgdisk --zap-all \
  --new=1:2048:+256M --typecode=1:EF00 --change-name=1:MOCK-WINDOWS-ESP \
  --new=2:0:+2048M --typecode=2:0700 --change-name=2:MOCK-WINDOWS-NTFS \
  --new=3:0:+1024M --typecode=3:EF00 --change-name=3:GASLUX-OWNED-ESP \
  --new=4:0:+26G --typecode=4:8300 --change-name=4:GASLUX-OWNED-ROOT \
  "$target" >/dev/null
for geometry in '1:2048' '2:526336' '3:4720640' '4:6817792'; do
  part="${geometry%%:*}"
  expected="${geometry#*:}"
  actual="$(sgdisk --info="$part" "$target" | awk '/First sector:/ {print $3; exit}')"
  [[ "$actual" == "$expected" ]] || die "Mock target partition $part moved"
done
sgdisk --print "$target" > "$work/target-before.txt"

# Mock Windows ESP: deliberately NO /EFI/BOOT/BOOTX64.EFI, so the native
# Pop ESP's fallback loader is the only bootable candidate on cold OVMF boot.
truncate -s 256M "$work/mock-windows-esp.img"
mkfs.vfat -F 32 -n MOCKWINESP "$work/mock-windows-esp.img" >/dev/null
mmd -i "$work/mock-windows-esp.img" ::/EFI
mmd -i "$work/mock-windows-esp.img" ::/EFI/Microsoft
mmd -i "$work/mock-windows-esp.img" ::/EFI/Microsoft/Boot
printf 'NOT AN EFI EXECUTABLE - GASLUX MOCK WINDOWS ONLY\\n' > "$work/mock-bootmgfw.efi"
mcopy -i "$work/mock-windows-esp.img" "$work/mock-bootmgfw.efi" \
  ::/EFI/Microsoft/Boot/bootmgfw.efi
dd if="$work/mock-windows-esp.img" of="$target" bs=1M seek=1 \
  conv=notrunc,sparse status=none

# A formatted, completely synthetic NTFS partition: no Windows OS/data.
truncate -s 2048M "$work/mock-windows-ntfs.img"
mkfs.ntfs -F -Q -L MOCKWINNTFS "$work/mock-windows-ntfs.img" >/dev/null
dd if="$work/mock-windows-ntfs.img" of="$target" bs=1M seek=257 \
  conv=notrunc,sparse status=none

truncate -s 1024M "$work/owned-esp.img"
mkfs.vfat -F 32 -n GXPOPMOCK "$work/owned-esp.img" >/dev/null
dd if="$work/owned-esp.img" of="$target" bs=1M seek=2305 \
  conv=notrunc,sparse status=none
rm -f -- "$work/mock-windows-esp.img" "$work/mock-windows-ntfs.img" \
  "$work/mock-bootmgfw.efi" "$work/owned-esp.img"
sync
# Host-side, immutable pre-install GPT evidence: isolated Linux-only VM disk.
python3 auto_tests/tools/gaslux_popos_native_mock_windows_gpt_reconcile.py capture \
  "$target" "$work/owned-gpt-before.json"
printf 'GASLUX_POP_NATIVE_INSTALL_LAB_DISK=isolated-mock-windows\n'

[[ "$iso" != *,* && "$target" != *,* ]] ||
  die 'Unsafe QEMU path separator'
timeout --kill-after=15s 1700s qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -net none \
  -drive "if=pflash,format=raw,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,file=$work/nvram-live.fd" \
  -drive "if=none,id=labefi,format=raw,file=$work/lab-efi.raw" \
  -device virtio-blk-pci,drive=labefi,bootindex=1 \
  -drive "if=none,id=verifiediso,readonly=on,format=raw,file=$iso" \
  -device virtio-blk-pci,drive=verifiediso,bootindex=2 \
  -drive "if=none,id=ownedtarget,format=raw,file=$target" \
  -device virtio-blk-pci,drive=ownedtarget,serial=GASLUXPOPMOCKVM,bootindex=3 \
  -boot order=c,menu=off \
  -chardev "socket,id=popserial,path=$work/live.sock,server=on,wait=off,logfile=$work/live.serial.log" \
  -serial chardev:popserial &
guest="$!"
set +e
python3 auto_tests/tools/gaslux_popos_native_install_serial.py \
  --socket "$work/live.sock" \
  --trace "$work/live.console.trace" \
  --distinst-sha256 "$agent"
control_rc=$?
set -e
[[ "$control_rc" == 0 ]] || die 'Native System76 full install did not complete'
# The controller requested an actual guest shutdown; ensure QEMU exited before
# restarting from the installed disk.
for _ in $(seq 1 75); do
  kill -0 "$guest" >/dev/null 2>&1 || break
  sleep 1
done
if kill -0 "$guest" >/dev/null 2>&1; then
  die 'Native guest did not cleanly power off after filesystem sync'
fi
set +e
wait "$guest"
qemu_rc="$?"
set -e
guest=''
printf '%s\n' "$qemu_rc" > "$work/install-qemu.exit"
[[ "$qemu_rc" == 0 ]] || die "Native install QEMU did not shut down cleanly ($qemu_rc)"
sgdisk --print "$target" > "$work/target-after.txt"
test -s "$work/target-after.txt" || die 'Installed target GPT cannot be inspected'
python3 auto_tests/tools/gaslux_popos_native_mock_windows_gpt_reconcile.py capture \
  "$target" "$work/owned-gpt-after.json"
python3 auto_tests/tools/gaslux_popos_native_mock_windows_gpt_reconcile.py verify \
  "$work/owned-gpt-before.json" "$work/owned-gpt-after.json" \
  > "$work/owned-gpt-proof.txt"
grep -Fxq 'GASLUX_POP_NATIVE_MOCK_WINDOWS_GPT_VERIFIED=1' \
  "$work/owned-gpt-proof.txt" || die 'Host GPT reconciliation missing'
expected_partuuid="$(python3 - "$work/owned-gpt-proof.txt" <<'PY'
import json
import sys
import uuid
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
if len(lines) != 2 or lines[0] != "GASLUX_POP_NATIVE_MOCK_WINDOWS_GPT_VERIFIED=1":
    raise SystemExit("Missing independently validated host GPT proof")
proof = json.loads(lines[1])
if proof.get("productionInstallationAuthorized") is not False:
    raise SystemExit("Lab GPT proof must never authorize production")
if proof.get("ownedEspGptEntryIdentical") is not True:
    raise SystemExit("Owned ESP GPT entry changed during native install")
value = proof.get("rootPartuuidAfter")
if type(value) is not str or str(uuid.UUID(value)) != value:
    raise SystemExit("Missing authoritative root PARTUUID")
print(value)
PY
)"
[[ "$expected_partuuid" =~ ^[0-9a-f-]{36}$ ]] ||
  die 'Host post-install root PARTUUID missing'
printf 'GASLUX_POP_NATIVE_DISTINST_FULL_INSTALL_ON_QEMU=1\n'

# The SECOND QEMU has NO lab EFI disk and NO live ISO. Only the native Pop disk
# and fresh OVMF NVRAM are attached; GRUB cannot supply the first boot.
# Some hosted runners revoke a user-specific /dev/kvm ACL after the first
# QEMU exits; reacquire it on this disposable runner, then fail closed.
prepare_hosted_kvm
timeout --kill-after=10s 360s qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -net none \
  -drive "if=pflash,format=raw,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,file=$work/nvram-installed.fd" \
  -drive "if=none,id=popinstalled,format=raw,file=$target" \
  -device virtio-blk-pci,drive=popinstalled,serial=GASLUXPOPMOCKVM,bootindex=1 \
  -boot order=c,menu=off \
  -serial "file:$work/installed.serial.log" &
guest="$!"
verified=0
for _ in $(seq 1 290); do
  if [[ -f "$work/installed.serial.log" ]]; then
    tr -d '\r' < "$work/installed.serial.log" > "$work/installed.normalized.log"
    if grep -Fq 'GASLUX_POP_NATIVE_FIRSTBOOT_FAILURE=' "$work/installed.normalized.log"; then
      tail -n 40 "$work/installed.serial.log" >&2
      die 'Installed Pop first boot proof explicitly failed'
    fi
    if grep -Fxq 'GASLUX_POP_NATIVE_FIRSTBOOT_VERIFIED=1' \
        "$work/installed.normalized.log" &&
       grep -Fxq 'GASLUX_POP_NATIVE_FIRSTBOOT_OS_ID=pop' \
        "$work/installed.normalized.log" &&
       grep -Eq '^GASLUX_POP_NATIVE_FIRSTBOOT_KERNEL=[^[:space:]]+$' \
        "$work/installed.normalized.log" &&
       grep -Fxq "GASLUX_POP_NATIVE_FIRSTBOOT_ROOT_PARTUUID=$expected_partuuid" \
        "$work/installed.normalized.log"; then
      verified=1
      break
    fi
  fi
  kill -0 "$guest" >/dev/null 2>&1 || break
  sleep 1
done
kill "$guest" >/dev/null 2>&1 || true
set +e
wait "$guest"
qemu_rc="$?"
set -e
guest=''
printf '%s\n' "$qemu_rc" > "$work/installed-qemu.exit"
if [[ "$verified" != 1 ]]; then
  tail -n 70 "$work/installed.serial.log" >&2 || true
  die 'No first boot of actual installed Pop via native systemd-boot proved'
fi
# Reinspect the actual image AFTER the independently verified installed-system
# boot; first boot must not modify either mock Windows volume.
python3 auto_tests/tools/gaslux_popos_native_mock_windows_gpt_reconcile.py capture \
  "$target" "$work/owned-gpt-postboot.json"
python3 auto_tests/tools/gaslux_popos_native_mock_windows_gpt_reconcile.py verify \
  "$work/owned-gpt-before.json" "$work/owned-gpt-postboot.json" \
  > "$work/owned-gpt-postboot-proof.txt"
grep -Fxq 'GASLUX_POP_NATIVE_MOCK_WINDOWS_GPT_VERIFIED=1' \
  "$work/owned-gpt-postboot-proof.txt" || die 'Post-firstboot mock Windows partitions changed'
printf 'GASLUX_POP_NATIVE_FIRSTBOOT_WITHOUT_LIVE_ISO=1\n'
printf 'GASLUX_POP_MOCK_WINDOWS_PROTECTED_THROUGH_FIRSTBOOT=1\n'
printf 'NOT TESTED: actual Windows 10/11 boot, BCD, WinRE, real dual boot, upgrades, rollback.\n'
