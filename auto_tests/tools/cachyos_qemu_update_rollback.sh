#!/usr/bin/env bash
# HOST-side GitHub Actions runner for isolated QCOW2 update and rollback proofs.
# Never pass physical disks, Windows disks or production OVMF variables.
set -Eeuo pipefail
die() { echo "GASLUX_UPDATE_ROLLBACK_FAILED: $*" >&2; exit 1; }
[[ $# == 4 ]] || die 'requires disposable QCOW2 OVMF_CODE OVMF_VARS EVIDENCE_DIR'
[[ "${GASLUX_LAB_FIRSTBOOT:-0}" == 1 &&
   "${GASLUX_LAB_UPDATE_ROLLBACK:-0}" == 1 &&
   -n "${GASLUX_SIGNED_EVIDENCE_DIR:-}" ]] ||
  die 'explicit signed-ISO disposable VM mode absent'
base="$1"; code="$2"; template="$3"; evidence="$4"
[[ "$base" == /tmp/cachyos-real-boot-*/target.qcow2 ]] ||
  die 'not the dedicated newly created CI target'
[[ -f "$base" && ! -L "$base" ]] || die 'missing unsafe or linked QCOW2'
w="$(dirname -- "$base")"
[[ -d "$w" && ! -L "$w" &&
   "$(stat -c %u "$base")" == "$(id -u)" ]] ||
  die 'disposable target path is not owned by runner'
for bin in qemu-system-x86_64 qemu-img python3 sha256sum timeout; do
  command -v "$bin" >/dev/null || die "missing $bin"
done
[[ "$code" == /usr/share/OVMF/OVMF_CODE_4M.secboot.fd &&
   "$template" == /usr/share/OVMF/OVMF_VARS_4M.fd &&
   -f "$code" && -f "$template" ]] ||
  die 'unexpected OVMF firmware'
python3 - "$base" <<'PY' || die 'invalid virtual disk image geometry'
import json,subprocess,sys
r=subprocess.run(['qemu-img','info','--output=json',sys.argv[1]],
                 check=True,capture_output=True,text=True)
info=json.loads(r.stdout)
assert info['format']=='qcow2' and info['virtual-size']==12884901888
assert not info.get('backing-filename'), 'base must not be overlay'
PY
mkdir -p "$evidence"
saved_sha="$(sha256sum "$base" | cut -d' ' -f1)"
vm_pid=0
cleanup() {
  if [[ "$vm_pid" =~ ^[0-9]+$ ]] && ((vm_pid > 0)); then
    kill -KILL "$vm_pid" 2>/dev/null || true
    wait "$vm_pid" 2>/dev/null || true
  fi
  # Failure is expected in fault-injection tests: preserve observed serial
  # transcripts BEFORE the parent script removes its temporary guest files.
  if [[ -d "$w" && ! -L "$w" && -d "$evidence" && ! -L "$evidence" ]]; then
    for name in powercut update-transaction update-reboot recovered-baseline; do
      source="$w/$name-serial.log"
      if [[ -f "$source" && ! -L "$source" ]]; then
        install -m 0600 "$source" "$evidence/cachyos-$name-serial.log" || true
        (
          cd "$evidence" || exit
          sha256sum "cachyos-$name-serial.log" \
            > "cachyos-$name-serial.sha256"
        ) || true
      fi
    done
  fi
}
trap cleanup EXIT

launch() {
  local disk="$1" mode="$2" log="$3" nvram="$4"
  [[ ! -e "$log" && "$disk" == "$w/"*.qcow2 ]] ||
    die 'refusing reused log or unexpected disk path'
  cp "$template" "$nvram"
  local fw=() net=()
  if [[ "$mode" != BASELINE ]]; then
    [[ "$mode" == GASLUX_CI_POWERCUT || "$mode" == GASLUX_CI_UPDATE ]] ||
      die 'unknown firmware test phase'
    fw=(-fw_cfg "name=opt/gaslux/ci-mode,string=$mode")
    net=(-netdev "user,id=net0" -device "virtio-net-pci,netdev=net0")
  fi
  qemu-system-x86_64 \
    -machine q35,accel=tcg,smm=on \
    -global driver=cfi.pflash01,property=secure,value=on \
    -smp 2 -m 4096 -display none -monitor none -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$code" \
    -drive if=pflash,format=raw,file="$nvram" \
    -drive "if=none,id=target,format=qcow2,file=$disk" \
    -device virtio-blk-pci,drive=target,serial=GASLUXLABTARGET,bootindex=1 \
    "${fw[@]}" "${net[@]}" \
    -serial "file:$log" &
  vm_pid=$!
}
require_marker() {
  local file="$1" marker="$2" count="$3" seen=0
  for ((i=0;i<count;i++)); do
    sleep 3
    if [[ -f "$file" ]] && awk -v marker="$marker" \
      '{gsub(/\r/, ""); if ($0 == marker) found = 1} END {exit !found}' \
      "$file"; then
      seen=1; break
    fi
    kill -0 "$vm_pid" 2>/dev/null || break
  done
  if [[ "$seen" != 1 ]] ||
     ( [[ -f "$file" ]] && grep -Fq GASLUX_VM_UPDATE_FAILURE "$file" ); then
    tail -c 10000 "$file" >&2 || true
    die "real running VM failed to emit exact $marker"
  fi
}
stop_vm() {
  kill -KILL "$vm_pid" 2>/dev/null || true
  wait "$vm_pid" 2>/dev/null || true
  vm_pid=0
}
assert_base_unchanged() {
  [[ "$(sha256sum "$base" | cut -d' ' -f1)" == "$saved_sha" ]] ||
    die 'immutable original CachyOS disk changed during overlay test'
}
make_overlay() {
  local out="$1"
  [[ ! -e "$out" && "$out" == "$w/"*.qcow2 ]] ||
    die 'refusing to replace an overlay'
  qemu-img create -f qcow2 -F qcow2 -b "$base" "$out"
  python3 - "$out" "$base" <<'PY' || die 'overlay not backed only by expected target'
import json,subprocess,sys
r=subprocess.run(['qemu-img','info','--output=json',sys.argv[1]],check=True,
                 capture_output=True,text=True)
d=json.loads(r.stdout)
assert d['format']=='qcow2' and d['virtual-size']==12884901888
assert d.get('backing-filename')==sys.argv[2] and d.get('backing-filename-format')=='qcow2'
PY
}

# Inject a real VM loss of power, then restore from the immutable base
# snapshot by discarding ONLY a newly-created disposable overlay.
cut="$w/powercut-overlay.qcow2"
make_overlay "$cut"
launch "$cut" GASLUX_CI_POWERCUT "$w/powercut-serial.log" "$w/powercut-vars.fd"
require_marker "$w/powercut-serial.log" 'GASLUX_VM_UPDATE_POWERCUT_ARMED=1' 150
stop_vm # SIGKILL is a hard VM cut, not a clean guest shutdown.
assert_base_unchanged
rm -- "$cut"
echo 'GASLUX_QCOW2_POWERCUT_SNAPSHOT_PRESERVED=1'

# Boot an overlay and make an actual signed pacman -Syu kernel/GRUB transaction.
update="$w/update-overlay.qcow2"
make_overlay "$update"
launch "$update" GASLUX_CI_UPDATE "$w/update-transaction-serial.log" "$w/update-vars.fd"
require_marker "$w/update-transaction-serial.log" 'GASLUX_VM_UPDATE_APPLIED=1' 900
stop_vm
assert_base_unchanged
echo 'GASLUX_QCOW2_SIGNED_PACMAN_UPDATE_APPLIED=1'

# Boot the same updated overlay (no Archiso!) and prove the refreshed kernel,
# initramfs, GRUB and pacman database are usable from the INSTALLED system.
launch "$update" GASLUX_CI_UPDATE "$w/update-reboot-serial.log" "$w/update-reboot-vars.fd"
require_marker "$w/update-reboot-serial.log" 'GASLUX_VM_UPDATED_REBOOT_VERIFIED=1' 170
stop_vm
assert_base_unchanged
echo 'GASLUX_QCOW2_UPDATED_LINUX_REBOOT_VERIFIED=1'

# Discard only the owned update overlay, then boot a NEW overlay of the
# unchanged baseline. Booting the base directly would allow systemd/journal
# writes to modify the very QCOW2 whose immutability we claim to prove.
rm -- "$update"
assert_base_unchanged
recovered="$w/recovered-overlay.qcow2"
make_overlay "$recovered"
launch "$recovered" BASELINE "$w/recovered-baseline-serial.log" "$w/recovered-vars.fd"
require_marker "$w/recovered-baseline-serial.log" 'GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1' 170
stop_vm
assert_base_unchanged
rm -- "$recovered"
assert_base_unchanged
echo 'GASLUX_QCOW2_BASELINE_RECOVERY_BOOT_VERIFIED=1'
echo 'NOT TESTED: Windows boot, WinRE/BCD/BitLocker recovery, desktop or production rollback.'

for name in powercut update-transaction update-reboot recovered-baseline; do
  install -m 0600 "$w/$name-serial.log" "$evidence/cachyos-$name-serial.log"
done
(
  cd "$evidence"
  sha256sum cachyos-powercut-serial.log cachyos-update-transaction-serial.log \
    cachyos-update-reboot-serial.log cachyos-recovered-baseline-serial.log \
    > cachyos-update-recovery.sha256
)
