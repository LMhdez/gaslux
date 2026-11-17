#!/usr/bin/env bash
# Issue #3 — actual Windows 10 QCOW2 + genuine CachyOS Archiso, READ ONLY.
# All guest disk attachments and the Windows backing are immutable to this VM.
set -Eeuo pipefail
[[ $# -eq 6 ]] || { echo 'Usage: iso sha256 owned-COW root-UUID root-PARTUUID evidence-dir' >&2; exit 2; }
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${RUNNER_OS:-}" == Linux && "${GITHUB_REPOSITORY:-}" == LMhdez/gaslux &&
   "${GASLUX_CACHYOS_ARCHISO_READONLY_CONSENT:-}" == I_ACCEPT_PINNED_ARCHISO_READONLY_WINDOWS10_QCOW2_COW ]] ||
   { echo 'Refusing outside explicitly authorized GitHub-hosted Windows 10 read-only lab' >&2; exit 3; }
iso="$(realpath -e "$1")"
hash="$2"
cow="$(realpath -e "$3")"
root_uuid="$4"
root_partuuid="$5"
evidence="$(realpath -e "$6")"
[[ "$iso" == */cachyos.iso && -f "$iso" && ! -L "$iso" &&
   "$hash" == 959f6577f45e25ee9fd8c220fd221b08e4ea79412c7315c0f922dd6d86d5e33c &&
   "$cow" == */windows-uefi-cow-checkpoint/cachyos-unwritten-trial-overlay.qcow2 &&
   -f "$cow" && ! -L "$cow" &&
   "$evidence" == */windows-x64-tcg-evidence && -d "$evidence" && ! -L "$evidence" ]] ||
   { echo 'Wrong ISO, COW backing path or bounded evidence directory' >&2; exit 4; }
printf '%s  %s\n' "$hash" "$iso" | sha256sum --check --status
for cmd in mkfs.ext4 debugfs mkfs.vfat grub-mkstandalone grub-script-check mcopy mmd \
    qemu-system-x86_64 qemu-img openssl python3 timeout; do
    command -v "$cmd" >/dev/null || { echo "Missing: $cmd"; exit 5; }
done
w="$(mktemp -d -p "$RUNNER_TEMP" gaslux-archiso-windows-cow-ro-XXXXXXXX)"
mounted_iso=0
vm_pid=''
cleanup() {
    if [[ -n "$vm_pid" ]]; then kill "$vm_pid" 2>/dev/null || true; fi
    if (( mounted_iso )); then sudo umount "$w/iso-mounted" || true; fi
    if [[ -f "$w/live-serial.log" && $(stat -c %s "$w/live-serial.log") -lt 524288 ]]; then
        cp "$w/live-serial.log" "$evidence/win10-archiso-live-serial.log"
        ( cd "$evidence" && sha256sum win10-archiso-live-serial.log > win10-archiso-live-serial.sha256 )
    fi
    if [[ -f "$w/boot-report.json" ]]; then cp "$w/boot-report.json" "$evidence/win10-archiso-boot-report.json"; fi
    rm -rf -- "$w"
}
trap cleanup EXIT
mkdir -m 0700 "$w/handoff" "$w/iso-mounted"
# The host creates the signer only after the real fourth Windows boot passed.
python3 - "$cow" "$w/handoff" "$root_uuid" "$root_partuuid" "$hash" <<'PY' >"$w/handoff-result.json"
import json, pathlib, sys
sys.path.insert(0, 'auto_tests/tools')
from cachyos_windows_archiso_signed_plan_lab import prepare
status = prepare(
    pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]),
    sys.argv[3], sys.argv[4], sys.argv[5],
    windows_fourth_verified=True,
)
assert status["pacstrapAuthorized"] is False
assert status["storageWritesAuthorized"] is False
print(json.dumps(status, sort_keys=True))
PY
read -r run_id boot_nonce plan_sha pub_sha rootuuid < <(
    python3 - "$w/handoff-result.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1],encoding="utf-8"))
print(*(s[k] for k in ("runId","bootNonce","planSha256","pubSha256","rootUuid")))
PY
)
[[ "$rootuuid" == "$root_uuid" && -n "$run_id" && -n "$boot_nonce" ]] ||
    { echo 'Signed handoff did not preserve expected Windows root identity' >&2; exit 6; }
# Only scratch disks created in private RUNNER_TEMP are formatted here.
iso_uuid="$(python3 -c 'import uuid;print(uuid.uuid4())')"
truncate -s 5G "$w/iso.raw"
mkfs.ext4 -q -F -U "$iso_uuid" "$w/iso.raw"
debugfs -w -R "write $iso /cachyos.iso" "$w/iso.raw" >"$w/iso-write.log" 2>&1
debugfs -R 'stat /cachyos.iso' "$w/iso.raw" >"$w/iso-stat.log" 2>&1
grep -Eq 'Size: [1-9][0-9]+' "$w/iso-stat.log"
truncate -s 64M "$w/control.raw"
mkfs.vfat -F 32 -n GASLUXCTL "$w/control.raw" >/dev/null
printf 'RUN_ID=%q\nROOT_UUID=%q\n' "$run_id" "$root_uuid" > "$w/lab.env"
mcopy -i "$w/control.raw" "$w/lab.env" ::/lab.env
mcopy -i "$w/control.raw" "$w/handoff/plan.json" ::/plan.json
mcopy -i "$w/control.raw" "$w/handoff/plan.sig" ::/plan.sig
mcopy -i "$w/control.raw" "$w/handoff/public.pem" ::/public.pem
mcopy -i "$w/control.raw" auto_tests/tools/cachyos_windows_archiso_live_guest_readonly.sh ::/gaslux-readonly.sh
mcopy -i "$w/control.raw" auto_tests/tools/cachyos_windows_shared_archiso_guest_probe.py ::/probe.py
mcopy -i "$w/control.raw" auto_tests/tools/cachyos_windows_shared_archiso_handoff.py ::/cachyos_windows_shared_archiso_handoff.py
mcopy -i "$w/control.raw" auto_tests/tools/cachyos_windows_shared_gpt_raw_audit.py ::/cachyos_windows_shared_gpt_raw_audit.py
mcopy -i "$w/control.raw" auto_tests/tools/windows_cachyos_qcow2_gpt_readonly.py ::/windows_cachyos_qcow2_gpt_readonly.py
# Use the same SHA-checked, ISO-identity-aware renderer as proven PR #34.
sudo mount -o ro,loop "$iso" "$w/iso-mounted"
mounted_iso=1
python3 auto_tests/tools/cachyos_generated_boot_config.py \
    "$iso" "$hash" "$iso_uuid" "$w/iso-mounted" "$w/grub.cfg" "$w/boot-report.json"
sudo umount "$w/iso-mounted"
mounted_iso=0
python3 - "$w/grub.cfg" "$run_id" "$boot_nonce" "$plan_sha" "$pub_sha" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
lines=p.read_text(encoding="utf-8").splitlines(keepends=True)
pos=[i for i,line in enumerate(lines) if line.startswith('    linux (gaslux_iso)/')]
if len(pos)!=1 or 'gaslux.run=' in lines[pos[0]] or not lines[pos[0]].endswith('\n'):
    raise SystemExit("Unexpected CachyOS boot configuration or duplicate handoff")
flags=(' systemd.mount-extra=LABEL=GASLUXCTL:/run/gaslux-control:vfat:ro,exec'
       ' systemd.run=/run/gaslux-control/gaslux-readonly.sh'
       ' systemd.mask=serial-getty@ttyS0.service'
       ' systemd.wants=kernel-command-line.service'
       ' systemd.run_success_action=none systemd.run_failure_action=none'
       ' gaslux.run='+sys.argv[2]+' gaslux.nonce='+sys.argv[3]
       +' gaslux.plan_sha256='+sys.argv[4]+' gaslux.key_sha256='+sys.argv[5])
lines[pos[0]]=lines[pos[0]][:-1]+flags+'\n'
p.write_text(''.join(lines),encoding='utf-8')
PY
grub-script-check "$w/grub.cfg"
grub-mkstandalone --format=x86_64-efi --output="$w/BOOTX64.EFI" \
    "boot/grub/grub.cfg=$w/grub.cfg"
truncate -s 96M "$w/liveboot.raw"
mkfs.vfat -F 32 -n GASLUXBOOT "$w/liveboot.raw" >/dev/null
mmd -i "$w/liveboot.raw" ::/EFI
mmd -i "$w/liveboot.raw" ::/EFI/BOOT
mcopy -i "$w/liveboot.raw" "$w/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
vars=/usr/share/OVMF/OVMF_VARS_4M.fd
[[ -f "$code" && -f "$vars" && -c /dev/kvm ]] ||
    { echo 'Hosted OVMF/KVM unavailable; do not claim real boot' >&2; exit 6; }
cp "$vars" "$w/nvram.fd"
before_cow="$(sha256sum "$cow" | cut -d' ' -f1)"
before_base="$(sha256sum "${cow%/windows-uefi-cow-checkpoint/*}/only-disposable-windows-target.qcow2" | cut -d' ' -f1)"
: > "$w/live-serial.log"
# Windows QCOW2 remains ATTACHED READ-ONLY. No host physical block paths.
timeout --kill-after=5s 1100s qemu-system-x86_64 \
    -machine q35,accel=kvm,smm=on -cpu host -smp 2 -m 6144 \
    -global driver=cfi.pflash01,property=secure,value=on \
    -display none -monitor none -no-reboot -boot order=c \
    -drive if=pflash,format=raw,readonly=on,file="$code" \
    -drive if=pflash,format=raw,file="$w/nvram.fd" \
    -device qemu-xhci \
    -drive if=none,id=bootefi,format=raw,file="$w/liveboot.raw",readonly=on \
    -device usb-storage,drive=bootefi \
    -drive if=none,id=iso_source,format=raw,file="$w/iso.raw",readonly=on \
    -device virtio-blk-pci,drive=iso_source \
    -drive if=none,id=windows_cow,format=qcow2,file="$cow",readonly=on \
    -device virtio-blk-pci,drive=windows_cow,serial=GASLUXWINDOWSCOWLAB \
    -drive if=none,id=gaslux_control,format=raw,file="$w/control.raw",readonly=on \
    -device virtio-blk-pci,drive=gaslux_control \
    -net none -serial "file:$w/live-serial.log" \
    2>"$w/live-qemu-stderr.log" &
vm_pid=$!
set +e
wait "$vm_pid"
guest_rc=$?
set -e
vm_pid=''
if [[ "$guest_rc" != 0 ]] ||
   ! grep -Fq "GASLUX_WIN10_ARCHISO_READONLY_PASS:$run_id:$root_uuid" "$w/live-serial.log" ||
   grep -Fq 'GASLUX_WIN10_ARCHISO_READONLY_FAILED' "$w/live-serial.log"; then
    echo "GASLUX_WIN10_ARCHISO_READONLY_NOT_PROVEN: QEMU=$guest_rc"
    tail -c 8000 "$w/live-serial.log" || true
    tail -c 1000 "$w/live-qemu-stderr.log" || true
    exit 7
fi
[[ "$(sha256sum "$cow" | cut -d' ' -f1)" == "$before_cow" &&
   "$(sha256sum "${cow%/windows-uefi-cow-checkpoint/*}/only-disposable-windows-target.qcow2" | cut -d' ' -f1)" == "$before_base" ]] ||
   { echo 'Windows COW or backing changed despite read-only guest'; exit 8; }
echo 'GASLUX_WIN10_GENUINE_ARCHISO_ON_WINDOWS_COW_READONLY_VERIFIED=1'
