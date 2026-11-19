#!/usr/bin/env bash
# PINNED native Pop ISO -> QEMU live audit; genuine Windows COW READ-ONLY.
set -Eeuo pipefail
die() { printf 'GASLUX_POP_WIN10_LIVE_VM_REFUSED: %s\n' "$*" >&2; exit 1; }
[[ $# == 4 ]] || die 'Usage: script OVERLAY MANIFEST WORKSPACE EVIDENCE'
overlay="$1"; manifest="$2"; workspace="$3"; evidence="$4"
[[ "$GITHUB_ACTIONS" == true && "$RUNNER_ENVIRONMENT" == github-hosted &&
   "$RUNNER_OS" == Linux && "$GITHUB_REPOSITORY" == LMhdez/gaslux &&
   "$GASLUX_POP_WIN10_LIVE_CONSENT" == I_ACCEPT_SIGNED_POP_ISO_READ_ONLY_GENUINE_WINDOWS_COW_VM ]] ||
  die 'Hosted QEMU opt-in missing'
[[ "$RUNNER_TEMP" == /home/runner/work/_temp &&
   "$workspace" == "$RUNNER_TEMP"/gaslux-win-x64-* &&
   -d "$workspace" && ! -L "$workspace" &&
   "$(stat -c %a "$workspace")" == 700 &&
   "$(stat -c %u "$workspace")" == "$(id -u)" &&
   "$overlay" == "$workspace/gaslux-pop-stage.qcow2" &&
   "$manifest" == "$workspace/pop-live-six-gpt.json" &&
   "$evidence" == "$GITHUB_WORKSPACE/windows-x64-tcg-evidence" &&
   -f "$overlay" && ! -L "$overlay" &&
   -f "$manifest" && ! -L "$manifest" &&
   -d "$evidence" && ! -L "$evidence" &&
   "$(stat -c %h "$overlay")" == 1 ]] ||
  die 'Unrecognized disposable Windows VM storage ownership'
python3 - "$overlay" "$workspace" <<'PY'
import json, pathlib, subprocess, sys
target = pathlib.Path(sys.argv[1])
base = pathlib.Path(sys.argv[2]) / "only-disposable-windows-target.qcow2"
info = json.loads(subprocess.check_output(
    ["qemu-img", "info", "--output=json", str(target)], timeout=30))
if (info.get("format") != "qcow2" or
    info.get("virtual-size") != 128*1024**3 or
    info.get("backing-filename") != str(base) or
    info.get("backing-filename-format") != "qcow2" or
    not base.is_file() or base.is_symlink()):
    raise SystemExit("Refuse unverified Windows backing chain")
PY
[[ -r /dev/kvm && -w /dev/kvm ]] || die 'KVM unavailable; no TCG fallback'
for bin in curl gpg aria2c sha256sum qemu-system-x86_64 qemu-img \
  grub-mkstandalone sgdisk mkfs.vfat mcopy mmd sudo mount umount timeout; do
  command -v "$bin" >/dev/null || die "Missing verified ISO/VM tool: $bin"
done

# Verified 17 Nov 2026: PR #67, Actions #44034706601, official GPG manifest.
iso_url='https://iso.pop-os.org/24.04/amd64/intel/20/pop-os_24.04_amd64_intel_20.iso'
iso_sha='a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c'
iso_bytes=2955067392
work="$workspace/post-pop-live"
[[ ! -e "$work" && ! -L "$work" ]] || die 'Refuse reused Pop live workspace'
mkdir -m 700 "$work"
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
}
trap cleanup EXIT
mkdir -m 700 "$work/iso-root" "$work/gnupg"
export GNUPGHOME="$work/gnupg"
curl -fLsS --retry 3 --connect-timeout 20 --max-time 150 \
  -o "$work/SHA256SUMS" \
  'https://iso.pop-os.org/24.04/amd64/intel/20/SHA256SUMS'
curl -fLsS --retry 3 --connect-timeout 20 --max-time 150 \
  -o "$work/SHA256SUMS.gpg" \
  'https://iso.pop-os.org/24.04/amd64/intel/20/SHA256SUMS.gpg'
gpg --batch --keyserver hkps://keyserver.ubuntu.com \
  --recv-keys 204DD8AEC33A7AFF
fpr="$(gpg --batch --with-colons --fingerprint 204DD8AEC33A7AFF |
  awk -F: '$1=="fpr" {print $10; exit}')"
[[ "$fpr" == 63C46DF0140D738961429F4E204DD8AEC33A7AFF ]] ||
  die 'Official Pop signing key fingerprint mismatch'
gpg --batch --verify "$work/SHA256SUMS.gpg" "$work/SHA256SUMS" ||
  die 'Official Pop ISO detached signature invalid'
python3 - "$work/SHA256SUMS" "$iso_sha" <<'PY'
from pathlib import Path
import re,sys
rows=Path(sys.argv[1]).read_text("utf-8").splitlines()
matches=[]
for row in rows:
    m=re.fullmatch(r"([0-9a-f]{64})\s+\*?([^/\s]+)", row)
    if m and m.group(2)=="pop-os_24.04_amd64_intel_20.iso":
        matches.append(m.group(1))
if matches != [sys.argv[2]]:
    raise SystemExit("Signed Pop ISO digest differs from pinned build 20")
PY
iso="$workspace/pop-os_24.04_amd64_intel_20.iso"
[[ ! -e "$iso" && ! -L "$iso" ]] || die 'ISO path already exists'
aria2c --quiet --allow-overwrite=false --max-connection-per-server=4 \
  --split=4 --retry-wait=5 --max-tries=4 --dir="$workspace" \
  --out=pop-os_24.04_amd64_intel_20.iso "$iso_url" ||
  die 'Pinned Pop ISO download interrupted'
[[ "$(stat -c %s "$iso")" == "$iso_bytes" ]] ||
  die 'Pinned Pop ISO size mismatch'
printf '%s  %s\n' "$iso_sha" "$iso" | sha256sum --check --status ||
  die 'Pinned Pop ISO SHA256 mismatch'
echo 'GASLUX_POP_WIN10_OFFICIAL_SIGNED_PINNED_ISO_VERIFIED=1'

sudo mount -o loop,ro,nosuid,nodev,noexec "$iso" "$work/iso-root"
mounted=1
find "$work/iso-root" -mindepth 1 -maxdepth 1 -type d \
  -name 'casper_pop-os_24.04_amd64_intel_*' -printf '%f\n' |
  sort > "$work/roots.txt"
[[ "$(wc -l < "$work/roots.txt")" == 1 ]] ||
  die 'Ambiguous Pop live runtime in pinned ISO'
prefix="$(cat "$work/roots.txt")"
[[ "$prefix" =~ ^casper_pop-os_24[.]04_amd64_intel_[A-Za-z0-9_.-]+$ ]] ||
  die 'Unknown Pop live path'
kernel="$prefix/vmlinuz.efi"; initrd="$prefix/initrd.gz"
[[ -s "$work/iso-root/$kernel" && -s "$work/iso-root/$initrd" ]] ||
  die 'Pinned Pop live kernel or initrd missing'
sudo umount "$work/iso-root"; mounted=0

code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
vars=/usr/share/OVMF/OVMF_VARS_4M.fd
[[ -f "$code" && -f "$vars" && "$vars" != *.ms.fd ]] ||
  die 'Virtual keyless Secure Boot-capable OVMF not installed'
cp "$vars" "$work/ovmf-vars-live.fd"
cat > "$work/grub.cfg" <<GRUB
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
set default=0
menuentry 'Gaslux Pop live read-only Windows target' {
  insmod iso9660
  insmod part_gpt
  if ! search --no-floppy --file --set=source /$kernel; then
    echo 'Pinned Pop live kernel missing'
    halt
  fi
  if [ ! -f (\$source)/$initrd ]; then
    echo 'Pinned Pop live initrd missing'
    halt
  fi
  linux (\$source)/$kernel boot=casper live-media-path=/$prefix console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.unit=multi-user.target systemd.debug_shell=ttyS0 systemd.mask=serial-getty@ttyS0.service
  initrd (\$source)/$initrd
}
GRUB
grub-mkstandalone --format=x86_64-efi --output="$work/BOOTX64.EFI" \
  "boot/grub/grub.cfg=$work/grub.cfg" >/dev/null

# ONLY format the new synthetic 128MiB control volume, NEVER the Windows COW.
truncate -s 256M "$work/lab-efi.raw"
sgdisk --zap-all --new=1:2048:+128M --typecode=1:EF00 \
  --change-name=1:GASLUX-LAB-ONLY "$work/lab-efi.raw" >/dev/null
truncate -s 128M "$work/control-esp.img"
mkfs.vfat -F 32 -n GASLUXLAB "$work/control-esp.img" >/dev/null
mmd -i "$work/control-esp.img" ::/EFI
mmd -i "$work/control-esp.img" ::/EFI/BOOT
mcopy -i "$work/control-esp.img" "$work/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$work/control-esp.img" \
  auto_tests/tools/windows10_popos_official_live_probe_guest.py ::/probe.py
mcopy -i "$work/control-esp.img" "$manifest" ::/six-gpt.json
(
  cd auto_tests/tools
  sha256sum windows10_popos_official_live_probe_guest.py |
    sed 's/windows10_popos_official_live_probe_guest.py/probe.py/'
) > "$work/probe.sha256"
mcopy -i "$work/control-esp.img" "$work/probe.sha256" ::/probe.sha256
dd if="$work/control-esp.img" of="$work/lab-efi.raw" \
  bs=1M seek=1 conv=notrunc status=none
rm "$work/control-esp.img"
sha_before="$(sha256sum "$overlay" | awk '{print $1}')"
[[ "$sha_before" =~ ^[0-9a-f]{64}$ ]] || die 'Missing Windows COW SHA'
[[ ! -e "$work/live.sock" && ! -L "$work/live.sock" ]] ||
  die 'Foreign Pop live serial socket'

# The ONLY Windows target attached is the exact child QCOW2, readonly=on.
timeout --kill-after=10s 850s qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -smp 2 -m 4096 \
  -display none -monitor none -no-reboot -net none \
  -drive "if=pflash,format=raw,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,file=$work/ovmf-vars-live.fd" \
  -drive "if=none,id=labefi,format=raw,file=$work/lab-efi.raw" \
  -device virtio-blk-pci,drive=labefi,bootindex=1 \
  -drive "if=none,id=verifiediso,readonly=on,format=raw,file=$iso" \
  -device virtio-blk-pci,drive=verifiediso,bootindex=2 \
  -drive "if=none,id=windowscow,readonly=on,format=qcow2,file=$overlay" \
  -device virtio-blk-pci,drive=windowscow,serial=GASLUX_POP_WIN10_COW,bootindex=3 \
  -boot order=c,menu=off \
  -chardev "socket,id=popserial,path=$work/live.sock,server=on,wait=off,logfile=$work/live.serial.log" \
  -serial chardev:popserial >"$work/qemu.stdout" 2>"$work/qemu.stderr" &
guest="$!"
set +e
python3 auto_tests/tools/windows10_popos_live_serial_controller.py \
  --socket "$work/live.sock" --trace "$work/live.console.trace"
serial_rc="$?"
set -e
if [[ "$serial_rc" != 0 ]]; then
  tail -n 65 "$work/live.console.trace" >&2 || true
  die 'Signed Pop live ISO did not pass read-only GPT guest audit'
fi
for i in $(seq 1 70); do
  kill -0 "$guest" >/dev/null 2>&1 || break
  sleep 1
done
if kill -0 "$guest" >/dev/null 2>&1; then
  die 'Pop live VM did not shut down cleanly'
fi
set +e
wait "$guest"
rc="$?"
set -e
guest=''
[[ "$rc" == 0 ]] || die "Pop live QEMU exit code $rc"
[[ "$(sha256sum "$overlay" | awk '{print $1}')" == "$sha_before" ]] ||
  die 'Read-only Pop guest modified Windows QCOW2 bytes'
[[ -s "$work/live.console.trace" &&
   "$(stat -c %s "$work/live.console.trace")" -le 9000000 ]] ||
  die 'Missing bounded live guest witness'
grep -Fq 'GASLUX_POP_LIVE_WIN10_SIX_GPT_READONLY_VERIFIED=1' \
  "$work/live.console.trace" || die 'Missing guest six-GPT proof'
cp "$work/live.console.trace" "$evidence/pop-live-windows-cow-serial.trace"
sha256sum "$evidence/pop-live-windows-cow-serial.trace" \
  > "$evidence/pop-live-windows-cow-serial.sha256"
python3 - "$evidence" "$iso_sha" "$sha_before" <<'PY'
import json,pathlib,sys
e=pathlib.Path(sys.argv[1])
report={
 "scenario":"real-windows10-pop-official-live-iso-qemu-readonly",
 "pinnedPopIsoSha256":sys.argv[2],
 "windowsChildQcow2Sha256Unchanged":sys.argv[3],
 "officialSignedManifestVerified":True,
 "popOfficialLiveIsoBootedSameWindowsCowReadOnly":True,
 "sixGptPartitionGuestAudit":True,
 "nativeDistinstExecuted":False,
 "popInstalled":False, "dualBootVerified":False,
 "updatesVerified":False, "rollbackVerified":False, "stable":False,
}
(e/"pop-live-windows-cow-result.json").write_text(
 json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
PY
echo 'GASLUX_POP_REAL_WIN10_COW_NATIVE_LIVE_BOOT_READONLY_CONFIRMED=1'
