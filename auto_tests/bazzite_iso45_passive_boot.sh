#!/usr/bin/env bash
# Exactly one passive ISO45 QEMU/KVM boot on one disposable read-only GPT guest disk.
set -Eeuo pipefail
test -n "$RUNNER_TEMP"
WORK="$RUNNER_TEMP/bazzite-iso-public-readback-work"
EVIDENCE="$RUNNER_TEMP/bazzite-iso-public-readback-evidence"
ROOT="$RUNNER_TEMP/bazzite-gpt-fixture"
ISO="$WORK/bazzite-stable-live-amd64.iso"
SOCK="$EVIDENCE/iso45-monitor.sock"
mkdir -p "$EVIDENCE"
qpid=''
cleanup() {
  rc=$?
  trap - EXIT
  if [[ -n "$qpid" ]]; then
    kill "$qpid" 2>/dev/null || true
    wait "$qpid" 2>/dev/null || true
  fi
  if [[ -f "$ROOT/manifest.json" ]]; then
    python auto_tests/bazzite_gpt_fixture.py audit \
      --root "$ROOT" --runner-temp "$RUNNER_TEMP" > "$EVIDENCE/iso45-synthetic-after.json" || rc=3
    python auto_tests/bazzite_gpt_fixture.py discard \
      --root "$ROOT" --runner-temp "$RUNNER_TEMP" > "$EVIDENCE/iso45-synthetic-discard.json" || rc=3
  fi
  if [[ -f "$RUNNER_TEMP/iso45-disposable-ovmf-vars.fd" ]]; then
    sha256sum "$RUNNER_TEMP/iso45-disposable-ovmf-vars.fd" > "$EVIDENCE/iso45-ovmf-post.sha256"
  fi
  printf '%s\n' "$rc" > "$EVIDENCE/iso45-boot-step-exit.txt"
  exit "$rc"
}
trap cleanup EXIT

# Same-run cryptographic ISO and embedded signed OCI verification must have passed.
python auto_tests/bazzite_iso45_passive_gate.py \
  --candidate auto_tests/bazzite_official_iso_candidate_20261117.json \
  --report "$EVIDENCE/bazzite-iso-public-readback.json" \
  --facts "$EVIDENCE/readback-facts.json" \
  --iso "$ISO" --runner-temp "$RUNNER_TEMP" > "$EVIDENCE/iso45-boot-preflight.json"
if [[ ! -c /dev/kvm ]]; then
  echo 'No KVM device; boot not attempted' > "$EVIDENCE/iso45-boot-refusal.txt"
  exit 3
fi
# Reuse the exact hosted-runner KVM access step already proven in Bazzite
# legacy/owned-QCOW2 QEMU workflows. No physical disk access is granted.
sudo chmod 0666 /dev/kvm
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo 'KVM remains inaccessible; boot not attempted' > "$EVIDENCE/iso45-boot-refusal.txt"
  exit 3
fi
sudo env DEBIAN_FRONTEND=noninteractive timeout 360s apt-get install -y -qq \
  gdisk qemu-utils qemu-system-x86 ovmf socat tesseract-ocr
python -m pip install --disable-pip-version-check pillow

python auto_tests/bazzite_gpt_fixture.py prepare \
  --root "$ROOT" --runner-temp "$RUNNER_TEMP" > "$EVIDENCE/iso45-synthetic-before.json"
python auto_tests/bazzite_atomic_destination_plan.py \
  --root "$ROOT" --runner-temp "$RUNNER_TEMP" > "$EVIDENCE/iso45-synthetic-plan.json"
python auto_tests/bazzite_gpt_fixture.py audit \
  --root "$ROOT" --runner-temp "$RUNNER_TEMP" > "$EVIDENCE/iso45-synthetic-verified.json"

code=/usr/share/OVMF/OVMF_CODE_4M.fd
varstemplate=/usr/share/OVMF/OVMF_VARS_4M.fd
if [[ ! -f "$code" || ! -f "$varstemplate" ]]; then
  code=/usr/share/OVMF/OVMF_CODE.fd
  varstemplate=/usr/share/OVMF/OVMF_VARS.fd
fi
test -f "$code" && test -f "$varstemplate"
test ! -L "$code" && test ! -L "$varstemplate"
vars="$RUNNER_TEMP/iso45-disposable-ovmf-vars.fd"
cp -- "$varstemplate" "$vars"
chmod 600 "$vars"
sha256sum "$code" "$vars" > "$EVIDENCE/iso45-ovmf-pre.sha256"
overlay="$ROOT/gpt-layout-scratch.qcow2"

# Exactly one lab-only GPT disk (read-only), the signed ISO as optical media,
# read-only OVMF_CODE and disposable OVMF_VARS. No network/guest agent/shell.
qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -m 8192 -smp 4 \
  -nodefaults -vga std -display none -S -no-reboot -boot order=d -nic none \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,unit=1,file=$vars" \
  -drive "file=$ISO,if=none,format=raw,media=cdrom,readonly=on,id=optical" \
  -device ich9-ahci,id=ahci -device ide-cd,bus=ahci.0,drive=optical \
  -drive "file=$overlay,if=none,format=qcow2,readonly=on,id=owned" \
  -device virtio-blk-pci,drive=owned,serial=GLXBAZRO001 \
  -serial "file:$EVIDENCE/iso45-serial.txt" \
  -monitor "unix:$SOCK,server=on,wait=off" \
  > "$EVIDENCE/iso45-qemu-stdout.txt" 2> "$EVIDENCE/iso45-qemu-stderr.txt" &
qpid=$!
for i in $(seq 1 30); do
  [[ -S "$SOCK" ]] && break
  sleep 1
done
test -S "$SOCK" && kill -0 "$qpid"
(printf 'info block\ninfo qtree\ninfo status\n' |
  timeout 12s socat - "UNIX-CONNECT:$SOCK" || true) > "$EVIDENCE/iso45-preboot-topology.txt"
grep -F 'GLXBAZRO001' "$EVIDENCE/iso45-preboot-topology.txt"
grep -F 'bazzite-stable-live-amd64.iso' "$EVIDENCE/iso45-preboot-topology.txt"
grep -F 'gpt-layout-scratch.qcow2' "$EVIDENCE/iso45-preboot-topology.txt"
# Only host monitor CPU-resume and passive framebuffer capture; no guest input.
(printf 'cont\n' | timeout 12s socat - "UNIX-CONNECT:$SOCK" || true) \
  > "$EVIDENCE/iso45-qemu-resume.txt"
test -s "$EVIDENCE/iso45-qemu-resume.txt"
touch "$EVIDENCE/iso45-cpu-resume-requested.flag"
for sample in 0 1 2 3 4 5; do
  sleep 45
  kill -0 "$qpid" || break
  out="$EVIDENCE/iso45-screen-$sample.ppm"
  (printf 'info status\nscreendump %s\n' "$out" |
    timeout 12s socat - "UNIX-CONNECT:$SOCK" || true) > "$EVIDENCE/iso45-monitor-$sample.txt"
  if [[ -s "$out" ]]; then
    python - "$out" <<'PY'
import sys
from pathlib import Path
from PIL import Image
p = Path(sys.argv[1])
with Image.open(p) as img:
    img.verify()
with Image.open(p) as img:
    img.convert("RGB").save(p.with_suffix(".png"), optimize=True)
p.unlink()
PY
    png=$(printf '%s' "$out" | sed 's/\.ppm$/.png/')
    tesseract "$png" stdout 2>/dev/null > "$EVIDENCE/iso45-ocr-$sample.txt" || true
    sha256sum "$png" >> "$EVIDENCE/iso45-screen-sha256.txt"
  fi
done
# Cleanup trap audits backing/overlay, terminates only this VM and hashes OVMF VARS.
