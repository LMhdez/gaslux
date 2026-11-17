#!/usr/bin/env bash
# Invoked only by the signed Archiso lab launcher; writes only existing GPT #5.
set -Eeuo pipefail
trap 'rc=$?; if (( rc != 0 )); then echo "GASLUX_SHARED_COW_ROOT_PACSTRAP_FAILED:exit=$rc"; fi; sync' EXIT
[[ "$(id -u)" == 0 ]] || { echo 'GASLUX_SHARED_COW_REFUSED_NOT_ROOT'; exit 11; }
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) echo 'GASLUX_SHARED_COW_REFUSED_NOT_QEMU'; exit 12;; esac
[[ -r /run/gaslux-control/lab.env && ! -L /run/gaslux-control/lab.env ]] || exit 13
source /run/gaslux-control/lab.env
[[ "$RUN_ID" =~ ^[a-z0-9-]{12,80}$ ]] || exit 14
[[ "$ROOT_UUID" =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] || exit 15
[[ "$ROOT_PARTUUID" =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] || exit 16
opts="$(findmnt -rn -M /run/gaslux-control -o OPTIONS)"
[[ ",$opts," == *,ro,* ]] || { echo 'GASLUX_SHARED_COW_REFUSED_WRITABLE_CONTROL'; exit 17; }
command -v udevadm >/dev/null || exit 18
udevadm settle --timeout=90
for attempt in $(seq 1 90); do
  [[ -b "/dev/disk/by-partuuid/$ROOT_PARTUUID" ]] && break
  sleep 1
done
[[ -b "/dev/disk/by-partuuid/$ROOT_PARTUUID" ]] || {
  echo 'GASLUX_SHARED_COW_REFUSED_MISSING_ROOT_PARTUUID'
  lsblk -o NAME,TYPE,SERIAL,FSTYPE,UUID,PARTUUID || true
  exit 19
}
export GITHUB_ACTIONS_GUEST=I_ACCEPT_QEMU_GUEST_WITH_HOSTED_WINDOWS_COW
export GASLUX_SHARED_COW_READONLY_CONSENT=I_ACCEPT_GITHUB_HOSTED_READONLY_ARCHISO_LAYOUT_ONLY
export GASLUX_SHARED_COW_ROOT_INSTALL_CONSENT=I_ACCEPT_SIGNED_CACHYOS_ROOT_ONLY_IN_DISPOSABLE_QEMU_COW
export GASLUX_DISPOSABLE_VM=I_ACCEPT_DISPOSABLE_VM_ONLY
set +e
python3 /run/gaslux-control/cachyos_windows_shared_root_pacstrap.py \
  --lab-install \
  --plan /run/gaslux-control/plan.json \
  --signature /run/gaslux-control/plan.sig \
  --public-key /run/gaslux-control/public.pem \
  --expected-run-id "$RUN_ID" \
  --expected-root-uuid "$ROOT_UUID" \
  --root-write-grant /run/gaslux-control/root-write-grant.json \
  --grant-signature /run/gaslux-control/root-write-grant.sig \
  > /run/gaslux-root-pacstrap.log 2>&1
result=$?
set -e
cat /run/gaslux-root-pacstrap.log
if (( result != 0 )) || \
   [[ "$(grep -Fc 'GASLUX_SHARED_COW_NATIVE_CACHYOS_PACSTRAP_ROOT_ONLY=1' /run/gaslux-root-pacstrap.log || true)" != 1 ]] || \
   [[ "$(grep -Fc 'GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED=1' /run/gaslux-root-pacstrap.log || true)" != 1 ]] || \
   grep -Fq 'GASLUX_SHARED_COW_PREWRITE_FAILURE' /run/gaslux-root-pacstrap.log; then
  echo "GASLUX_SHARED_COW_ROOT_PACSTRAP_FAILED:python=$result"
  systemctl --no-block poweroff || true
  exit 20
fi
echo "GASLUX_SHARED_COW_ROOT_PACSTRAP_PASS:$RUN_ID:$ROOT_UUID"
sync
systemctl --no-block poweroff
