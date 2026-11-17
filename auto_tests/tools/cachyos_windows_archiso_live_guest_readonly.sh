#!/usr/bin/env bash
# Genuine CachyOS live Archiso, Windows COW is attached read-only by QEMU.
# No pacstrap, mkfs, partition mounts/writes or bootloader changes.
set -Eeuo pipefail
exec >/dev/ttyS0 2>&1
echo 'GASLUX_WIN10_ARCHISO_READONLY_GUEST_BEGIN'
source /run/gaslux-control/lab.env
[[ "$(id -u)" == 0 ]] || { echo 'GASLUX_WIN10_ARCHISO_REFUSED_ROOT'; exit 13; }
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) echo 'GASLUX_WIN10_ARCHISO_REFUSED_NOT_QEMU'; exit 14;; esac
opts="$(findmnt -rn -M /run/gaslux-control -o OPTIONS)"
[[ ",$opts," == *,ro,* ]] || { echo 'GASLUX_WIN10_ARCHISO_REFUSED_CONTROL_WRITABLE'; exit 15; }
test -r /run/gaslux-control/plan.json
test -r /run/gaslux-control/plan.sig
test -r /run/gaslux-control/public.pem
test -r /run/gaslux-control/probe.py
export GASLUX_SHARED_COW_READONLY_CONSENT='I_ACCEPT_GITHUB_HOSTED_READONLY_ARCHISO_LAYOUT_ONLY'
set +e
python3 /run/gaslux-control/probe.py \
    --plan /run/gaslux-control/plan.json \
    --signature /run/gaslux-control/plan.sig \
    --public-key /run/gaslux-control/public.pem \
    --expected-run-id "$RUN_ID" \
    --expected-root-uuid "$ROOT_UUID" \
    > /run/gaslux-archiso-readonly.json 2>&1
result=$?
set -e
cat /run/gaslux-archiso-readonly.json
if (( result != 0 )) || ! grep -Fq '"actualPrimaryBackupGptCrcAndWindowsPartitionsVerified": true' /run/gaslux-archiso-readonly.json || \
   ! grep -Fq '"observedFivePartitionLayoutMatchesSignedPlan": true' /run/gaslux-archiso-readonly.json || \
   ! grep -Fq '"signedPlanAndIsolatedDiskContractVerified": true' /run/gaslux-archiso-readonly.json || \
   ! grep -Fq '"storageWritesAuthorized": false' /run/gaslux-archiso-readonly.json || \
   ! grep -Fq '"pacstrapAuthorized": false' /run/gaslux-archiso-readonly.json; then
    echo 'GASLUX_WIN10_ARCHISO_READONLY_FAILED'
    systemctl --no-block poweroff || true
    exit 3
fi
# Independently validate EFI, BCD, Windows loader and WinRE inside Archiso.
# No actual Windows mount is writable. Missing ntfs3/dirty NTFS is a failure.
test -r /run/gaslux-control/protected.py
set +e
python3 /run/gaslux-control/protected.py \
    --plan /run/gaslux-control/plan.json \
    --signature /run/gaslux-control/plan.sig \
    --public-key /run/gaslux-control/public.pem \
    --expected-run-id "$RUN_ID" \
    --expected-root-uuid "$ROOT_UUID" \
    > /run/gaslux-archiso-protected.json 2>&1
protected_rc=$?
set -e
cat /run/gaslux-archiso-protected.json
if (( protected_rc != 0 )) || \
   ! grep -Fq '"realWindowsEspBcdLoaderWinreGuestHashesVerified": true' /run/gaslux-archiso-protected.json || \
   ! grep -Fq '"guestWindowsMountsReadOnlyVerified": true' /run/gaslux-archiso-protected.json || \
   ! grep -Fq '"storageWritesAuthorized": false' /run/gaslux-archiso-protected.json || \
   ! grep -Fq '"pacstrapAuthorized": false' /run/gaslux-archiso-protected.json; then
    echo 'GASLUX_WIN10_ARCHISO_PROTECTED_WINDOWS_READONLY_FAILED'
    systemctl --no-block poweroff || true
    exit 4
fi
echo 'GASLUX_WIN10_ARCHISO_PROTECTED_WINDOWS_READONLY_PASS'
printf 'GASLUX_WIN10_ARCHISO_READONLY_PASS:%s:%s\n' "$RUN_ID" "$ROOT_UUID"
systemctl --no-block poweroff
