#!/usr/bin/env bash
# Experimental ONLY: native System76 installer on a disposable CHILD QCOW2
# of a genuine installed Windows 10 disk. Never use on hardware.
set -Eeuo pipefail

fail() {
  printf 'GASLUX_POP_NATIVE_INSTALL_FAILURE: %s\n' "$*" > /dev/ttyS0
  exit 1
}
[[ $# -eq 0 ]] || fail 'unexpected guest installer arguments'
trusted_hash_file=/run/gaslux-pop-lab/agent.sha256
[[ -f "$trusted_hash_file" && ! -L "$trusted_hash_file" ]] ||
  fail 'host-pinned native agent digest missing on lab control disk'
[[ "$(wc -c < "$trusted_hash_file")" == 65 ]] ||
  fail 'malformed host-pinned native agent digest file'
trusted_hash="$(tr -d '\r\n' < "$trusted_hash_file")"
[[ "$trusted_hash" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'malformed pinned native agent digest'
[[ "$(id -u)" == 0 ]] || fail 'guest root shell required'
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) fail 'not virtual machine' ;; esac
. /etc/os-release
[[ "${ID:-}" == pop && "${VERSION_ID:-}" == 24.04 ]] || fail 'wrong live OS identity'
[[ -f /usr/bin/distinst && ! -L /usr/bin/distinst ]] || fail 'native agent missing'
[[ "$(sha256sum /usr/bin/distinst | awk '{print $1}')" == "$trusted_hash" ]] ||
  fail 'native distinst digest differs from authenticated ISO'
[[ "$(findmnt -rn -M /run/gaslux-pop-lab -o FSTYPE)" == vfat ]] ||
  fail 'lab command media not FAT'
findmnt -rn -M /run/gaslux-pop-lab -o OPTIONS | tr , '\n' | grep -qx ro ||
  fail 'lab control media is not mounted read-only'

# Firmware must be virtual UEFI with Secure Boot known to be disabled.
[[ -d /sys/firmware/efi/efivars ]] || fail 'guest did not enter UEFI mode'
secure=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
setup=/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c
[[ -f "$secure" && ! -L "$secure" && -f "$setup" && ! -L "$setup" ]] ||
  fail 'missing or untrusted EFI SecureBoot/SetupMode firmware variables'
# efivarfs reports special-file metadata; read the exact five bytes instead
# of relying on stat(2) sizes.
[[ "$(wc -c < "$secure")" == 5 && "$(wc -c < "$setup")" == 5 ]] ||
  fail 'invalid EFI security variable lengths'
secure_value="$(od -An -tu1 -j4 -N1 "$secure" | tr -d '[:space:]')"
setup_value="$(od -An -tu1 -j4 -N1 "$setup" | tr -d '[:space:]')"
[[ "$secure_value" == 0 && "$setup_value" == 1 ]] ||
  fail 'Secure Boot enabled or EFI SetupMode not keyless'
printf 'GASLUX_POP_VM_SECUREBOOT_DISABLED_SETUPMODE_1=1\n' > /dev/ttyS0

# Require a SIGNED, durable, isolated lab-only Windows recovery checkpoint.
# A supplied ephemeral public key proves LAB coherence only, not production trust.
[[ -s /run/gaslux-pop-lab/recovery-plan.json &&
   -s /run/gaslux-pop-lab/recovery-plan.sig &&
   -s /run/gaslux-pop-lab/recovery-plan.pub ]] ||
  fail 'missing separate native-child rollback checkpoint'
openssl pkeyutl -verify -pubin \
  -inkey /run/gaslux-pop-lab/recovery-plan.pub -rawin \
  -in /run/gaslux-pop-lab/recovery-plan.json \
  -sigfile /run/gaslux-pop-lab/recovery-plan.sig >/dev/null ||
  fail 'native-child rollback checkpoint signature invalid'
python3 - <<'PY' || fail 'foreign native-child rollback policy'
import json
from pathlib import Path
p=json.loads(Path('/run/gaslux-pop-lab/recovery-plan.json').read_text())
assert type(p) is dict
assert p.get('mode') == 'disposable-windows10-pop-native-child-qcow2-only'
assert p.get('productionInstallationAuthorized') is False
assert p.get('nativeGuestWriteAllowedOnlyOnPartitions') == [5,6]
assert p.get('windowsPartitionIndexesReadOnly') == [1,2,3,4]
assert p.get('rollbackMechanism') == 'discard-child-then-reboot-parent-windows'
assert p.get('parentSnapshotImmutable') is True
assert p.get('hostRecoveryCheckpointFsynced') is True
assert p.get('popIsoSha256') == 'a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c'
assert p.get('distinstSha256') == '8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5'
PY
# Reuse the exact host-measured primary+backup GPT SHA and owner GUID probe
# before formatting any Pop-owned filesystem in this separate child.
python3 /run/gaslux-pop-lab/probe.py ||
  fail 'six-GPT live disk identity disagrees with signed parent'
by_id=/dev/disk/by-id/virtio-GASLUX_POP_WIN10_COW
[[ -b "$by_id" ]] || fail 'approved QEMU virtio device not present'
disk="$(readlink -e "$by_id")"
[[ "$disk" =~ ^/dev/vd[a-z]+$ ]] || fail 'foreign canonical QEMU device'
[[ "$(lsblk -dn -o SERIAL "$disk" | tr -d '[:space:]')" == GASLUX_POP_WIN10_COW ]] ||
  fail 'virtual disk serial mismatch'
[[ "$(blockdev --getsize64 "$disk")" == 137438953472 ]] ||
  fail 'virtual Windows 10 capacity mismatch'
for n in 1 2 3 4 5 6; do
  [[ -b "$by_id-part$n" ]] || fail "missing exact Windows/Pop GPT partition $n"
done
[[ ! -e "$by_id-part7" ]] || fail 'unexpected foreign seventh partition'
[[ "$(blkid -s TYPE -o value "$by_id-part1")" == vfat ]] ||
  fail 'genuine Windows Boot Manager ESP absent'
[[ "$(blkid -s TYPE -o value "$by_id-part3")" == ntfs ]] ||
  fail 'genuine Windows filesystem absent'
[[ -z "$(blkid -s TYPE -o value "$by_id-part5" 2>/dev/null || true)" &&
   -z "$(blkid -s TYPE -o value "$by_id-part6" 2>/dev/null || true)" ]] ||
  fail 'Gaslux owned ESP/root unexpectedly formatted'
printf 'GASLUX_POP_NATIVE_WIN10_SIX_GPT_PREWRITE_VERIFIED=1\n' > /dev/ttyS0
# Both installer artifacts must live inside the same GPG/SHA-verified ISO.
mapfile -t roots < <(find /cdrom -mindepth 2 -maxdepth 3 -type f \
  -name filesystem.squashfs -print | sort)
[[ "${#roots[@]}" == 1 ]] || fail 'missing or ambiguous Pop squashfs'
squashfs="${roots[0]}"
remove="${squashfs%/*}/filesystem.manifest-remove"
[[ -s "$squashfs" && -s "$remove" ]] ||
  fail 'Pop signed installation source/manifest absent'
printf 'GASLUX_POP_NATIVE_INSTALL_PREFLIGHT_OK=1\n' > /dev/ttyS0
printf 'GASLUX_POP_NATIVE_WIN10_SIX_GPT_PREWRITE_VERIFIED=1\n' > /dev/ttyS0


# ONLY an owned fifth GPT partition in the extra QCOW2 child is formatted;
# the real Windows parent and its ESP remain outside writable guest disks.
mkfs.vfat -F 32 -n GASLUXPOP "$by_id-part5" >/dev/null ||
  fail 'format exact owned ESP #5 failed'
[[ "$(blkid -s TYPE -o value "$by_id-part5")" == vfat ]] ||
  fail 'owned ESP FAT32 signature not verified after writing'

log="$(mktemp -p /run -t gaslux-native-distinst.XXXXXX)"
# The actual native System76 installer performs extraction, target configuration
# and systemd-boot. No --test, no --new-table or --modify-boot, no host disk.
printf 'GASLUX_POP_NATIVE_INSTALL_DISTINST_STARTED=1\n' > /dev/ttyS0
# The full native run is longer than the partition-stage check. The
# authenticated disposable guest forwards bounded diagnostic tails every
# 40 seconds; never expose guest logs as installation success evidence.
timeout --kill-after=15s 1500s /usr/bin/distinst \
  --no-efi-vars \
  --squashfs "$squashfs" --remove "$remove" \
  --hostname gaslux-pop-installed --keyboard us --lang en_US.UTF-8 \
  --block "$disk" \
  --use "$disk:5:reuse:mount=/boot/efi" \
  --use "$disk:6:ext4:mount=/" \
  > "$log" 2>&1 &
native_pid="$!"
while kill -0 "$native_pid" >/dev/null 2>&1; do
  sleep 40
  printf 'GASLUX_POP_NATIVE_INSTALL_DIAGNOSTIC_TAIL_BEGIN\n' > /dev/ttyS0
  tail -n 6 "$log" | cut -c1-220 > /dev/ttyS0 || true
  printf 'GASLUX_POP_NATIVE_INSTALL_DIAGNOSTIC_TAIL_END\n' > /dev/ttyS0
done
native_rc=0
wait "$native_pid" || native_rc="$?"
if [[ "$native_rc" != 0 ]]; then
  tail -n 55 "$log" > /dev/ttyS0
  fail "System76 native full installation failed (exit=$native_rc)"
fi
grep -Fq 'install was successful' "$log" ||
  fail 'native System76 success message missing'
sync
[[ "$(blkid -s TYPE -o value "$by_id-part6")" == ext4 ]] ||
  fail 'native install did not create ext4 root'

# These are independent installed-target checks, not a SquashFS copy.
mnt=/run/gaslux-pop-native-installed
mkdir -p "$mnt"
mount -t ext4 -o rw "$by_id-part6" "$mnt" || fail 'native root mount failed'
[[ -f "$mnt/etc/os-release" ]] || fail 'installed Pop OS identity missing'
(
  . "$mnt/etc/os-release"
  [[ "${ID:-}" == pop && "${VERSION_ID:-}" == 24.04 ]]
) || fail 'installed OS identity mismatch'
[[ -s "$mnt/sbin/init" || -s "$mnt/lib/systemd/systemd" ||
   -s "$mnt/usr/lib/systemd/systemd" ]] || fail 'native systemd absent'
[[ -d "$mnt/var/lib/dpkg" ]] || fail 'installed package database absent'

mkdir -p "$mnt/boot/efi"
mount -t vfat -o ro "$by_id-part5" "$mnt/boot/efi" ||
  fail 'native ESP could not be mounted'
efi="$mnt/boot/efi"
[[ -s "$efi/EFI/systemd/systemd-bootx64.efi" ]] ||
  fail 'native systemd-boot EFI loader absent'
[[ -s "$efi/EFI/BOOT/BOOTX64.EFI" ]] ||
  fail 'native UEFI fallback loader absent'
entries=("$efi"/loader/entries/*.conf)
[[ "${#entries[@]}" -ge 1 && -s "${entries[0]}" ]] ||
  fail 'native systemd-boot entry absent'
[[ -d "$mnt/boot" ]] || fail 'installed kernel directory absent'

# Test-only proof, hash-authenticated on isolated lab control media, is added
# AFTER native installation. This does not replace the native bootloader.
proof=/run/gaslux-pop-lab/firstboot.sh
[[ -s "$proof" && ! -L "$proof" ]] || fail 'lab firstboot proof missing'
install -D -m 0755 "$proof" "$mnt/usr/local/libexec/gaslux-pop-firstboot-lab"
install -d "$mnt/etc/systemd/system/multi-user.target.wants"
cat > "$mnt/etc/systemd/system/gaslux-pop-firstboot-lab.service" <<'UNIT'
[Unit]
Description=Gaslux VM-only first-boot proof for independently installed Pop OS
After=local-fs.target
ConditionPathExists=/usr/local/libexec/gaslux-pop-firstboot-lab
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/gaslux-pop-firstboot-lab
TimeoutStartSec=30
[Install]
WantedBy=multi-user.target
UNIT
ln -s ../gaslux-pop-firstboot-lab.service \
  "$mnt/etc/systemd/system/multi-user.target.wants/gaslux-pop-firstboot-lab.service"
sync
umount "$mnt/boot/efi" || fail 'native ESP unmount failed'
umount "$mnt" || fail 'installed root unmount failed'
printf 'GASLUX_POP_NATIVE_FULL_INSTALL_COMPLETED=1\n' > /dev/ttyS0
