#!/usr/bin/env bash
# Experimental ONLY: complete System76 distinst REUSE on disposable Linux-only
# QEMU target. Never run against any physical, Windows, or user disk.
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

# Strongly bind the by-id symlink and the canonical device BEFORE any writer.
by_id=/dev/disk/by-id/virtio-GASLUXPOPFULLVM
[[ -b "$by_id" ]] || fail 'owned virtio target missing'
disk="$(readlink -e "$by_id")"
[[ "$disk" =~ ^/dev/vd[a-z]+$ ]] || fail 'unexpected canonical target'
[[ "$(lsblk -dn -o SERIAL "$disk" | tr -d '[:space:]')" == GASLUXPOPFULLVM ]] ||
  fail 'virtio target serial mismatch'
[[ "$(blockdev --getsize64 "$disk")" == 34359738368 ]] ||
  fail 'unexpected disk capacity'
[[ "$(lsblk -dn -o RO "$disk" | tr -d '[:space:]')" == 0 ]] ||
  fail 'owned target not writable'
# Pop live can expose /dev/zram0 as TYPE=disk. Exclude virtual memory
# devices but refuse any additional physical-style guest disks.
disks="$(lsblk -dn -o NAME,TYPE |
  awk '$2=="disk" && $1 !~ /^(zram|ram)[0-9]+$/ {n++} END {print n+0}')"
[[ "$disks" == 3 ]] || fail 'unexpected number of guest block disks'
for n in 1 2; do
  [[ -b "$by_id-part$n" ]] || fail "missing expected owned partition $n"
done
[[ ! -e "$by_id-part3" ]] || fail 'unexpected partition on Linux-only target'
base="${disk##*/}"
[[ "$(cat "/sys/class/block/${base}1/start")" == 2048 ]] ||
  fail 'ESP offset changed'
[[ "$(cat "/sys/class/block/${base}1/size")" == 2097152 ]] ||
  fail 'ESP size changed'
[[ "$(cat "/sys/class/block/${base}2/start")" == 2099200 ]] ||
  fail 'Linux root offset changed'
[[ "$(cat "/sys/class/block/${base}2/size")" == 58720256 ]] ||
  fail 'Linux root size changed'
[[ "$(blkid -s TYPE -o value "$by_id-part1")" == vfat ]] ||
  fail 'owned ESP is not FAT'
root_old_type="$(blkid -s TYPE -o value "$by_id-part2" 2>/dev/null || true)"
[[ "$root_old_type" == ext4 ]] ||
  fail 'owned root is not preformatted ext4 before reuse'
[[ "$(blockdev --getss "$disk")" == 512 ]] ||
  fail 'unexpected synthetic sector size'
[[ "$(blkid -s PTUUID -o value "$disk" | tr '[:upper:]' '[:lower:]')" ==
   6c8e012e-6c29-457e-a119-0cde4fa54dd6 ]] ||
  fail 'foreign disk GPT GUID'
[[ "$(blkid -s PARTUUID -o value "$by_id-part1" | tr '[:upper:]' '[:lower:]')" ==
   b65d9228-97af-4b13-b5fa-59f1d8d9653e ]] ||
  fail 'foreign ESP PARTUUID'
[[ "$(blkid -s PARTUUID -o value "$by_id-part2" | tr '[:upper:]' '[:lower:]')" ==
   6a8555cd-6dc0-45fa-8e66-9de78e41557b ]] ||
  fail 'foreign root PARTUUID'
[[ -s /run/gaslux-pop-lab/checkpoint.proof &&
   ! -L /run/gaslux-pop-lab/checkpoint.proof ]] ||
  fail 'independent synthetic checkpoint proof missing'
grep -Fxq 'GASLUX_POP_FULL_REUSE_CHECKPOINT_AND_RECOVERY_PROVEN=1' \
  /run/gaslux-pop-lab/checkpoint.proof ||
  fail 'synthetic checkpoint recovery not proven'

# Both installer artifacts must live inside the same GPG/SHA-verified ISO.
mapfile -t roots < <(find /cdrom -mindepth 2 -maxdepth 3 -type f \
  -name filesystem.squashfs -print | sort)
[[ "${#roots[@]}" == 1 ]] || fail 'missing or ambiguous Pop squashfs'
squashfs="${roots[0]}"
remove="${squashfs%/*}/filesystem.manifest-remove"
[[ -s "$squashfs" && -s "$remove" ]] ||
  fail 'Pop signed installation source/manifest absent'
printf 'GASLUX_POP_NATIVE_INSTALL_PREFLIGHT_OK=1\n' > /dev/ttyS0
trace=/sys/kernel/tracing
[[ -f "$trace/events/block/block_bio_queue/enable" ]] ||
  fail 'guest independent BIO queue tracepoint absent'
python3 -B /run/gaslux-pop-lab/bio-monitor.py \
  >/run/gaslux-pop-bio-stdout.log 2>/run/gaslux-pop-bio-stderr.log &
bio_pid="$!"
for _ in {1..80}; do
  [[ -s /run/gaslux-pop-bio-ready ]] && break
  kill -0 "$bio_pid" >/dev/null 2>&1 ||
    fail 'guest BIO monitor terminated before installer'
  sleep 0.1
done
[[ -s /run/gaslux-pop-bio-ready ]] ||
  fail 'guest BIO monitor did not become ready'

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
  --use "$disk:1:reuse:mount=/boot/efi" \
  --use "$disk:2:reuse:mount=/" \
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
sync
touch /run/gaslux-pop-bio-stop
bio_rc=0
wait "$bio_pid" || bio_rc="$?"
if [[ -s /run/gaslux-pop-bio-report.json ]]; then
  printf 'GASLUX_POP_FULL_BIO_JSON=%s\n' \
    "$(tr -d '\r\n' </run/gaslux-pop-bio-report.json)" > /dev/ttyS0
fi
[[ "$bio_rc" == 0 ]] || fail 'guest BIO stream incomplete or foreign disk write'
if [[ "$native_rc" != 0 ]]; then
  tail -n 55 "$log" > /dev/ttyS0
  fail "System76 native full installation failed (exit=$native_rc)"
fi
grep -Fq 'install was successful' "$log" ||
  fail 'native System76 success message missing'
sync
[[ "$(blkid -s TYPE -o value "$by_id-part2")" == ext4 ]] ||
  fail 'native full reuse changed ext4 root identity'

# These are independent installed-target checks, not a SquashFS copy.
mnt=/run/gaslux-pop-native-installed
mkdir -p "$mnt"
mount -t ext4 -o rw "$by_id-part2" "$mnt" || fail 'native root mount failed'
[[ -f "$mnt/etc/os-release" ]] || fail 'installed Pop OS identity missing'
(
  . "$mnt/etc/os-release"
  [[ "${ID:-}" == pop && "${VERSION_ID:-}" == 24.04 ]]
) || fail 'installed OS identity mismatch'
[[ -s "$mnt/sbin/init" || -s "$mnt/lib/systemd/systemd" ||
   -s "$mnt/usr/lib/systemd/systemd" ]] || fail 'native systemd absent'
[[ -d "$mnt/var/lib/dpkg" ]] || fail 'installed package database absent'

mkdir -p "$mnt/boot/efi"
mount -t vfat -o ro "$by_id-part1" "$mnt/boot/efi" ||
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
[[ "$(blkid -s PTUUID -o value "$disk" | tr '[:upper:]' '[:lower:]')" ==
   6c8e012e-6c29-457e-a119-0cde4fa54dd6 ]] ||
  fail 'complete installation changed GPT disk GUID'
printf 'GASLUX_POP_NATIVE_FULL_INSTALL_COMPLETED=1\n' > /dev/ttyS0
