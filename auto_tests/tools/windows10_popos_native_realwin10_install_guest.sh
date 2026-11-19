#!/usr/bin/env bash
# Native System76 on SECOND disposable QCOW2 child of REAL Win10 only.
# Windows backing and six-GPT stage are never writable during this run.
set -Eeuo pipefail
fail() {
  printf 'GASLUX_POP_NATIVE_INSTALL_FAILURE: %s\n' "$*" > /dev/ttyS0
  exit 1
}
[[ $# -eq 0 && "$(id -u)" == 0 ]] ||
  fail 'unexpected native install arguments or non-root shell'
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;;
  *) fail 'not a disposable virtual machine' ;;
esac
[[ "$(printenv GASLUX_POP_NATIVE_COW_WRITER_CONSENT || true)" == \
  I_ACCEPT_DISPOSABLE_POP_NATIVE_ONLY_OWNED_PARTITIONS ]] ||
  fail 'explicit native guest child consent absent'
[[ "$(printenv GASLUX_POP_LIVE_GPT_RO_CONSENT || true)" == \
  I_ACCEPT_DISPOSABLE_GUEST_GPT_READ_ONLY ]] ||
  fail 'prior guest GPT audit consent missing'
[[ "$(findmnt -rn -M /run/gaslux-pop-lab -o FSTYPE)" == vfat ]] ||
  fail 'native handoff must be a FAT control disk'
findmnt -rn -M /run/gaslux-pop-lab -o OPTIONS | tr , '\n' |
  grep -Fxq ro || fail 'native handoff must remain readonly'

# Signed Ed25519 plan + authentic ISO agent SHA + direct Linux GPT,
# Windows partitions, OVMF SecureBoot and exact guest block geometry.
python3 -B /run/gaslux-pop-lab/windows10_popos_native_prewrite_guest.py ||
  fail 'native Windows owner GPT/signed handoff refused before any write'
printf 'GASLUX_POP_NATIVE_INSTALL_PREFLIGHT_OK=1\n' > /dev/ttyS0

# Host QEMU only attaches private native child writable. Guest uniquely binds
# serial, disk geometry and GUIDs. Windows partitions 1-4 are never mounted.
byid=/dev/disk/by-id/virtio-GASLUX_POP_WIN10_COW
[[ -b "$byid" && -b "$byid-part5" && -b "$byid-part6" ]] ||
  fail 'exact Pop-owned Win10 COW partition missing'
disk="$(readlink -e "$byid")"
[[ "$disk" =~ ^/dev/vd[a-z]{1,2}$ ]] ||
  fail 'unrecognized target disk identity'
[[ "$(lsblk -dn -o SERIAL "$disk" | tr -d '[:space:]')" == \
  GASLUX_POP_WIN10_COW ]] || fail 'guest virtio target serial mismatch'
[[ "$(blockdev --getsize64 "$disk")" == 137438953472 ]] ||
  fail 'unapproved Win10/Pop disk byte length'
[[ "$(blockdev --getss "$disk")" == 512 ]] ||
  fail 'unapproved Win10/Pop logical sector size'

source_list=/run/gaslux-native-squashfs-list
find /cdrom -mindepth 2 -maxdepth 4 -type f \
  -name filesystem.squashfs -print | sort > "$source_list"
[[ "$(wc -l < "$source_list")" == 1 ]] ||
  fail 'ambiguous native System76 live SquashFS'
squashfs="$(cat "$source_list")"
remove="$(dirname "$squashfs")/filesystem.manifest-remove"
[[ -s "$squashfs" && -s "$remove" ]] ||
  fail 'authenticated Pop native removal manifest absent'
[[ -f /usr/bin/distinst && ! -L /usr/bin/distinst ]] ||
  fail 'verified native System76 distinst absent'

# FIRST WRITES: exclusively Pop #5/#6 of disposable VM child, never Windows.
command -v mkfs.vfat >/dev/null || fail 'native FAT32 formatter absent'
[[ -z "$(blkid -p -s TYPE -o value "$byid-part5" 2>/dev/null || true)" ]] ||
  fail 'owned Pop ESP already formatted'
[[ -z "$(blkid -p -s TYPE -o value "$byid-part6" 2>/dev/null || true)" ]] ||
  fail 'owned Pop root already formatted'
mkfs.vfat -F 32 -n GASLUXPOP "$byid-part5" >/dev/null ||
  fail 'owned Pop ESP FAT32 format failed'
[[ "$(blkid -s TYPE -o value "$byid-part5")" == vfat ]] ||
  fail 'new Pop-only ESP not FAT32'
sync
printf 'GASLUX_POP_NATIVE_OWNED_ESP5_ONLY_FORMATTED=1\n' > /dev/ttyS0

log="$(mktemp -p /run -t gaslux-win10-pop-distinst.XXXXXXXX)"
printf 'GASLUX_POP_NATIVE_INSTALL_DISTINST_STARTED=1\n' > /dev/ttyS0
# Genuine System76 native installer, no --test, --new-table or --modify-boot.
# --no-efi-vars forbids BootOrder/NVRAM modification by the installer.
timeout --kill-after=15s 1500s /usr/bin/distinst \
  --no-efi-vars --squashfs "$squashfs" --remove "$remove" \
  --hostname gaslux-pop-vm --keyboard us --lang en_US.UTF-8 \
  --block "$disk" \
  --use "$disk:5:reuse:mount=/boot/efi" \
  --use "$disk:6:ext4:mount=/" > "$log" 2>&1 &
native_pid="$!"
while kill -0 "$native_pid" >/dev/null 2>&1; do
  sleep 40
  printf 'GASLUX_POP_NATIVE_INSTALL_DIAGNOSTIC_TAIL_BEGIN\n' > /dev/ttyS0
  tail -n 5 "$log" | cut -c1-220 > /dev/ttyS0 || true
  printf 'GASLUX_POP_NATIVE_INSTALL_DIAGNOSTIC_TAIL_END\n' > /dev/ttyS0
done
rc=0
wait "$native_pid" || rc="$?"
if [[ "$rc" != 0 ]]; then
  tail -n 60 "$log" > /dev/ttyS0
  fail "native System76 installer failed ($rc)"
fi
grep -Fq 'install was successful' "$log" ||
  fail 'native System76 success message absent'
sync
[[ "$(blkid -s TYPE -o value "$byid-part6")" == ext4 ]] ||
  fail 'native installed root is not ext4'

# Independent real OS / systemd-boot / package metadata checks.
mnt=/run/gaslux-pop-native-realwin10-installed
mkdir -p "$mnt"
mount -t ext4 -o rw "$byid-part6" "$mnt" ||
  fail 'native installed root inaccessible'
[[ -s "$mnt/etc/os-release" ]] || fail 'installed OS identity missing'
(
  . "$mnt/etc/os-release"
  [[ "$ID" == pop && "$VERSION_ID" == 24.04 ]]
) || fail 'installed target not Pop 24.04'
[[ -d "$mnt/var/lib/dpkg" && -x "$mnt/usr/bin/apt-get" ]] ||
  fail 'native installed package database missing'
mkdir -p "$mnt/boot/efi"
mount -t vfat -o ro "$byid-part5" "$mnt/boot/efi" ||
  fail 'native Pop ESP inaccessible readonly'
[[ -s "$mnt/boot/efi/EFI/systemd/systemd-bootx64.efi" ]] ||
  fail 'native systemd-boot EFI binary absent'
[[ -s "$mnt/boot/efi/EFI/BOOT/BOOTX64.EFI" ]] ||
  fail 'native systemd-boot fallback EFI absent'
[[ ! -e "$mnt/boot/efi/EFI/Microsoft/Boot/bootmgfw.efi" ]] ||
  fail 'Windows loader must remain only in Windows ESP'
[[ -n "$(find "$mnt/boot/efi/loader/entries" -maxdepth 1 \
  -name '*.conf' -type f -print -quit)" ]] ||
  fail 'native systemd-boot entry missing'
umount "$mnt/boot/efi" || fail 'Pop ESP failed to unmount'

# Boot witness inserted AFTER the System76 installer finished.
proof=/run/gaslux-pop-lab/firstboot.sh
[[ -s "$proof" && ! -L "$proof" ]] ||
  fail 'verified VM-only firstboot witness missing'
install -D -m 0755 "$proof" "$mnt/usr/local/libexec/gaslux-pop-realwin10-firstboot"
install -d "$mnt/etc/systemd/system/multi-user.target.wants"
cat > "$mnt/etc/systemd/system/gaslux-pop-realwin10-firstboot.service" <<'UNIT'
[Unit]
Description=Gaslux VM-only genuine Pop installed on Windows GPT proof
After=local-fs.target
ConditionPathExists=/usr/local/libexec/gaslux-pop-realwin10-firstboot
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/gaslux-pop-realwin10-firstboot
TimeoutStartSec=40
[Install]
WantedBy=multi-user.target
UNIT
ln -s ../gaslux-pop-realwin10-firstboot.service \
  "$mnt/etc/systemd/system/multi-user.target.wants/gaslux-pop-realwin10-firstboot.service"
sync
umount "$mnt" || fail 'Pop root failed to unmount'
printf 'GASLUX_POP_NATIVE_FULL_INSTALL_COMPLETED=1\n' > /dev/ttyS0
