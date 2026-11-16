#!/usr/bin/env bash
# Execute ONLY in a disposable QEMU guest with a Gaslux lab-owned GPT disk.
# Source: Q4OS 6.10 native GRUB package on a staged installed target.
# Never run in Windows, on the GitHub host, or as a production installer.
set -Eeuo pipefail

fatal() {
  printf 'GASLUX_Q4OS_NATIVE_GRUB_REFUSED=%s\n' "$*" > /dev/ttyS0 2>/dev/null || true
  printf 'GASLUX_Q4OS_NATIVE_GRUB_REFUSED: %s\n' "$*" >&2
  exit 1
}
[[ $# -eq 1 && ( "$1" == install || "$1" == verify-second ) ]] || fatal 'usage'
[[ "$EUID" -eq 0 ]] || fatal 'must-be-root-in-guest'
[[ -d /sys/firmware/efi ]] || fatal 'not-uefi'
[[ -r /sys/class/dmi/id/product_name && -r /sys/class/dmi/id/sys_vendor ]] ||
  fatal 'missing-hypervisor-evidence'
grep -Eiq 'QEMU|Bochs|Standard PC \(Q35' /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor ||
  fatal 'not-a-qemu-guest'
[[ -e /dev/ttyS0 ]] || fatal 'guest-serial-missing'
[[ "$(cat /etc/q4os_version)" == '6.10-deb13u1' ]] || fatal 'q4os-identity'
[[ -f /etc/gaslux-q4os-lab-root.uuid ]] || fatal 'missing-lab-ownership-proof'
root_device="$(findmnt -nro SOURCE /)"
esp_device="$(findmnt -nro SOURCE /boot/efi)"
[[ "$root_device" == /dev/vda2 && "$esp_device" == /dev/vda1 ]] ||
  fatal 'unexpected-guest-device-topology'
[[ "$(lsblk -nro PARTLABEL "$root_device")" == 'GASLUX-Q4OS-ROOT' ]] ||
  fatal 'root-partition-not-lab-owned'
[[ "$(lsblk -nro PARTLABEL "$esp_device")" == 'GASLUX-Q4OS-ESP' ]] ||
  fatal 'efi-partition-not-lab-owned'
[[ "$(findmnt -nro FSTYPE /)" == 'ext4' && "$(findmnt -nro FSTYPE /boot/efi)" == 'vfat' ]] ||
  fatal 'unexpected-mounted-filesystems'
root_uuid="$(blkid -s UUID -o value "$root_device")"
[[ "$root_uuid" == "$(cat /etc/gaslux-q4os-lab-root.uuid)" ]] ||
  fatal 'root-uuid-ownership-mismatch'
[[ ! -e /boot/efi/EFI/Microsoft ]] || fatal 'windows-efi-tree-not-allowed'
[[ ! -e /boot/efi/EFI/BOOT/bootmgfw.efi ]] || fatal 'windows-loader-not-allowed'
[[ "$(lsblk -d -n -o NAME,TYPE | awk '$2 == "disk" { print $1 }')" == 'vda' ]] ||
  fatal 'more-than-one-guest-disk'

native_loader='/boot/efi/EFI/GasluxQ4OSLab/grubx64.efi'
boot_fallback='/boot/efi/EFI/BOOT/BOOTX64.EFI'
state='/var/lib/gaslux-q4os-native-grub.sha256'
if [[ "$1" == verify-second ]]; then
  [[ -s "$state" && -s "$native_loader" && -s "$boot_fallback" ]] ||
    fatal 'missing-native-grub-after-reboot'
  actual="$(sha256sum "$boot_fallback" | cut -d' ' -f1)"
  [[ "$actual" == "$(cat "$state")" ]] || fatal 'second-boot-native-efi-hash'
  cmp -s "$native_loader" "$boot_fallback" || fatal 'fallback-does-not-match-native-grub'
  [[ -s /boot/grub/grub.cfg ]] || fatal 'native-grub-cfg-missing'
  [[ "$(uname -r)" == '6.12.111+deb13-amd64' ]] ||
    fatal 'second-kernel-version-does-not-match-pinned-q4os-iso'
  [[ -r /proc/cmdline ]] || fatal 'second-kernel-cmdline-unavailable'
  grep -Fq 'BOOT_IMAGE=' /proc/cmdline ||
    fatal 'second-kernel-was-not-started-by-grub'
  printf 'GASLUX_Q4OS_NATIVE_GRUB_SECOND_KERNEL=6.12.111+deb13-amd64\n' > /dev/ttyS0
  printf 'GASLUX_Q4OS_NATIVE_GRUB_SECOND_BOOT=6.10-deb13u1\n' > /dev/ttyS0
  exit 0
fi

[[ -s "$boot_fallback" && -s /etc/gaslux-q4os-lab-temp-efi.sha256 ]] ||
  fatal 'missing-owned-temporary-efi'
sha256sum --status -c /etc/gaslux-q4os-lab-temp-efi.sha256 ||
  fatal 'guest-efi-fallback-was-replaced'
[[ ! -e "$native_loader" && ! -e "$state" ]] || fatal 'native-target-already-present'
offline_dir='/var/cache/gaslux-q4os-lab'
[[ -d "$offline_dir" && -s "$offline_dir/grub-efi-amd64-bundle.sha256" ]] ||
  fatal 'missing-signed-apt-grub-bundle-manifest'
shopt -s nullglob
grub_debs=("$offline_dir"/grub-efi-amd64-unsigned_*_amd64.deb
           "$offline_dir"/grub-efi-amd64-bin_*_amd64.deb)
shopt -u nullglob
[[ "${#grub_debs[@]}" -eq 2 && -f "${grub_debs[0]}" && -f "${grub_debs[1]}" ]] ||
  fatal 'ambiguous-or-missing-grub-efi-package-bundle'
(cd "$offline_dir" && sha256sum --status -c grub-efi-amd64-bundle.sha256) ||
  fatal 'guest-efi-package-bundle-sha256-mismatch'
command -v dpkg >/dev/null || fatal 'missing-dpkg'
# Both packages were downloaded from a Debian 13 APT index authenticated by
# Debian's archive keyring on the runner. No network is attached to this VM.
dpkg -i "${grub_debs[@]}" > /dev/ttyS0 2>&1 ||
  fatal 'offline-native-grub-package-install-failed'
for package in grub-efi-amd64-unsigned grub-efi-amd64-bin; do
  [[ "$(dpkg-query -W -f='${Status}' "$package")" == 'install ok installed' ]] ||
    fatal "EFI-GRUB-package-not-installed-$package"
done
dpkg -S /usr/lib/grub/x86_64-efi/normal.mod >/dev/null ||
  fatal 'EFI-GRUB-modules-not-package-owned'
for tool in grub-install grub-mkconfig sha256sum sync; do
  command -v "$tool" >/dev/null || fatal "missing-native-package-$tool"
done
mkdir -p /etc/default/grub.d
cat > /etc/default/grub.d/99-gaslux-q4os-guest-only.cfg <<'CFG'
GRUB_TIMEOUT=1
GRUB_DEFAULT=0
GRUB_TERMINAL="serial console"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"
GRUB_CMDLINE_LINUX="console=ttyS0,115200n8 console=tty0 systemd.unit=multi-user.target"
GRUB_DISABLE_OS_PROBER=true
CFG
# No NVRAM modification and no --removable. Native Q4OS package writes
# only into the guest-owned ESP. Do not copy this procedure to a Windows ESP.
grub-install --target=x86_64-efi --efi-directory=/boot/efi \
  --bootloader-id=GasluxQ4OSLab --no-nvram --recheck > /dev/ttyS0 2>&1 ||
  fatal 'native-grub-install-failed'
if ! grub-mkconfig -o /boot/grub/grub.cfg > /var/log/gaslux-q4os-grubcfg.log 2>&1; then
  printf 'GASLUX_Q4OS_NATIVE_GRUB_CONFIG_DIAGNOSTICS_BEGIN\n' > /dev/ttyS0
  tail -n 100 /var/log/gaslux-q4os-grubcfg.log > /dev/ttyS0 || true
  # Run a second, TRACE-ONLY investigation *inside this disposable guest*.
  # Never treat its result as a successful install or alter fallback/NVRAM.
  /bin/sh -x /usr/sbin/grub-mkconfig -o /boot/grub/grub.cfg \
    > /var/log/gaslux-q4os-grubcfg-trace.log 2>&1 || true
  tail -n 90 /var/log/gaslux-q4os-grubcfg-trace.log > /dev/ttyS0 || true
  fatal 'native-grub-config-failed'
fi
sha256sum --status -c /etc/gaslux-q4os-lab-temp-efi.sha256 ||
  fatal 'native-grub-modified-fallback-without-ownership'
[[ -s "$native_loader" && -s /boot/grub/grub.cfg ]] || fatal 'native-grub-file-missing'
# Only the VM-created fallback from this one guest is allowed to be replaced.
cp -- "$native_loader" "${boot_fallback}.gaslux-next"
chmod 0644 "${boot_fallback}.gaslux-next"
mv -f -- "${boot_fallback}.gaslux-next" "$boot_fallback"
cmp -s "$native_loader" "$boot_fallback" || fatal 'native-loader-copy-failed'
mkdir -p /var/lib
sha256sum "$native_loader" | cut -d' ' -f1 > "$state"
ln -s /etc/systemd/system/gaslux-q4os-native-second.service \
  /etc/systemd/system/multi-user.target.wants/gaslux-q4os-native-second.service
rm -f /etc/systemd/system/multi-user.target.wants/gaslux-q4os-native-grub.service
sync
printf 'GASLUX_Q4OS_NATIVE_GRUB_INSTALLED=6.10-deb13u1\n' > /dev/ttyS0
