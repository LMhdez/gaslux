#!/usr/bin/env bash
# VM-only genuine CachyOS Archiso -> pacstrap -> EFI GRUB -> installed first boot.
# Never call from the Windows installer. Never accepts physical disk paths.
set -Eeuo pipefail
# Output is mediated by the supervising systemd journal+console service.
# Never open ttyS0 directly: agetty/vhangup can revoke that descriptor.
trap 'rc=$?; if (( rc != 0 )); then echo "GASLUX_VM_INSTALL_FAILED:exit=$rc:line=$LINENO"; fi; sync' EXIT
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo 'GASLUX_VM_INSTALL_BEGIN'
# Lab-only preflight tracing. No passwords are ever passed to this script;
# disable tracing before pacstrap to avoid leaking package manager state.
PS4='+GASLUX_VM_PREFLIGHT_LINE:${LINENO}: '
set -x
[[ "$(id -u)" == 0 ]] || { echo 'Refusing unprivileged guest'; exit 11; }
case "$(systemd-detect-virt --vm)" in
  qemu|kvm) ;;
  *) echo 'Refusing non-QEMU/KVM guest'; exit 11 ;;
esac
[[ -r /run/gaslux-control/lab.env && -r /run/gaslux-control/stage.sh ]] || {
  echo 'Missing read-only laboratory control medium'; exit 12;
}
# This control medium is generated from the workflow checkout, not network.
# shellcheck source=/dev/null
source /run/gaslux-control/lab.env
[[ "$RUN_ID" =~ ^gaslux-vm-[a-f0-9]{16}$ ]] || exit 13
[[ "$ROOT_UUID" =~ ^[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$ ]] || exit 14
[[ "$STAGE_SHA256" =~ ^[a-f0-9]{64}$ ]] || exit 15
[[ "$STRICT_SHA256" =~ ^[a-f0-9]{64}$ ]] || exit 45
[[ "$TRUST_SHA256" =~ ^[a-f0-9]{64}$ ]] || exit 46
printf '%s  /run/gaslux-control/stage.sh\n' "$STAGE_SHA256" | sha256sum --check --status || {
  echo 'Stage script hash differs from pinned lab content'; exit 16;
}
printf '%s  /run/gaslux-control/strict-pacman.py\n' "$STRICT_SHA256" | sha256sum --check --status ||
  { echo 'Signed-only policy renderer has invalid SHA-256'; exit 47; }
printf '%s  /run/gaslux-control/pacman-trust.py\n' "$TRUST_SHA256" | sha256sum --check --status ||
  { echo 'Pacman trust policy guard has invalid SHA-256'; exit 48; }
# systemd-run's generated service can race with udev on live Archiso.
# Wait for all guest-owned virtio block devices before checking ownership.
echo 'GASLUX_VM_WAIT_DISK_DEVICE_DISCOVERY'
command -v udevadm >/dev/null || { echo 'udevadm missing'; exit 17; }
udevadm settle --timeout=90 || { echo 'udev did not settle'; exit 17; }
for _ in $(seq 1 60); do
  [[ -b /dev/vdb1 && -b /dev/vdc ]] && break
  sleep 1
done
[[ -b /dev/vdb1 && -b /dev/vdc ]] || {
  echo 'GASLUX_VM_DISKS_MISSING_AFTER_UDEV'
  lsblk -o NAME,TYPE,FSTYPE,LABEL || true
  exit 17
}
[[ "$(blkid -s LABEL -o value /dev/vdc)" == GASLUXESP ]] || exit 18
[[ "$(lsblk -dn -o TYPE /dev/vdc)" == disk ]] || exit 19
[[ ",$(findmnt -rn -M /run/gaslux-control -o OPTIONS)," == *,ro,* ]] || exit 20
export GASLUX_DISPOSABLE_VM=I_ACCEPT_DISPOSABLE_VM_ONLY
mkdir -p /mnt/target
mount -t ext4 -o rw /dev/vdb1 /mnt/target
# Reuse production-safe experimental ownership and Secure Boot preflight.
bash /run/gaslux-control/stage.sh --validate-target "$RUN_ID" "$ROOT_UUID"
echo 'GASLUX_VM_TARGET_ISOLATED'
# The official CachyOS/Archiso installer relies on live pacman keyring
# initialization and network availability. Running pacstrap concurrently
# with the live keyring service is unsafe and causes signature failures.
echo 'GASLUX_VM_WAIT_NETWORK'
command -v nm-online >/dev/null || { echo 'NetworkManager online probe missing'; exit 41; }
timeout 120s nm-online -q --timeout=90 || {
  echo 'GASLUX_VM_NETWORK_NOT_READY'; exit 42;
}
echo 'GASLUX_VM_WAIT_KEYRING'
# Archiso already starts pacman-init.service at boot. Calling systemctl
# start again races with the existing keyring setup and can hide the
# underlying failure behind the kernel-command-line.service exit code.
# Poll the single native initialization transaction instead. No pacstrap
# may proceed while this service is activating or failed.
keyring_ready=0
for attempt in $(seq 1 240); do
  if systemctl is-active --quiet pacman-init.service; then
    keyring_ready=1
    break
  fi
  if systemctl is-failed --quiet pacman-init.service; then
    echo 'GASLUX_VM_PACMAN_INIT_FAILED'
    break
  fi
  if (( attempt % 30 == 0 )); then
    echo "GASLUX_VM_PACMAN_INIT_WAIT_SECONDS=$attempt"
    systemctl show pacman-init.service -p LoadState -p ActiveState -p SubState -p Result --no-pager || true
  fi
  sleep 1
done
if (( keyring_ready != 1 )); then
  # Diagnostic output is permitted only after native service failure.
  # Never bypass package signature verification or delete keys here.
  echo 'GASLUX_VM_LIVE_KEYRING_NOT_READY'
  date -u --iso-8601=seconds || true
  systemctl status pacman-init.service --no-pager -l || true
  systemctl show pacman-init.service -p LoadState -p ActiveState -p SubState -p Result -p ExecMainStatus --no-pager || true
  journalctl -b -u pacman-init.service --no-pager -o cat -n 85 || true
  echo 'GASLUX_VM_PACMAN_KEYRING_DIAGNOSTICS_END'
  exit 43
fi
# The required trust anchors are vendor-supplied and must be present,
# never manufactured, downloaded without a pinned origin, or bypassed.
for keyring in archlinux cachyos; do
  [[ -s "/usr/share/pacman/keyrings/$keyring.gpg" ]] || {
    echo "GASLUX_VM_TRUST_ANCHOR_MISSING:$keyring"; exit 44;
  }
done
echo 'GASLUX_VM_NETWORK_KEYRING_READY'
set +x
# The authentic pinned CachyOS ISO has an inadequate effective package
# signature policy. Never use its pacman.conf as the install policy.
# Reuse the signed-only, HTTPS-filtering builder from experimental PR #27.
echo 'GASLUX_VM_SIGNED_ONLY_PREPARE_BEGIN'
strict_dir="/run/gaslux-pacman-$RUN_ID"
python3 /run/gaslux-control/strict-pacman.py --root / --run-id "$RUN_ID" --prepare-vm ||
  { echo 'GASLUX_VM_STRICT_PACMAN_RENDER_FAILED'; exit 49; }
[[ -s "$strict_dir/pacman-install.conf" && -s "$strict_dir/pacman-target.conf" ]] ||
  { echo 'GASLUX_VM_STRICT_PACMAN_FILES_MISSING'; exit 50; }
python3 /run/gaslux-control/pacman-trust.py --config "$strict_dir/pacman-install.conf" ||
  { echo 'GASLUX_VM_STRICT_PACMAN_TRUST_REJECTED'; exit 51; }
grep -Fxq 'LocalFileSigLevel = Required TrustedOnly' "$strict_dir/pacman-install.conf" ||
  { echo 'GASLUX_VM_LOCAL_SIGNATURE_POLICY_REJECTED'; exit 52; }
grep -Fxq 'RemoteFileSigLevel = Required TrustedOnly' "$strict_dir/pacman-install.conf" ||
  { echo 'GASLUX_VM_REMOTE_SIGNATURE_POLICY_REJECTED'; exit 53; }
echo 'GASLUX_VM_SIGNED_ONLY_POLICY_PASS'
echo 'GASLUX_VM_PACSTRAP_BEGIN'
# Genuine signed-only package installation. Never copy live squashfs rootfs,
# inherit the weak live pacman.conf, or bypass package signatures.
pacstrap -K -C "$strict_dir/pacman-install.conf" /mnt/target \
  base linux-cachyos mkinitcpio grub efibootmgr \
  cachyos-keyring cachyos-mirrorlist cachyos-settings cachyos-hooks \
  pacman e2fsprogs dosfstools
# Persist the same strict signing policy and filtered HTTPS mirror lists.
# The installed OS must NOT inherit the weaker ISO package configuration.
for name in mirrorlist cachyos-mirrorlist; do
  install -m 0644 "$strict_dir/$name" "/mnt/target/etc/pacman.d/$name"
  cmp -s "$strict_dir/$name" "/mnt/target/etc/pacman.d/$name" || exit 54
done
install -m 0644 "$strict_dir/pacman-target.conf" /mnt/target/etc/pacman.conf
cmp -s "$strict_dir/pacman-target.conf" /mnt/target/etc/pacman.conf || exit 55
grep -Fxq 'SigLevel = Required DatabaseOptional TrustedOnly' /mnt/target/etc/pacman.conf ||
  { echo 'GASLUX_VM_TARGET_PACKAGE_SIGNATURE_POLICY_REJECTED'; exit 56; }
echo 'GASLUX_VM_SIGNED_ONLY_INSTALLED_POLICY_PASS'
[[ -s /mnt/target/boot/vmlinuz-linux-cachyos ]] || {
  echo 'CachyOS pacstrap did not create a kernel'; exit 21;
}
[[ -s /mnt/target/var/lib/pacman/local/ALPM_DB_VERSION ]] || exit 22
grep -Eq '^ID="?cachyos"?$' /mnt/target/etc/os-release || {
  echo 'Installed target fails CachyOS distribution identity check'; exit 23;
}
mkdir -p /mnt/target/boot/efi
mount -t vfat -o rw /dev/vdc /mnt/target/boot/efi
genfstab -U /mnt/target > /mnt/target/etc/fstab
grep -F "$ROOT_UUID" /mnt/target/etc/fstab >/dev/null || exit 24
grep -F '/boot/efi' /mnt/target/etc/fstab >/dev/null || exit 25
printf 'gaslux-qemu-lab\n' > /mnt/target/etc/hostname
arch-chroot /mnt/target mkinitcpio -P
arch-chroot /mnt/target grub-install --target=x86_64-efi \
  --efi-directory=/boot/efi --removable --no-nvram --recheck
[[ -s /mnt/target/boot/efi/EFI/BOOT/BOOTX64.EFI ]] || exit 26
# This is a dedicated boot config only for the empty VM-only ESP; it never
# claims Windows dual-boot preservation or touches an existing ESP.
mkdir -p /mnt/target/boot/grub
cat > /mnt/target/boot/grub/grub.cfg <<EOF
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set default=0
set timeout=0
menuentry 'CachyOS installed VM test' {
  insmod part_gpt
  insmod ext2
  search --no-floppy --fs-uuid --set=root $ROOT_UUID
  linux /boot/vmlinuz-linux-cachyos root=UUID=$ROOT_UUID rw console=tty0 console=ttyS0,115200n8 systemd.unit=multi-user.target
  initrd /boot/initramfs-linux-cachyos.img
}
EOF
echo 'GASLUX_VM_GRUB_INSTALL_PASS'
if ! arch-chroot /mnt/target grub-script-check /boot/grub/grub.cfg; then
  echo 'GASLUX_VM_GRUB_SCRIPT_INVALID'
  exit 61
fi
echo 'GASLUX_VM_GRUB_CONFIG_PASS'
[[ -s /mnt/target/boot/initramfs-linux-cachyos.img ]] || exit 27
mkdir -p /mnt/target/usr/local/libexec
cat > /mnt/target/usr/local/libexec/gaslux-lab-firstboot-check <<'FIRSTBOOT'
#!/usr/bin/env bash
set -Eeuo pipefail
# Output is mediated by the supervising systemd journal+console service.
# Never open ttyS0 directly: agetty/vhangup can revoke that descriptor.
trap 'rc=$?; if (( rc != 0 )); then echo "GASLUX_VM_FIRSTBOOT_FAILED:exit=$rc"; fi' EXIT
# shellcheck source=/dev/null
source /etc/gaslux-lab-firstboot.env
[[ "$(cat /proc/1/comm)" == systemd ]] || exit 31
[[ "$(cat /.libertix-stage-owner)" == "$RUN_ID" ]] || exit 32
grep -Eq '^ID="?cachyos"?$' /etc/os-release || exit 33
[[ "$(findmnt -rn -M / -o FSTYPE)" == ext4 ]] || exit 34
rootdev="$(findmnt -rn -M / -o SOURCE)"
[[ -b "$rootdev" ]] || exit 35
[[ "$(blkid -s UUID -o value "$rootdev")" == "$ROOT_UUID" ]] || exit 36
[[ "$(uname -r)" == *cachyos* ]] || exit 37
[[ "$(pacman -Qq linux-cachyos)" == linux-cachyos ]] || exit 38
[[ -s /boot/vmlinuz-linux-cachyos && -s /boot/initramfs-linux-cachyos.img ]] || exit 39
[[ -s /boot/efi/EFI/BOOT/BOOTX64.EFI ]] || exit 40
echo "GASLUX_VM_FIRSTBOOT_PASS:$RUN_ID:$ROOT_UUID:$(uname -r)"
sync
systemctl --no-block poweroff
FIRSTBOOT
chmod 0755 /mnt/target/usr/local/libexec/gaslux-lab-firstboot-check
printf 'RUN_ID=%q\nROOT_UUID=%q\n' "$RUN_ID" "$ROOT_UUID" \
  > /mnt/target/etc/gaslux-lab-firstboot.env
chmod 0600 /mnt/target/etc/gaslux-lab-firstboot.env
cat > /mnt/target/etc/systemd/system/gaslux-lab-firstboot.service <<'UNIT'
[Unit]
Description=Gaslux experimental installed CachyOS first boot proof
After=local-fs.target
ConditionPathExists=/etc/gaslux-lab-firstboot.env

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/gaslux-lab-firstboot-check
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
UNIT
# Work on the validated VM-owned root directly; never contact live systemd
# or enable a unit on the host/Archiso. --root performs offline symlink edits.
if ! systemctl --root=/mnt/target enable gaslux-lab-firstboot.service; then
  echo 'GASLUX_VM_FIRSTBOOT_UNIT_ENABLE_FAILED'
  exit 62
fi
if ! systemctl --root=/mnt/target is-enabled --quiet gaslux-lab-firstboot.service; then
  echo 'GASLUX_VM_FIRSTBOOT_UNIT_NOT_ENABLED'
  exit 63
fi
echo 'GASLUX_VM_FIRSTBOOT_UNIT_ENABLED'
if ! systemctl --root=/mnt/target enable serial-getty@ttyS0.service; then
  echo 'GASLUX_VM_SERIAL_UNIT_ENABLE_FAILED'
  exit 64
fi
if ! systemctl --root=/mnt/target is-enabled --quiet serial-getty@ttyS0.service; then
  echo 'GASLUX_VM_SERIAL_UNIT_NOT_ENABLED'
  exit 65
fi
echo 'GASLUX_VM_SERIAL_UNIT_ENABLED'
sync
echo "GASLUX_VM_PACSTRAP_PASS:$RUN_ID:$ROOT_UUID"
systemctl --no-block poweroff
