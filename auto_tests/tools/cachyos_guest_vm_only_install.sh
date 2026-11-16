#!/usr/bin/env bash
# LAB ONLY: native pacstrap + EFI GRUB to a separate QEMU-created virtio disk.
# Windows, hardware devices and production NVRAM are NEVER exposed.
set -Eeuo pipefail
trap 'echo "GASLUX_LAB_INSTALL_FAILURE: line=$LINENO" >&2' ERR
die() { echo "GASLUX_LAB_INSTALL_FAILURE: $*" >&2; exit 1; }
TX=lab-real-iso-signed-20261116
ROOT_UUID=01234567-89ab-cdef-0123-456789abcdef
TARGET=/mnt/target
LINK=/dev/disk/by-id/virtio-GASLUXLABTARGET
[[ "${GASLUX_DISPOSABLE_VM:-}" == I_ACCEPT_DISPOSABLE_VM_ONLY ]] || die 'VM consent missing'
[[ "$(id -u)" == 0 ]] || die 'guest root required'
case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) die 'not QEMU/KVM' ;; esac
for tool in python3 sgdisk mkfs.ext4 mkfs.vfat blkid lsblk findmnt mount \
            pacstrap arch-chroot grub-script-check udevadm blockdev; do
  command -v "$tool" >/dev/null || die "missing $tool"
done
# Recheck the running kernel's ephemeral Ed25519-bound transaction before
# formatting even the specifically identified QEMU target disk.
python3 - <<'PY' || die 'signed boot or Secure Boot proof rejected'
import json
from pathlib import Path
expect=json.loads(Path('/run/gaslux-lab/boot-args.json').read_text())
keys={'gaslux.run','gaslux.nonce','gaslux.plan_sha256','gaslux.key_sha256'}
if not isinstance(expect,dict) or set(expect)!=keys:
    raise SystemExit('incomplete signed boot identity')
actual={}
for word in Path('/proc/cmdline').read_text().split():
    k,sep,v=word.partition('=')
    if k.startswith('gaslux.'):
        if k not in keys or not sep or not v or k in actual:
            raise SystemExit('unknown/duplicate signed boot parameter')
        actual[k]=v
if actual!=expect or actual['gaslux.run']!='lab-real-iso-signed-20261116':
    raise SystemExit('signed kernel handoff mismatch')
root=Path('/sys/firmware/efi/efivars')
guid='8be4df61-93ca-11d2-aa0d-00e098032b8c'
def flag(k):
    p=root/(k+'-'+guid)
    if not p.is_file() or p.is_symlink(): raise SystemExit('missing EFI flag')
    data=p.read_bytes()
    if len(data)!=5: raise SystemExit('invalid EFI flag')
    return data[4]
if flag('SecureBoot')!=0 or flag('SetupMode')!=1:
    raise SystemExit('no-key OVMF state mismatch')
PY
[[ -L "$LINK" ]] || die 'unique virtio target serial not found'
disk="$(readlink -f -- "$LINK")"
[[ -b "$disk" && "$disk" == /dev/vd? ]] || die 'unexpected target disk'
[[ "$(lsblk -dn -o TYPE "$disk")" == disk ]] || die 'target not whole disk'
size="$(blockdev --getsize64 "$disk")"
(( size >= 10000000000 && size <= 16000000000 )) || die 'wrong VM disk size'
[[ "$(lsblk -nr -o NAME "$disk" | wc -l)" -eq 1 ]] || die 'disk not empty'
[[ -z "$(lsblk -nr -o MOUNTPOINTS "$disk" | tr -d '[:space:]')" ]] || die 'disk in use'
[[ ! -e "$TARGET/.libertix-stage-owner" ]] || die 'reused target'
# Only this disposable virtual disk has the consented device serial.
sgdisk --clear \
  --new=1:1MiB:+512MiB --typecode=1:ef00 --change-name=1:GASLUX-LAB-ESP \
  --new=2:0:0 --typecode=2:8300 --change-name=2:GASLUX-LAB-ROOT "$disk"
udevadm settle
esp="$LINK-part1"; root="$LINK-part2"
for _ in {1..20}; do
  [[ -b "$esp" && -b "$root" ]] && break
  sleep 1
done
[[ -b "$esp" && -b "$root" ]] || die 'missing GPT partitions'
mkfs.vfat -F 32 -i AB12CD34 -n GASLUXESP "$esp"
mkfs.ext4 -q -F -U "$ROOT_UUID" -L GASLUXROOT "$root"
[[ "$(blkid -s UUID -o value "$root")" == "$ROOT_UUID" ]] || die 'root UUID mismatch'
[[ "$(blkid -s UUID -o value "$esp")" == AB12-CD34 ]] || die 'ESP UUID mismatch'
mkdir -p "$TARGET"
mount "$root" "$TARGET"
[[ "$(findmnt -rn -M "$TARGET" -o FSTYPE)" == ext4 ]] || die 'root mount mismatch'
printf '%s\n' "$TX" > "$TARGET/.libertix-stage-owner"
chmod 0600 "$TARGET/.libertix-stage-owner"
echo 'GASLUX_LAB_TARGET_PARTITIONED=1'
# Minimal, REAL CachyOS packages from official live pacman repos, with
# pacman's signature verification unchanged. NOT a finished desktop installer.
pacstrap -K "$TARGET" \
  base linux-cachyos-lts mkinitcpio grub efibootmgr \
  cachyos-keyring cachyos-mirrorlist cachyos-settings \
  sudo e2fsprogs dosfstools python
echo 'GASLUX_LAB_PACSTRAP_FINISHED=1'
grep -qx 'ID=cachyos' "$TARGET/etc/os-release" || die 'installed distro identity wrong'
[[ -s "$TARGET/boot/vmlinuz-linux-cachyos-lts" ]] || die 'kernel missing'
mkdir -p "$TARGET/boot/efi"
mount "$esp" "$TARGET/boot/efi"
cat > "$TARGET/etc/fstab" <<EOF
# Gaslux disposable QEMU only, transaction $TX
UUID=$ROOT_UUID / ext4 defaults 0 1
UUID=AB12-CD34 /boot/efi vfat umask=0077 0 2
EOF
printf '%s\n' gaslux-cachyos-ci > "$TARGET/etc/hostname"
printf '%s\n' LANG=en_US.UTF-8 > "$TARGET/etc/locale.conf"
grep -qx 'en_US.UTF-8 UTF-8' "$TARGET/etc/locale.gen" ||
  printf '%s\n' 'en_US.UTF-8 UTF-8' >> "$TARGET/etc/locale.gen"
arch-chroot "$TARGET" locale-gen
arch-chroot "$TARGET" ln -sfn /usr/share/zoneinfo/Etc/UTC /etc/localtime
arch-chroot "$TARGET" useradd -m -s /bin/bash gasluxtest
arch-chroot "$TARGET" passwd -l gasluxtest
arch-chroot "$TARGET" mkinitcpio -P
[[ -s "$TARGET/boot/initramfs-linux-cachyos-lts.img" ]] || die 'initramfs missing'
mkdir -p "$TARGET/etc/default/grub.d"
cat > "$TARGET/etc/default/grub.d/95-gaslux-ci.cfg" <<'EOF'
GRUB_TIMEOUT=2
GRUB_TIMEOUT_STYLE=menu
GRUB_DISABLE_OS_PROBER=true
GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0,115200n8 console=tty0 systemd.unit=multi-user.target"
EOF
# No NVRAM writes. --removable installs EFI fallback ONLY on VM ESP.
arch-chroot "$TARGET" grub-install --target=x86_64-efi \
  --efi-directory=/boot/efi --bootloader-id=GasluxLab \
  --no-nvram --removable --recheck
arch-chroot "$TARGET" grub-mkconfig -o /boot/grub/grub.cfg
arch-chroot "$TARGET" grub-script-check /boot/grub/grub.cfg
[[ -s "$TARGET/boot/efi/EFI/BOOT/BOOTX64.EFI" ]] || die 'EFI GRUB absent'
grep -Fq vmlinuz-linux-cachyos-lts "$TARGET/boot/grub/grub.cfg" ||
  die 'GRUB lacks installed kernel'
# The proof executes only after rebooting into the INSTALLED system. The
# second VM has exactly the target disk: no Archiso image or boot FAT.
mkdir -p "$TARGET/usr/local/sbin" "$TARGET/etc/systemd/system"
cat > "$TARGET/usr/local/sbin/gaslux-ci-firstboot-audit" <<'AUDIT'
#!/usr/bin/env bash
set -Eeuo pipefail
fail() { printf 'GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_FAIL: %s\n' "$*" >/dev/ttyS0; exit 1; }
case "$(systemd-detect-virt --vm)" in kvm|qemu) ;; *) fail 'not QEMU' ;; esac
[[ -d /sys/firmware/efi/efivars ]] || fail 'not UEFI'
grep -qx ID=cachyos /etc/os-release || fail 'not installed CachyOS'
[[ ! -e /run/archiso ]] || fail 'unexpected live Archiso'
[[ "$(findmnt -rn -M / -o FSTYPE)" == ext4 ]] || fail 'not installed ext4 root'
source="$(findmnt -rn -M / -o SOURCE)"
[[ "$(blkid -s UUID -o value "$source")" == 01234567-89ab-cdef-0123-456789abcdef ]] ||
  fail 'wrong installed root UUID'
[[ "$(cat /.libertix-stage-owner)" == lab-real-iso-signed-20261116 ]] ||
  fail 'owner missing'
[[ "$(findmnt -rn -M /boot/efi -o FSTYPE)" == vfat ]] || fail 'ESP not mounted'
[[ -s /boot/efi/EFI/BOOT/BOOTX64.EFI ]] || fail 'GRUB EFI missing'
[[ -s /boot/vmlinuz-linux-cachyos-lts &&
   -s /boot/initramfs-linux-cachyos-lts.img ]] || fail 'kernel/initrd missing'
pacman -Q linux-cachyos-lts grub base >/dev/null || fail 'pacman database invalid'
id gasluxtest >/dev/null || fail 'lab user missing'
[[ "$(uname -r)" == *cachyos* ]] || fail 'incorrect running kernel'
printf 'GASLUX_INSTALLED_CACHYOS_ROOT_UUID=01234567-89ab-cdef-0123-456789abcdef\n' >/dev/ttyS0
printf 'GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1\n' >/dev/ttyS0
AUDIT
chmod 0755 "$TARGET/usr/local/sbin/gaslux-ci-firstboot-audit"
cat > "$TARGET/etc/systemd/system/gaslux-ci-firstboot.service" <<'UNIT'
[Unit]
Description=Gaslux disposable installed CachyOS first-boot verification
After=local-fs.target
ConditionVirtualization=true

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gaslux-ci-firstboot-audit
TimeoutStartSec=40

[Install]
WantedBy=multi-user.target
UNIT
arch-chroot "$TARGET" systemctl enable gaslux-ci-firstboot.service
sync
echo 'GASLUX_LAB_TARGET_INSTALLED=1'
echo 'GASLUX_LAB_WINDOWS_RECOVERY_NOT_TESTED=1'
