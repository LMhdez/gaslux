# CachyOS UEFI/GPT — write-set GRUB/ESP DENY-only

Observed 2026-11-22 UTC. Experimental read-only review; no writing, Windows,
QEMU, Archiso, pacstrap, GRUB installation or efibootmgr was executed here.

## Exact source pinned to #314 7d55bd4a

| Module | Git blob SHA-1 | Actually implemented |
| --- | --- | --- |
| assets/live/cachyos-stage-target.sh | 453f04b0a20ffc475ff3b4fc9614c80dc82515fe | pacstrap and mkinitcpio -P in owned VM ext4; **no grub-install** |
| assets/live/cachyos-uefi-config.py | f5743d5ca1e9d7b33f7ac45713bc24aa0776a2ab | pure fstab/GRUB/Windows entry renderer, no write |
| assets/live/cachyos-uefi-lab.py | 90bd65a2d2df0ce22a83fc9488dcc03f7b64292d | **executable** disposable VM GRUB install/mkconfig, ESP changes, rollback |
| auto_tests/tools/cachyos_configure_installed.py | 979551dc10adff8ad960642026a395ce18f76f57 | lab account, locale, systemd on ext4, not EFI |

The source-gated Python model verifies exact content hash and parses the
real UEFI lab AST to require the exact grub-install flags --no-nvram,
--no-extra-removable, --target=x86_64-efi,
--efi-directory=/boot/efi and --bootloader-id=Gaslux-CachyOS. It also
checks the literal grub-mkconfig candidate and grub-script-check path.
Matching the pinned source code does **not** authenticate the external
GRUB executable, kernel package, ESP or QEMU disk.

## Actual proposed write-set, all authorization=false

| Actor | Expected target | Physical scope / Windows risk |
| --- | --- | --- |
| pacstrap kernel / mkinitcpio -P | /boot/vmlinuz-linux-cachyos, /boot/initramfs-linux-cachyos.img | Linux ext4 intended; kernel package hooks dynamic |
| lab fstab/defaults/Windows entry text | /etc/fstab, /etc/default/grub.d/99-gaslux.cfg, /etc/grub.d/45_gaslux_windows | Linux ext4 intended; GRUB generator hooks not authenticated |
| lab EFI mkdir/marker | /boot/efi/EFI/Gaslux-CachyOS, .gaslux-owner | Windows shared ESP; marker does not authenticate child-file ownership |
| grub-install executable | /boot/efi/EFI/Gaslux-CachyOS/grubx64.efi | ESP; additional external binary effects not traced |
| grub-install modules | /boot/grub/** | Linux ext4; unbounded effective write list |
| grub-mkconfig + os.link | /boot/grub/grub.cfg.gaslux-candidate then /boot/grub/grub.cfg | Linux ext4; validates only generated text and candidate |
| exception rollback | /boot/efi/EFI/Gaslux-CachyOS/** | ESP; recursive rmtree after marker check, insufficient child ownership |
| exception rollback | generated GRUB candidate and root configuration files | Linux ext4; pathname/mode checks not full inode ownership proof |

On the intended layout, /boot resides on Linux ext4, /boot/efi is a
shared Windows FAT32 ESP. **Neither physical mapping is independently
attested by the lab script**: it checks filesystem UUIDs with blkid
and owner marker text but not an authenticated GPT disk GUID/PARTUUID/FD
transaction. Source claim agreement is not authority.

The renderer references /EFI/Microsoft/Boot/bootmgfw.efi via a
chainloader stanza; that is read-only text. The VM lab reads/hashes
bootmgfw.efi before/after, but **does not** authenticate BCD, WinRE,
other Microsoft loaders, OEM, BootOrder/BootNext or rollback in-place.
Historical #263 shows 682 changed BCD bytes in both A and B; writer
attribution and mutation approval are absent.

--no-nvram and --no-extra-removable are command-line intentions, not
proof of unchanged firmware NVRAM or fallback EFI. Any proposal touching
EFI/Microsoft, EFI/BOOT, EFI/OEM, EFI/Recovery, EFI/Libertix, BootOrder,
BootNext or unknown paths is rejected before any action.

The generic Debian-family libertix-sync-efi.sh and libertix-update-grub.sh
use signed shim/dpkg and EFI/Libertix; they are NOT a validated CachyOS
pacman/GRUB update strategy. No Arch-native kernel/EFI update, reboot
persistence, native dual boot or Windows rollback is proven.

## Model and threat boundary

auto_tests/tools/cachyos_uefi_writeset_readonly.py creates a bounded
inspection-only manifest. It requires an exact UEFI Secure-Boot-disabled
plan rendered by the actual pinned pure renderer and consistent expected
and observed *claims* of transaction, GPT disk GUID, ESP PARTUUID, VFAT
UUID, 512-byte sector, disk bytes and ESP offsets/length. Self-provided
matching claims do not independently prove physical identity.

All model output remains:
- status=BOOT_WRITESET_MODEL_ONLY_DENY_NO_WRITER
- espIdentityAuthority=CLAIMED_NOT_FD_AUTHENTICATED
- each operation authorization=false, ownershipVerified=false
- sourceEvidence=PINNED_SOURCE_STATIC_ONLY
- destinationIdentity=UNVERIFIED_PHYSICAL_MAPPING
- all Windows, EFI fallback, firmware order, rollback, dual boot and
  release authorization flags false.

check_proposal rejects unlisted operations, foreign transaction/ESP,
path traversal, Microsoft/OEM/Recovery/fallback EFI, firmware BootOrder/
BootNext and unexpected GRUB updates. A syntactically matching proposal
STILL returns authorization=false.

The model does not run scripts or probe disks, and cannot prove the
external grub-install effective write-set or safe rmtree rollback.
Before any future writer, require an authenticated transaction ownership,
pinned ESP GPT/FD+PARTUUID, recovery baseline, **actual** GRUB/EFI
write observation, full child-file ownership, Windows BCD/WinRE,
NVRAM preservation and a distinct native Arch update/recovery path.

P3 pacstrap or a generated GRUB menu is not P4 native dual-boot proof.
#314 remains draft untouched; #263 operational KVM remains gated;
#279 ETW/BCD contracts untouched. Request Safety review of only this
new write-set model and its unproven external effects; no ETW-01 rerun.
