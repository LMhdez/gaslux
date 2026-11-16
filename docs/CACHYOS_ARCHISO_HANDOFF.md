# CachyOS Archiso handoff — integration boundary

**Experimental only. Not a Windows-to-CachyOS installer.**

Libertix's Debian mini-ISO extracts a Debian/Ubuntu filesystem.squashfs.
CachyOS instead uses Archiso: airootfs.sfs plus its own live kernel and
initramfs. The official CachyOS loopback.cfg accepts img_dev=UUID and
img_loop to boot a verified ISO file from another filesystem.

## Delivered

- assets/live/cachyos-archiso-handoff.py renders a read-only GRUB loopback
  entry only after checking an explicit transaction identity, UEFI mode,
  Secure Boot disabled, strict ISO path, size, SHA-256, a matched live
  kernel/initramfs pair (preferring the official LTS variant),
  and the SHA-pinned 260809 squashfs identity (ID=cachyos,
  ID_LIKE=arch, NAME=CachyOS Linux, IMAGE_ID=cachyos and
  IMAGE_VERSION=2026.08.09; pacman present).
- The optional --require-mounted-iso mode additionally checks that the
  ISO source is on an exact filesystem/UUID mount and that the read-only
  ISO9660 mount really comes from the hashed loop-backed source.
- Test files auto_tests/test_cachyos_archiso_handoff.py reject wrong hashes,
  UUIDs, path injections, symlinks, missing boot components and wrong mounts.
- Two QEMU/OVMF jobs actually run GRUB and find Archiso files within
  synthetic ISO images on ext4 and NTFS virtual disks.
- The official ISO inspection workflow validates the pinned 260809 desktop
  release using CachyOS's published SHA-256:
  959f6577f45e25ee9fd8c220fd221b08e4ea79412c7315c0f922dd6d86d5e33c.

Synthetic tests prove EFI GRUB loopback file discovery, not that the real
Archiso initramfs can mount the ISO or that the CachyOS kernel boots.

## Release blockers (issue #3)

1. Integrate immutable signed CachyOS ISO metadata with Windows C#,
   PowerShell, deployment catalog and installation-plan schema.
2. Safely build a temporary firmware boot entry for verified Archiso
   with a complete Windows/EFI rollback transaction; verify NTFS clean
   shutdown, Fast Startup and BitLocker policy before any disk mutation.
3. Ensure the live Archiso can authenticate the same installation plan,
   launch the pacstrap stage and resume after power or network failure.
4. Finish final CachyOS GRUB, first-boot verification, kernel update guards,
   and full Windows BCD/WinRE restoration and boot health checks.
5. Execute the complete Windows 10/11 dual-boot, failure injection and
   recovery matrix using actual virtual machine images. Retest on real
   hardware only with backups and tested restore procedures.

CachyOS remains intentionally absent from release-config.json.
Do not merge this development branch as a production release.

References:
https://github.com/CachyOS/CachyOS-Live-ISO/blob/master/archiso/grub/loopback.cfg
https://github.com/CachyOS/CachyOS-Live-ISO/blob/master/archiso/grub/grub.cfg
https://wiki.cachyos.org/cachyos_basic/download/
https://build.cachyos.org/ISO/desktop/260809/
