# CachyOS support: initial, non-installing backend groundwork

**Status: research/preflight only. Do not advertise CachyOS in release-config.json or the Windows wizard.**

The existing Libertix installer is designed for Debian/Ubuntu derived operating systems. The
CachyOS live ISO is an **Archiso environment**, not an installed root filesystem ready to copy
into Libertix's `/mnt/target` and boot. Adding a URL and checksum to `release-config.json` would
be unsafe. This preliminary work provides a **read-only** ISO format verifier and tests only.

## Confirmed upstream differences

- Libertix uses `casper/filesystem.squashfs` discovery and requires `dpkg`, `update-initramfs`,
  `lsinitramfs`, and `update-grub` inside the target.
- CachyOS's official `CachyOS-Live-ISO/archiso/profiledef.sh` configures `airootfs_image_type=squashfs`.
  An Archiso image is normally `arch/x86_64/airootfs.sfs`.
- The CachyOS live ISO **sets `ID=arch`, `NAME="CachyOS"`**, from
  `CachyOS-Live-ISO/archiso/airootfs/etc/os-release`. It is not safe to rely on `ID=cachyos`.
- Current CachyOS installation is managed through its own installer with online package setup;
  directly extracting the live root is not a functional substitute for the official installer.
- CachyOS's installation documentation requires Secure Boot **and CSM disabled** for initial UEFI
  installation. This conflicts with Libertix's current signed Ubuntu shim boot architecture.

## Inspect an ISO (read-only)

With a CachyOS ISO **already mounted or extracted** at `/mnt/cachyos-iso`:

```bash
python3 assets/live/libertix-cachyos-preflight.py /mnt/cachyos-iso
python3 -m unittest discover -s auto_tests -p test_cachyos_preflight.py -v
```

The JSON output intentionally sets `libertix_installation_supported=false`; success means
"this looks like the expected CachyOS Archiso image", **not** "installable with Libertix".

## Necessary changes before release support

1. Define a separate `archiso-cachyos` installation backend in distribution metadata and
   extend schema validation, Windows UI, PowerShell policy and release signing. Keep it disabled
   until an immutable, SHA-256-verified supported ISO release is chosen.
2. Design a CachyOS-specific installation source, matching the current online installation
   repository and CachyOS package installation flow. Never copy the live Archiso image as though
   it were the target system.
3. Make the target configuration distro-aware (create user, locale, keyboard, time zone, sudo
   `wheel`, pacman database/keyring, initramfs with mkinitcpio or dracut, package hooks).
4. Implement a separate GRUB/EFI path and kernel filename verification, without
   `shim-signed`, `grub-efi-amd64-signed` or `dpkg-divert` assumptions. Do not make changes to
   Secure Boot firmware keys automatically.
5. Preserve Libertix's transaction-owned disk geometry, rollback markers, boot state and
   Windows recovery chain. New paths require matching static and runtime validations.
6. Test UEFI/GPT dual boot with Windows 10 and Windows 11 in isolated snapshots, including power
   loss, failed downloads, Secure Boot enabled (fail before any mutation), and installation abort.
   Do not test an unverified build on the user's production Windows installation.

## References

- https://github.com/ekimiateam/libertix/blob/main/docs/ARCHITECTURE.md
- https://github.com/ekimiateam/libertix/blob/main/assets/live/libertix-distribution-common.sh
- https://github.com/CachyOS/CachyOS-Live-ISO/blob/master/archiso/profiledef.sh
- https://github.com/CachyOS/CachyOS-Live-ISO/blob/master/archiso/airootfs/etc/os-release
- https://wiki.cachyos.org/installation/installation_on_root/
