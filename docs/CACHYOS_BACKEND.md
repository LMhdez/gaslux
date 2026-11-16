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


## Experimental target provisioning stage (not production)

Added in `feature/cachyos-target-backend`:

- `assets/live/cachyos-stage-target.sh` only runs from the official CachyOS
  Archiso with UEFI firmware and *provably disabled* Secure Boot. It refuses
  a missing/different transaction marker, root UUID mismatch, wrong filesystem,
  existing OS installation or unrelated target files.
- The installer invokes `pacstrap -K` to install a basic CachyOS KDE desktop.
  It creates an account, configures locale/hostname/timezone, provisions sudo,
  generates the initramfs, and enables SDDM and NetworkManager.
- The stage **never partitions/formats disks, never writes Windows volumes,
  never installs EFI files or GRUB, and never changes UEFI NVRAM**.
  It requires an ext4 mount already prepared at `/mnt/target` and a matching
  `.libertix-stage-owner` file left by a separately trusted transaction.
- `assets/live/cachyos-target-verify.py` checks a provisioned root read-only:
  installed CachyOS identity, key pacman packages, user/wheel/sudo, kernel and
  initramfs, and optional fstab/GRUB/EFI artifact presence. It always reports
  `bootable_proved=false` and `windows_recovery_proved=false`.
- `auto_tests/test_cachyos_target_verify.py` contains disk-free unit tests.
  The `CachyOS backend safety tests` GitHub Action runs them alongside the
  original ISO preflight tests.

**Lab command (inspect only):**

```bash
bash assets/live/cachyos-stage-target.sh --check
python3 -m unittest discover -s auto_tests -p 'test_cachyos_*.py' -v
```

The `--install` mode is **for an explicitly configured disposable VM only**.
It is not connected to Windows, cannot complete a bootable installation, and
has never been tested with real CachyOS package repositories by this workflow.

## Remaining mandatory release blockers

1. Source/target transport: Libertix's mini-ISO is Debian-based. It cannot
   invoke the Archiso-only pacstrap stage. Design a verified Archiso handoff
   preserving the signed installation-plan identity and independent rollback.
2. Wire distribution/backend catalog choices across Windows C#, PowerShell,
   JSON schemas and the signed release mechanism. Do not add the CachyOS
   selection before a boot-and-recovery test matrix succeeds.
3. Build an Arch-aware fstab, GRUB configuration and EFI installation path
   which preserves the current Windows Boot Manager and handles kernel updates.
   Do not reuse Debian shim, dpkg-divert, APT hooks or Debian initramfs names.
4. Adapt BIOS/UEFI final verification, Windows recovery/rollback, boot ownership,
   the first-boot verifier and Windows-side success-evidence contracts.
5. Full VM test matrix: Windows 10 and 11 UEFI/GPT, successful dual boot,
   failed downloads, network absence, power interruption and rollback,
   Secure Boot enabled rejection before disk mutation, Windows health after
   failure, and Linux package/kernel updates.
6. Separately perform supervised test deployments on real hardware, including
   backup and restore validation. **Until then, do not label this stable.**

### Notes

The official CachyOS ISO's `os-release` uses `ID=arch`, whereas an installed
CachyOS root is expected to use `ID=cachyos`. The verifier deliberately
rejects an Archiso live system as an installed target. This distinction must
remain explicit in any final installer pipeline.


## QEMU/KVM UEFI laboratory boot stage (still NOT stable)

A separate branch implements a **lab-only** UEFI configuration and bootloader
installation path. This DOES NOT connect to the Windows WPF installer.

- `assets/live/cachyos-uefi-config.py`: pure, read-only JSON renderer for an
  already authenticated transaction. Requires exact ext4 UUID, ESP UUID,
  Windows ESP UUID, a trusted Windows Boot Manager SHA-256, UEFI firmware and
  disabled Secure Boot. Rejects unknown fields, malformed identifiers,
  cross-ESP chainloads and command injection.
- `assets/live/cachyos-uefi-lab.py`: default mode only prints the generated
  fstab and Windows GRUB entry. `--apply-vm-lab` requires root, a QEMU/KVM
  guest, UEFI Secure Boot *provably disabled*, and the environment variable
  `GASLUX_DISPOSABLE_VM=I_ACCEPT_DISPOSABLE_VM_ONLY`.
- For a dedicated disposable guest **with its own virtual Windows/ESP and
  Linux volumes already created**, the apply stage additionally checks Linux
  UUID/transaction ownership and the SHA-256 of the Windows loader before
  writing. It refuses existing Linux configuration/EFI objects, then runs
  `grub-install --target=x86_64-efi --no-nvram --no-extra-removable` in the
  Arch chroot. It verifies GRUB syntax, Linux/Windows menu entries, the EFI
  executable, and rechecks the Windows loader hash.
- No `efibootmgr` writes or firmware BootOrder changes are implemented.
  Windows EFI files are never overwritten. Consequently this stage **does
  not demonstrate an automatically bootable installation**.
- Failure cleanup is limited to transaction-created guest files and EFI
  directories. The full Windows partition/BCD/WinRE recovery system is
  neither invoked nor validated here.

### Read-only local test

Example plan input (replace values with *verified values from a disposable
virtual machine*; do not use production disk identifiers):

```json
{
  "version": 1,
  "firmware": "uefi",
  "secureBootEnabled": false,
  "runId": "cachyos-lab-2026",
  "rootUuid": "01234567-89ab-cdef-0123-456789abcdef",
  "espUuid": "AB12-CD34",
  "windowsBootUuid": "AB12-CD34",
  "windowsBootManagerSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "linuxLabel": "CachyOS Linux",
  "grubResolution": "1920x1080"
}
```

```bash
python3 assets/live/cachyos-uefi-config.py ./vm-plan.json
python3 assets/live/cachyos-uefi-lab.py ./vm-plan.json
python3 -m unittest discover -s auto_tests -p 'test_cachyos_*.py' -v
```

The example digest is illustrative and is NOT an approved Windows boot binary
digest. The presence of a GRUB executable on the ESP is not evidence of
successful firmware boot, a valid Windows return path, or recoverable rollback.

### What is needed before the "stable" label

The highest-risk missing component is a verified Windows-to-Archiso handoff
and full rollback across EFI/BCD/WinRE and power failure. The official
CachyOS installer requires a different live system from Libertix's Debian
mini-ISO. No current test executes the end-to-end installation on a
Windows 10 or 11 VM, and the working branch deliberately keeps CachyOS
disabled in the release catalog. See issue #3 for the full acceptance matrix.
