# CachyOS — independent QEMU update/rollback laboratory

**Experimental, DISPOSABLE VM ONLY. Not a Windows dual-boot acceptance test.**

This work stacks on the real signed CachyOS ISO / installed first boot in
[draft PR #36](https://github.com/LMhdez/gaslux/pull/36).
It does not alter main, the stable distribution catalog or the WPF wizard.

## Boundary and validation

The original headless installed CachyOS image was produced by verified
SHA-256-pinned ISO, signed-source GRUB and native `pacstrap -K`. The normal
first-boot UEFI guest has only the 12 GiB, file-backed QCOW2 target disk
attached and publishes a success line only after verifying the actual
running kernel, root UUID, distribution identity, pacman, ownership and EFI.

This new independent laboratory exercise runs **after** that verified
first boot. It records the SHA-256 of the original target disk, then:

1. Create a fresh QCOW2 power-cut overlay backed only by the verified
   target. The QEMU firmware exposes a test-only `fw_cfg` request to
   the installed, SHA-256-verified guest updater. The running system
   writes a transaction-owned checkpoint and prints an exact serial
   acknowledgement, then the host forcibly SIGKILLs QEMU (not a
   graceful shutdown). Discard ONLY the overlay; verify original
   image bytes are unchanged.
2. Create an independent, new update overlay, with NAT networking
   and OVMF no-keys Secure Boot-capable firmware. The installed guest
   checks VM identity, root UUID, native CachyOS identity, ownership,
   mount/EFI files and **effective per-repository trusted package
   signatures** before running authentic `pacman -Syu --noconfirm
   linux-cachyos-lts grub`. These extra package arguments force a
   signed kernel/GRUB reinstall even if pacstrap already installed
   the newest available versions.
3. Regenerate CachyOS initramfs and GRUB, check native files and
   package database, mark successful transaction durably and reboot.
   Boot the **same updated overlay** in a NEW QEMU process; a
   systemd service, executing from the updated installed root, proves
   its kernel, pacman, GRUB and filesystem and emits an independently
   matched post-update reboot marker.
4. Destroy ONLY the owned update overlay; verify the baseline QCOW2
   SHA-256 never changed during the overlay experiments. Launch a
   **further** fresh OVMF VM with only the original QCOW2 and require
   the original installed CachyOS firstboot audit to pass again.
   Upload SHA-256-hashed serial evidence for power cut, package
   transaction, updated Linux reboot and baseline recovery.

Every QEMU instance is created by the GitHub Actions job and uses only
QCOW2 files in its newly generated `/tmp/cachyos-real-boot-*` directory.
There is **no** Windows disk, user hardware, real firmware write,
Windows Boot Manager or production EFI key in this experiment. Even a
successful QEMU snapshot restore is NOT a Windows BCD, BitLocker, WinRE
or ESP rollback.

If package mirrors, network, SHA-256, effective signing policy, systemd,
update scripts, GRUB, reboots, marker provenance or baseline file hash
are wrong, the job must **fail** and retain diagnostics. No fallback to
unsigned packages, relaxed Secure Boot, unverified external disks or
a synthetic boot success is allowed.

## Limits

- A fresh `pacstrap` normally installs current repository versions;
  therefore the signed full-system update may find no newer packages.
  Explicit signed kernel/GRUB reinstall tests their hooks, but **does
  not prove a future version upgrade** unless versions actually change.
- A disposable QCOW2 overlay restore is not proof that Gaslux can undo
  real GPT/ESP edits, preserve Windows EFI/BCD/WinRE/BitLocker, recover
  after power loss on physical storage or uninstall safely.
- No graphical desktop session, KDE/SDDM login, signed Windows-to-live
  production handoff, real Windows 10/11 VM, BIOS/MBR or hardware
  installation is exercised here.
- Human review and issue #3 remain mandatory before any production
  installer or catalog release is enabled.

The legitimate CachyOS manual recommends `pacman -Syu` and a reboot
after major/kernel updates. Pacman requires trusted signatures for
official packages; a repo using `TrustAll`, `PackageOptional` or
`Never` must not be accepted here.

References:
- https://wiki.cachyos.org/configuration/post_install_setup/
- https://man.archlinux.org/man/pacman.conf.5

Run branch: `feature/cachyos-qemu-updates-snapshot-recovery`.
Relevant files: `auto_tests/tools/cachyos_qemu_update_rollback.sh`
and `auto_tests/tools/cachyos_vm_update_recovery_guest.sh`.
