# CachyOS for Gaslux: Release and Recovery Validation Matrix

**Status: EXPERIMENTAL / NOT ELIGIBLE FOR RELEASE.**

The CachyOS code in the feature branches is not integrated into the Windows
Libertix installer. Passing CI is *not* evidence of a safe install alongside
Windows. The production release catalogue MUST continue to omit CachyOS.

## Evidence obtained

| Test | Evidence | Scope | Result |
|---|---|---|---|
| Archiso payload identification | \`test_cachyos_preflight.py\` | Detects expected live ISO layout, never installs | Pass |
| Target provisioning contract | \`test_cachyos_release_gate.py\` | Rejects production exposure and refuses staging outside a disposable QEMU/KVM guest | Pass |
| Target filesystem checks | \`test_cachyos_target_verify.py\` | Pacman metadata, locale/user/sudo, kernel/initramfs, EFI UUID and owner, Windows PE hash | Pass on fixtures |
| GRUB candidate transaction | \`test_cachyos_uefi_transaction.py\` | Fault-injected GRUB generation; no overwrite of existing config; cleans transaction-owned artifacts | Pass on fixtures |
| Booted Linux auditor | \`test_cachyos_first_boot_audit.py\` | Validates expected root/ESP mount and running kernel; fixture mode never reports real boot | Pass on fixtures |
| EFI firmware execution | \`auto_tests/tools/cachyos_ovmf_smoke.sh\` | Boots **standalone GRUB EFI** in QEMU/OVMF, checks serial output | Pass on QEMU |
| Full CachyOS kernel boot | Not executed | Real installed CachyOS root on virtual disk | **Not verified** |
| Windows dual boot | Not executed | Windows Boot Manager and CachyOS selectable after EFI installation | **Not verified** |
| Windows rollback after failure | Not executed | BCD, WinRE, BitLocker and GPT recovery | **Not verified** |

## Mandatory virtual-machine acceptance tests

Use isolated, disposable QEMU/KVM guests with externally retained snapshots.
Never run an unverified image on a production Windows installation.

1. Snapshot an unmodified Windows 10 UEFI/GPT guest, with a functioning
   recovery partition, Windows Boot Manager, and a known Windows SHA-256
   baseline. Repeat on Windows 11. Record exact partition offsets and sizes,
   GPT disk GUID, ESP partition GUID/UUID, BCD and WinRE state, and BootOrder.
2. Run the Windows-side preflight with signed, pinned CachyOS ISO metadata.
   Verify that Secure Boot enabled, BitLocker enabled, unsupported disk
   topology, missing mirrors and insufficient free space are all rejected
   **before the first modification**.
3. Perform an actual USB-free Windows-to-Archiso handoff. Require the same
   signed installation-plan/run ID in Windows, the transient live environment,
   and CachyOS. Reject stale/foreign Linux staging partitions and ISO files.
4. Install CachyOS packages and KDE with verified pacman keys, repository
   mirrors and no unsigned external package substitutions. Verify account,
   locale, keyboard, initramfs, fstab, network and graphical login.
5. Install the final GRUB EFI chain without modifying
   \`EFI/Microsoft/Boot/bootmgfw.efi\`; verify the actual UEFI BootCurrent
   entry, BootOrder, Windows entry and Linux entry on boot. Boot Windows,
   reboot to CachyOS, then boot Windows again.
6. Reboot CachyOS and run \`cachyos-first-boot-audit.py\` on the running root.
   Inspect post-boot logs and package errors. Update the kernel, GRUB, and
   related boot packages, then repeat the two-system reboot sequence.
7. Restore a pre-install snapshot and inject failures during every mutating
   transaction boundary: NTFS resize, GPT change, ext4 formatting, package
   download, package extraction, GRUB EFI write, NVRAM write, first boot,
   clean-up and shutdown. Also inject power cuts where a VM snapshot makes
   the test reproducible.
8. After each recoverable failure, verify original Windows partition geometry,
   ESP and Windows loader hashes, WinRE health, BCD, UEFI entries, BitLocker
   state, and successful Windows reboot. Do not treat copied log files or an
   exit code alone as rollback proof.
9. Ensure no CachyOS-specific paths alter the existing Linux Mint or Zorin
   installation/removal test matrix.
10. Repeat in supervised physical-hardware tests with offline backups,
    a tested restore procedure, and deliberately varied UEFI vendor behaviour.

## Release gate

A CachyOS-enabled Windows installer must **not** be built or advertised
until all mandatory cases are executed with trustworthy logs, snapshot IDs,
result signatures and independently reviewed failure evidence.

This repo presently has no verified Windows 10/11 VM image, no fully working
Windows-to-Archiso handoff and no complete dual-boot/rollback integration.
The existing QEMU/OVMF smoke test validates that a GRUB EFI executable can run;
it does **not** boot a CachyOS kernel or Windows, and it is not a substitute
for any of the mandatory tests above.

Do not mark the experimental PRs ready for review or merge them into the
production branch on the basis of unit tests or the standalone GRUB smoke.
