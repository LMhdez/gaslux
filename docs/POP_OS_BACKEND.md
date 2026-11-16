# Pop!_OS / System76 backend — independent experimental workstream

**Status: lab-only diagnostic, not an installer.** This branch is based on
`feature/multidistro-lab-media-probe`, not any CachyOS implementation.

## Grounded policy

System76's published installation guidance requires disabling Secure Boot.
Pop!_OS uses **systemd-boot for UEFI** and **GRUB for legacy BIOS**. Its
installer offers advanced/custom partitioning, while full-disk encryption
on a Windows-shared drive is not a supported assumption.

The probe:
- Distinguishes generic and NVIDIA x86-64 media policy (actual ISO exact
  variant binding awaits verified signed metadata).
- Refuses UEFI/MBR and BIOS/GPT, wrong bootloader, enabled Secure Boot,
  mismatched `os-release ID=pop`, bad ISO hash, or Windows-shared full-disk
  encryption.
- Accepts BIOS/MBR and UEFI/GPT **as upstream candidates**, never claiming
  those combinations are installed or certified in Gaslux.
- Returns `installationAuthorized: false`, regardless of test outcome.

## Remaining implementation

1. Pin exact official ISO variant/bytes/SHA in a maintainer-signed v2
   catalogue. Do not reuse an unrelated Mint/Zorin squashfs even if both
   images contain `casper`.
2. Verify real Pop live root and System76 distinst/pop-installer identity
   from the **same** pinned ISO and authenticate Windows-to-live handoff.
3. Implement native target installation, account/locale, firmware-specific
   boot chain (including kernelstub / systemd-boot UEFI), update resilience
   and Windows boot entry recovery.
4. Exercise install, dual-boot, updates, uninstall and rollback with disposable
   Windows 10 BIOS/MBR, Windows 10 UEFI/GPT, Windows 11 UEFI/GPT guests.
   Never test on physical disks without independent recovery evidence.

Sources:
- https://support.system76.com/support/install-pop
- https://support.system76.com/support/bootloader
- https://support.system76.com/support/windows
- https://github.com/pop-os/iso/blob/master/config/pop-os/24.04.mk

## Ubuntu-family target configuration reuse (experimental bridge)

The inherited `assets/live/configure-target-main.sh` is split into two
explicitly ordered phases without changing the Mint/Zorin operations:

- `configure_common_ubuntu_target`: account, Windows sharing and preferences,
  locale, keyboard, timezone and development-access configuration.
- `configure_legacy_grub_target`: Casper cleanup, initramfs rebuild, GRUB,
  boot-update guards and first-boot resize setup.

`validate_legacy_target_backend_or_die` executes **before target configuration**
and requires exactly `mint/linuxmint` or `zorin/zorin`. This check runs
inside the installed target, **after live disk staging and extraction**;
it is not a substitute for an earlier Windows/live pre-disk authorization gate. The only accepted
backend remains `debian-squashfs` (the legacy default); `system76`, `popos/pop`
and unknown identities all fail closed. The selection function is deliberately
not wired to a Pop!_OS writer. This does not override Windows preflight or
authorize disk/EFI changes.

The next integration must separately prove that each shared operation works on
the verified System76 installed target. Pop!_OS still requires native
`distinst`/installer integration, its own boot/update/verification policy
(systemd-boot UEFI, GRUB BIOS), authenticated Windows-to-live handoff,
and disposable Windows VM installation/dual-boot/rollback evidence.

`auto_tests/tests/test_ubuntu_target_backend_preflight.py` executes only the
Bash validation function with synthetic environment inputs, confirms negative
and positive policy cases and guards the historical operation order. It does
not execute installer or disk commands.

## OVMF live-boot block-device diagnostic (experimental)

GitHub Actions can verify the official Pop!_OS ISO but older QEMU runs failed
because GRUB could not find the live kernel on emulated CD-ROM or USB optical devices.
The serial evidence listed only the lab EFI disk, so the test now uses a
second explicitly read-only virtio-blk disk for the verified ISO.
The Pop-specific disposable-VM experiment now attaches the signed/digest-checked
ISO as a **read-only virtio block device** (separate from the fresh temporary GPT
ESP disk) and requires a matching live kernel/initramfs and **serial login**.
The shared Q4OS smoke harness retains its previous optical-media path.
A missing GRUB device remains a failure, not a boot success. This is a live
smoke test only; the Windows target disk, System76 distinst, and bootloader
writers are never attached or invoked.
