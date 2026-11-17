# Pop!_OS / System76 backend — independent experimental workstream

**Status: lab-only diagnostic, not an installer.** This diagnostic module depends only on the shared read-only media tools already integrated into `dev`.

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

## Isolation from legacy Mint/Zorin installer

This extracted preflight does **not** modify `assets/live/configure-target-main.sh`, dispatch code, the WPF wizard, schema, signed release catalogue, or any disk/EFI writer. The related Ubuntu target refactor remains in experimental PR #20 for separate review and VM regression testing. The installed Pop!_OS boot and Windows recovery path have not been demonstrated here.
