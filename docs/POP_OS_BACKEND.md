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

The Pop!_OS preflight does **not** authorize System76 target installation or
alter the WPF wizard, release catalogue, schema or disk/EFI writer. The
shared `configure-target-main.sh` refactor from historical PR #20 is
already present in the `dev` workstream, but it remains **Mint/Zorin only**.

The two explicit phases are `configure_common_ubuntu_target` (account,
locale, keyboard, time zone, sharing and optional development settings) and
`configure_legacy_grub_target` (Casper cleanup, initramfs, GRUB, boot-update
guards and first-boot resize). `validate_legacy_target_backend_or_die`
executes before target configuration and accepts only the verified
`mint/linuxmint` or `zorin/zorin` pair under `debian-squashfs`.
It rejects `popos/pop`, `system76`, unknown identities and mismatched
firmware/layout; this installed-target check is **not** a pre-disk Windows
authorization gate.

The existing synthetic tests for `test_ubuntu_target_backend_preflight.py`
retain original Mint/Zorin operation order and rejection behavior; the
candidate media CI also runs `bash -n` on the shared installer shell. These
checks do not execute native `distinst` and do not prove Mint/Zorin reinstall,
Pop!_OS installation, Windows boot or rollback.

The obsolete official-ISO workflow and older exploratory documentation from
PR #20 are not production acceptance gates. Any new System76 writer requires
its own authenticated media/handoff, boot/update policy and disposable
Windows dual-boot and recovery evidence before catalog promotion.
