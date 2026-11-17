# Windows 10/11 evaluation firstboot — one-shot EFI DVD lab (experimental)

**Status:** isolated GitHub-hosted KVM Windows guest installation experiment.
This is NOT the production Gaslux Windows installer and does NOT authorize
CachyOS dual boot, shrinking real Windows, bootloader writes, rollback or
release promotion.

## Why

The signed original Microsoft evaluation Windows 10/11 DVDs blocked at the
UEFI `Press any key to boot from CD or DVD` prompt on headless QEMU, despite
HMP `sendkey ret` being accepted. Independent synthetic GRUB in guest UEFI
failed to observe the host key. [PR #65](https://github.com/LMhdez/gaslux/pull/65)
therefore derives a temporary **EFI no-prompt** UDF DVD from the pinned official
Microsoft ISO (`efisys_noprompt.bin`) and has proven a **Windows 10 firmware
DVD handoff only**. Its success must not be confused with Windows Setup boot.

This branch stacks on PR #65 to test actual installed **Windows 10 and 11
Enterprise Evaluation x64** on brand-new discardable Q35/KVM/OVMF guests.

## Authorization and hard isolation

- Exact GitHub-hosted x86_64 Linux runner, repository identity and CI
  authorization; explicitly enabled `GASLUX_WINDOWS_KVM_CONSENT` and separate
  `GASLUX_WINDOWS_ONE_SHOT_INSTALL_CONSENT` for **this one-shot workflow**.
- Download the independently SHA-256 pinned original ISO from allowlisted
  Microsoft HTTPS endpoints. Keep it unchanged; derive a separate ephemeral
  UDF El Torito DVD with its own distinct SHA-256.
- Create an absolutely new, file-backed QCOW2 under the exact temporary
  GitHub-hosted runner root; preserve private OVMF variables and Windows 11
  vTPM. Attach no physical disks or firmware NVRAM.
- Provide only the verified Microsoft-sourced lab DVD, one owned QCOW2 and an
  ephemeral unattended-setup floppy to the QEMU process. No ISO, WIM, QCOW2,
  vTPM state or credentials may enter the uploaded artefacts.
- The new CLI `--one-shot-install-only` requires `--derived-no-prompt`,
  `--accel kvm`, a separate explicit consent environment variable and no
  `--boot-probe-only`. Other combinations fail **before download**.
- Use documented QEMU `-boot order=c,once=d`: DVD prioritized **on first
  firmware start only**, then the freshly installed disk for reboots.
  A firmware serial trace showing a second `BdsDxe: starting ... DVD`
  triggers **immediate failure and termination of that disposable guest**,
  never silent reinstallation.
- Fail on missing/incorrect **real guest** first-logon serial markers.
  Specifically require Windows client `ProductType=1`, the requested x64
  build, GPT/ESP, Windows recovery GPT partition, WinRE actually enabled,
  BCD enumeration, and QEMU normal exit only after a guest-initiated Windows
  poweroff. A setup screen or Windows Boot Manager alone proves nothing.
- Do not claim provenance of Windows recovery or Linux/Windows dual boot on
  the basis of these tests. No snapshot is restored, Windows dual boot is
  absent, and no production storage/EFI/BCD writer is invoked.

## Results, acceptance gates and follow-up

The run of `windows-x64-noprompt-one-shot-firstboot.yml` runs all negative
contracts before starting genuine ISO fetches on separate file-backed
Windows 10/11 VMs. Only a complete **success** of each corresponding real VM
job, with genuine inside-guest markers and an observed clean guest shutdown,
could establish *Windows client firstboot*; all other cases explicitly fail.

Even a passing Windows-firstboot run proves **neither** CachyOS installation
on the Windows VM, nor cross-boot after kernel updates, nor BCD/WinRE/EFI
and GPT restoration after interrupted install or uninstall. Those acceptance
criteria remain in [issue #3](https://github.com/LMhdez/gaslux/issues/3).
Windows guest capture from [PR #56](https://github.com/LMhdez/gaslux/pull/56)
is not yet authenticated to this VM and is not invoked here.

References:
- [QEMU invocation: `-boot once=d`](https://www.qemu.org/docs/master/system/invocation.html)
- [Microsoft: DVD unattended Setup and Autounattend.xml](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/boot-from-a-dvd?view=windows-10)
- [Microsoft: EFI ISO image boot options](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oscdimg-command-line-options?view=windows-11)

GPL-3.0; human review and audit required under `AI_POLICY.md`.
Generated-by: GPT-6.
