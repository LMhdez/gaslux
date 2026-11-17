# Windows 10/11: Windows Setup DVD guest then disk-only installed guest

**DRAFT — TEST LAB ONLY.** This capability is restricted to GitHub-hosted
ephemeral Linux KVM and cannot be used by the Gaslux WPF production installer.

## Motivation and verified prerequisite

Microsoft original evaluation ISO digests and a no-prompt EFI/DVD firmware
handoff passed for BOTH Windows 10 and Windows 11 on
[Actions #44035435121](https://github.com/LMhdez/gaslux/actions/runs/44035435121).
This did **not** start Windows Setup nor boot an installed OS.

[PR #70](https://github.com/LMhdez/gaslux/pull/70) tried QEMU's
`-boot order=c,once=d`. But its **real** guest firmware test
[#44036611388](https://github.com/LMhdez/gaslux/actions/runs/44036611388)
FAILED: UEFI GRUB reboot repeatedly returned to DVD. The follow-up using a
proper GPT/ESP SATA disk also failed in
[#44037067491](https://github.com/LMhdez/gaslux/actions/runs/44037067491).
Passing the textual `-boot once` argument into QEMU does not guarantee this
OVMF configuration will select the disk on the next reboot.

A **different mechanism** was genuinely verified with *two* distinct QEMU/KVM
guest executions and real UEFI GRUB serial markers:

- [Actions #44037470888](https://github.com/LMhdez/gaslux/actions/runs/44037470888)
  **SUCCESS**: first OVMF boot executes DVD GRUB and reboots, causing
  `-no-reboot` to shut down QEMU. A second QEMU process, with the same
  private OVMF variables and a GPT ESP **SATA disk only** (no DVD), boots its
  independent EFI GRUB successfully. This proves only the firmware protocol.
  No Microsoft media, Windows or Windows boot manager were used.

## Implementation under test

`--two-stage-install-only` requires the official original ISO byte digest,
a separately SHA-256-hashed Microsoft-sourced no-prompt EFI DVD derivative,
GitHub-hosted QEMU/KVM, new isolated file-backed QCOW2 and explicit
`GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT`.

1. **First guest**: attach read-only derived DVD, a new owned QCOW2 and
   unattended answer floppy; boot DVD. The QEMU process has `-no-reboot` and
   stops on the first guest reboot. Reject any repeated DVD boot, abnormal
   exit, missing DVD EFI marker or insufficient QCOW2 staging activity.
2. **Second guest**: launch a *new* QEMU process with the SAME owned QCOW2,
   same private OVMF variable file and the answer floppy, but **no DVD or ISO
   device at all**. All device arguments are reconstructed using a
   positive/negative allowlist and separate serial transcript.
3. Accept the second guest as installed Windows only if it emits the genuine
   expected Windows client `ProductType=1`, x64 build, GPT/ESP, WinRE
   enabled, Recovery GPT, BCD markers from the installed guest and then
   powers off cleanly (QEMU exit status 0). This can be proven only by
   actual Windows 10 and 11 installed-guest CI jobs, not by synthetic tests.
4. If any check fails, report failure. The disposable VM disks and media
   are automatically destroyed with the temporary hosted runner. No host
   disks or production EFI/BCD/WinRE are exposed.

Security: the boot-stage allocated QCOW2 size is only a conservative
staging heuristic; it cannot prove Windows has been installed. Neither
a Microsoft SHA-256 check nor one or two firmware boot markers are proof
of Windows firstboot. The installed-client witness remains mandatory.
The workflow uploads only serial logs/sha256/results, **never Microsoft ISO,
WinPE image, virtual disks, TPM, account password or private firmware NVRAM**.

## Not yet accepted

The Windows 10 and 11 actual installed-guest second-boot runs are separate
and must finish SUCCESS with actual independent guest evidence. Even then,
this does NOT install CachyOS, boot Windows after Linux kernel updates,
recover BitLocker or Windows BCD/WinRE/EFI/GPT, uninstall Gaslux or validate
physical hardware. Those all require cross-OS acceptance gates in
[issue #3](https://github.com/LMhdez/gaslux/issues/3).

GPL-3.0. The maintainer must review all code under `AI_POLICY.md`.
Generated-by: GPT-6.
