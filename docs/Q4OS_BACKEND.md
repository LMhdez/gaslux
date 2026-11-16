# Q4OS — native partitioned installation workstream

**Status: read-only experimental candidate probe, no installer.**
Independent of CachyOS. Stacked only on shared lab-media preflight.

Q4OS 6.10 Andromeda was announced as the updated stable release on
8 October 2026. It is based on Debian 13 Trixie. The native Q4OS live
media uses Calamares. The distinct **Q4OS for Windows** program installs
into a Windows filesystem folder: that is *not* the Gaslux native
partitioned installation model.

## Important identity mismatch

Unlike the existing `osReleaseId=q4os` assumption in the draft signed
catalogue v2 policy, Q4OS 6.9 evidence shows `ID=debian` in
`/etc/os-release`. Q4OS identity requires independently checked
Q4OS-specific version evidence (e.g. `/etc/q4os_version`) **from the
same verified native ISO**, plus a real Calamares installation payload.
This early module refuses missing/malformed version evidence, and
reports that ISO-to-live identity binding is **not yet proven**.

The current probe conservatively rejects Secure Boot enabled until
the exact native image signing chain is independently verified; this
does not claim Q4OS itself lacks Secure Boot support.

## Support boundaries

- BIOS/MBR and UEFI/GPT are candidate modes only; the existing MBR
  4-entry/extended/logical and UEFI ESP preservation requirements apply.
- UEFI/MBR and BIOS/GPT are refused.
- The user must not be sent to Calamares' interactive partitioning; an
  authenticated unattended native backend and transaction-owned target
  provisioning are not implemented.
- No ISO URL, exact bytes or SHA-256 is invented or included in the
  stable distribution catalogue.

## Still blocked

Native Calamares partition intent handoff;
Windows storage transaction; disk ownership evidence; bootloader
and update durability; first Linux and Windows boot; uninstall; power
loss; and WinRE/BCD/MBR/ESP rollback in disposable Windows 10/11 VMs.

## Verified official image and QEMU lab boundary (16 November 2026)

- The official SourceForge `q4os-6.10-x64.r2.iso` SHA-256 is
  `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`.
  This is an upstream-published checksum, **not** a Gaslux maintainer-signed
  release catalogue or a verified upstream detached signature.
- The real ISO's complete bytes and Debian 13 live SquashFS passed the
  independent Q4OS Actions inspection:
  https://github.com/LMhdez/gaslux/actions/runs/43936058057
- The later disposable QEMU boot experiment failed because the guest GRUB
  could not see `/live/vmlinuz-6.12.111+deb13-amd64` on the emulated
  optical device:
  https://github.com/LMhdez/gaslux/actions/runs/43940542320
- A stacked branch now reuses the verified, read-only VirtIO ISO transport
  from the Pop!_OS workstream. The guest has only ephemeral NVRAM and ESP
  images, no network or physical disk. A pass requires observed guest
  kernel/userspace login, not merely an EFI/GRUB menu.
- This is a **live-media experiment**, not the requested native Calamares
  install. No unattended target partitioning, disk ownership, Windows boot,
  bootloader update or rollback has been demonstrated.

Reuse policy: the original Libertix partition/transaction/Windows recovery
machinery remains the shared base. Q4OS's native installer settings, module
ordering and installed-root behavior must be checked against the *same pinned
ISO* before attempting an unattended, transaction-owned installation.
The upstream public Calamares GitHub mirror points development to Codeberg.
Do not copy Calamares configuration from unrelated distributions or treat
Q4OS Windows WinSetup folder mode as a native disk installation.

Official Q4OS sources:
- https://q4os.org/blog.html
- https://q4os.org/dqa007.html
- https://www.q4os.org/forum/viewtopic.php?pid=35537
