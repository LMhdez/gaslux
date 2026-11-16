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

## Calamares source-of-truth inventory (experimental branch)

The follow-on disposable CI workstream enumerates `etc/calamares` and
`usr/share/calamares` from the **same exact ISO-mounted SquashFS** whose
Q4OS 6.10 r2 full ISO SHA-256 is checked again before inspection. It
records the actual settings path, ordered Calamares `show` / `exec`
modules, `dont-chroot`, candidate Q4OS version evidence and per-file
SHA-256s. The evidence is archived for human review.

This step **does not execute Calamares, provision a target partition, launch
an unattended installer or authorize any disk writes**. It deliberately
reports `installationAuthorized: false` in every possible result. A
Calamares executable and configuration are not sufficient to assert an
unattended installer exists. Only after confirming these exact official
modules and their expected target/boot behavior can an isolated virtual
target-disk experiment be constructed.

The GitHub Actions run link and observed settings/module values must be
added after the corresponding run finishes; this document does not
anticipate their results.

## Recorded native Calamares contract from the official Q4OS 6.10 r2 ISO

The [real ISO evidence run #43956145614](https://github.com/LMhdez/gaslux/actions/runs/43956145614)
establishes these byte-for-byte configuration facts:

- `/etc/q4os_version`: `6.10-deb13u1`.
- `/etc/calamares/settings.conf`: `dont-chroot: false`; native
  `partition`, `mount`, `unpackfs`, `users`, Q4OS-specific hooks,
  `grubcfg`, `bootloader` and initramfs stages.
- `/etc/calamares/modules/unpackfs.conf` selects
  `/run/live/medium/live/filesystem.squashfs` as its installed-system
  source. Unlike CachyOS, unpacking the live filesystem is the normal
  upstream Calamares native installation stage here.
- `/etc/calamares/modules/bootloader.conf` specifies
  `efiBootLoader: "grub"` and **`installEFIFallback: true`**.

That default **must not** be executed against an existing Windows ESP:
Calamares may update `EFI/BOOT/BOOTX64.EFI`, and Gaslux has not proven
ownership or rollback of that path. The future Windows backend must either
disable fallback writes through a verified owned configuration or reject the
installation. Disabling fallback alone is *not* enough: the preflight must
also prove target partition ownership, bootloader ID isolation, Windows
Boot Manager preservation and BCD/WinRE/EFI recovery.

The current branch remains read-only and `installationAuthorized: false`.
No Calamares unattended run, disposable native target installation,
first installed Linux boot, Windows dual boot or rollback is yet proven.
