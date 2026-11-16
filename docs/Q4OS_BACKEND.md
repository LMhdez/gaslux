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

## Exact native Calamares inspection and disposable installed-root experiment

The official pinned Q4OS 6.10 r2 ISO actually contains the full native
`/etc/calamares/settings.conf` and module configuration. The guest root
reported `/etc/q4os_version = 6.10-deb13u1`. From the verified ISO:

- `unpackfs.conf` selects
  `/run/live/medium/live/filesystem.squashfs`, sourcefs `squashfs`,
  destination `""`. This is the only install payload source used by
  the disposable materialization experiment.
- `settings.conf` sequences partition, mount, unpackfs, Q4OS hooks,
  users, GRUB, package cleanup, initramfs and unmount. Those hooks must
  be individually reviewed before real unattended installation.
- `bootloader.conf` selects UEFI GRUB and sets
  `installEFIFallback: true`: blindly reusing this would risk replacing
  `EFI/BOOT/BOOTX64.EFI` on a Windows ESP. The Gaslux policy rejects
  such unowned fallback writes.
- `partition.conf` defaults to ext4 and has
  `initialPartitioningChoice: none`; this is not automatic,
  transaction-owned partitioning.

[Calamares config verification run 43964771409](https://github.com/LMhdez/gaslux/actions/runs/43964771409)
completed successfully, with hashes and native files retained as an artifact.
The policy auditor parses the extracted YAML using a duplicate-key-rejecting
loader; a pass **never** authorizes a production disk write.

The separate `gaslux_q4os_installed_root_lab.sh` experiment is explicitly
opted in **only on disposable GitHub Actions runners**. It creates a fresh
12-GiB sparse GPT image under its private temporary directory and validates
loop backing-file ownership before formatting its own EFI and ext4 partitions.
It stages the native Calamares `unpackfs` SquashFS payload, writes a
guest-only boot-proof systemd unit, and tries to boot with OVMF using a temporary
runner-built GRUB EFI binary. The ISO is **not attached** during the target boot,
and neither Windows disks nor a host physical disk are passed into QEMU.

**Important limitation:** this tests a staged *installed root*, not Calamares'
full installation: Q4OS-specific Calamares hooks, account provisioning,
native package-owned GRUB, package removal/updates, Windows coexistence,
transactional handoff and recovery are not run. A positive boot proof requires
the new guest's own systemd unit to emit a serial marker; success must only
be claimed after reviewing the exact-head GitHub Actions result.

The production catalogue, WPF wizard and Windows/BCD/ESP writers remain
untouched. Q4OS remains experimental; no stable dual-boot support is claimed.

## Native package-owned EFI GRUB and two-boot disposable OVMF proof

The follow-on experimental [PR #45](https://github.com/LMhdez/gaslux/pull/45)
tests a second boot using a **package-installed EFI GRUB loader** instead
of the earlier runner-built temporary EFI loader. This is not full Calamares
execution or a production Windows coexistence test.

The exact Q4OS 6.10 r2 live SquashFS initially lacked `x86_64-efi` GRUB
modules. The lab downloads `grub-efi-amd64-unsigned` and
`grub-efi-amd64-bin` with **Debian 13 signed APT repository metadata**,
requires matching package versions and verifies their SHA-256 before
offline guest `dpkg -i`. The observed packages had version
`2.12-9+deb13u2`. The guest verifies package status and module ownership
with `dpkg-query` and `dpkg -S` before invoking its own
`grub-install --target=x86_64-efi --no-nvram --recheck` and
`grub-mkconfig`.

All native bootloader writes stay on the guest-created GPT ESP. Guest code
rejects Windows EFI files, incorrect root/ESP filesystem/UUID/partition
labels, additional disks, non-QEMU firmware, and unexpected changes to the
original lab-created fallback EFI file. No NVRAM creation or host device
passthrough is permitted. The controlled guest-only fallback copy happens
after all these checks, and is prohibited for any Windows/shared ESP.

In the second QEMU invocation, only the same disposable GPT image and
temporary OVMF variables are presented, with **no ISO**. A pass requires
the real guest's second-boot systemd service to attest the pinned
`uname -r`, `BOOT_IMAGE` kernel command line, Q4OS version,
guest-owned ext4 root UUID and both EFI loader file hashes, as well as
the Q4OS native GRUB menu output. A mere GRUB menu is never accepted as
proof of a successful Linux boot.

[GitHub Actions #43978320653](https://github.com/LMhdez/gaslux/actions/runs/43978320653)
reached a **passing native GRUB installed-guest two-boot step** on commit
`00fca87de6ffc5cd2744a78a4a347aeeb0f52dac`.
Its separate ISO live-boot stage must be checked independently for a
complete workflow pass.

**Still not demonstrated:** full Q4OS Calamares view modules, Q4OS
`q4oshook*` execution, real account/localization provisioning, final
signed installation transaction, Windows 10/11 dual boot, loader updates,
boot durability, removal or WinRE/BCD/ESP/MBR rollback. Native package
boot alone cannot authorize an end-user Q4OS installation or stable release.
