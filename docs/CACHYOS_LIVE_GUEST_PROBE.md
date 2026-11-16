# CachyOS 260809 real live guest preflight (QEMU/OVMF only)

**Safety status: LAB TEST — not an installed system, not Windows dual boot and
not permission to modify physical disks.** This branch is stacked on the
experimental Archiso ISO contract work (PR #11).

## Purpose

Previous CI established that the independently SHA-256-pinned official
CachyOS 260809 ISO could boot its LTS Linux kernel to a serial login under
OVMF/QEMU. It did **not** run the guarded CachyOS backend in that live OS.

This follow-up adds a second, more demanding, non-mutating test. The test:

1. Downloads the official 260809 ISO from mirrors, checks its exact expected
   SHA-256, and mounts it read-only for identity and Archiso layout checks.
2. Creates only temporary, disposable `mkfs.ext4` and FAT **image files**
   in the hosted CI workspace. It never opens any host block disk for write.
   The FAT virtual boot medium contains GRUB and a byte-for-byte,
   SHA-256-checked copy of `assets/live/cachyos-stage-target.sh`.
3. Boots real CachyOS from the pinned ISO file with GRUB, OVMF and QEMU.
4. Connects to the VM's *serial console socket*, logs into the disposable
   live guest and runs a fixed, read-only script mounted from the temporary
   FAT image with `mount -t vfat -o ro`.
5. Requires CachyOS `ID=cachyos`, `ID_LIKE=arch`,
   `IMAGE_VERSION=2026.08.09`, virtual machine detection, UEFI with
   disabled Secure Boot, `pacstrap`, `arch-chroot`, Pacman, the CachyOS
   repo and mirrors, timezone metadata, and a correct stage-script SHA-256.
   Then calls the real backend's **`--check` mode only**.
6. Expects a distinct success line produced by the guest preflight process.
   Echoing a shell command that contains the marker is not enough.
7. Saves the boot and guest-session serial transcripts plus per-file SHA-256
   digests as workflow artifacts. Failure/timeout never authorizes writes.

The serial controller never passes Windows credentials or private signing
keys into the live environment. No partition formatting, target
installation, ESP/BCD/NVRAM update, rollback or first boot of an installed
system is performed.

### Reproducible scope

The official ISO job:

`https://github.com/LMhdez/gaslux/actions/workflows/cachyos-official-iso.yml`

The synthetic test suite:

`https://github.com/LMhdez/gaslux/actions/workflows/cachyos-backend-tests.yml`

CI does not contain, emulate or validate an actual Windows 10/11 installed
system. A successful guest preflight cannot close stability issue #3.

## Next required implementation

A trusted, versioned Windows-to-Archiso boot transaction must supply
independently authenticated disk geometry, GPT/ESP/NTFS identity, Windows
bootloader and WinRE/BCD baseline and a durable recovery sequence. The
target package installation must be tested first on a distinct, explicitly
identified disposable QEMU virtual root disk with a snapshot and independent
post-install boot and rollback evidence. No stage script may rely on an
ownership marker alone; the experimental authenticated handoff work in PR
#10 must be integrated and reviewed before enabling `pacstrap`.

There is **no proof yet** of a Windows 10/11 install, Windows Boot Manager
recovery, system upgrades or removable Windows-owned artifact cleanup. No
CachyOS executable can be released for real disks on this basis.
