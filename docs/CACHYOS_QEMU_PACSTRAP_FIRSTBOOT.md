# CachyOS real pacstrap + EFI GRUB firstboot, QEMU/OVMF lab only

**NOT A WINDOWS INSTALLER — NOT PRODUCTION READY.**

This experiment extends the signed-source live-ISO QEMU proof in PR #31.
It changes ONLY newly created images owned by the GitHub Actions job. It
never receives any Windows disk, Windows Boot Manager, production ESP, BIOS
or real firmware NVRAM. The test is activated **only** on the dedicated
`feature/cachyos-qemu-pacstrap-firstboot` branch.

## Test sequence

1. Download SHA-256-pinned official CachyOS desktop 260809 ISO. Validate
   official live identity, Archiso kernel and initramfs; produce the
   ephemeral signed handoff, verify the signature and GRUB instructions.
2. Create a disposable ext4 image containing the ISO and a **distinct,
   brand-new 12 GiB sparse QCOW2 target disk**. QEMU gives only the target
   the unique virtio serial `GASLUXLABTARGET`.
3. Boot verified GRUB/Archiso under isolated no-key OVMF. The live guest
   proves `SecureBoot=0`, `SetupMode=1`, signed kernel arguments, real
   CachyOS identity and the existing read-only stage preflight.
4. On the host, hash the VM-only installer. In the guest, require the
   exact hash and independent signed `/proc/cmdline` proof before
   using any mutating command. Reject missing virtual disk serial, wrong
   block-device type, wrong size, existing partitions or mounts.
5. Format **only** that empty guest disk as GPT: an EFI FAT32 partition
   and a transaction-owned ext4 root. Use native `pacstrap -K` with
   signature-verified CachyOS repositories and a minimal native
   `linux-cachyos-lts` installation. Check installed CachyOS identity,
   generate initramfs and GRUB configuration, install removable GRUB EFI
   on the guest ESP with `--no-nvram`.
6. Close the live guest. Launch a NEW QEMU/OVMF VM exposing **only** the
   installed QCOW2 disk, not the Archiso source or the test FAT device.
   The installed system has a dedicated one-shot firstboot audit, which
   checks the running kernel, real root UUID, ext4 filesystem, installed
   pacman database, transaction ownership, lab user, ESP and EFI GRUB
   loader. Only that installed audit can publish the exact serial marker
   `GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1`.
7. The host refuses success without the exact marker and no observed
   failure marker. All available live/firstboot serial logs and hashes
   are retained by the Actions artifact step, including on failure.

## Limitations

This is a **minimal, headless installed-system experiment**. It is NOT
the user-facing complete KDE/CachyOS installer, account setup, keyboard
and locale integration with the Windows WPF wizard, signed production
Windows-to-Archiso handoff, persistent NVRAM/BootNext, kernel updates
or a Windows dual-boot/recovery test. The signed test key and disk identity
are temporary lab fixtures, not real Windows-authorized identities.

No VM-only formatting code may be used in production, even if this
experiment passes. Human review is required per AI_POLICY.md, and issue #3
remains the release gate. Do not enable CachyOS in the stable catalogue.

## Reproducibility

The workflow `.github/workflows/cachyos-official-iso.yml` runs with
`GASLUX_LAB_FIRSTBOOT=1` only for the named branch. The live installer is
`auto_tests/tools/cachyos_guest_vm_only_install.sh`. The two-guest QEMU
runner is `auto_tests/tools/cachyos_real_live_kernel_smoke.sh`. The
serial controller is `auto_tests/tools/cachyos_live_guest_serial.py`.

These static contract tests, including negative cases, are not evidence
of a first boot: `auto_tests/test_cachyos_qemu_firstboot_contract.py`.
Check the actual Actions result and serial artifact before asserting that
the installed guest booted.
