# CachyOS Windows 10/11 E2E validation and release approval

**Release status: NOT APPROVED for physical disks.**

This branch adds two independent components to prepare the evidence required to
evaluate a safe, dual-boot, USB-free CachyOS installer. Neither component itself
installs an OS or modifies disks.

## Read-only Proxmox readiness

The original Libertix repository contains a real three-VM Proxmox automation
framework (Windows 10 BIOS, Windows 10 UEFI and Windows 11 UEFI). Gaslux
retains that framework, including existing Windows rollback and cross-boot
evidence checks for Mint and Zorin.

The CachyOS checker uses only two explicitly authorized and enabled guests:
Windows 10 UEFI and Windows 11 UEFI. It refuses unexpected firmware, missing
EFI variable storage, absent Windows 11 vTPM, missing snapshots, bad TLS,
unexpected repository URLs or unauthorized VM IDs. Its client performs
**GET requests only**; no Proxmox snapshot restore or boot action occurs.

From a prepared *isolated* test host, using your OWN untracked and authorized
Proxmox credentials and lab infrastructure:

```bash
cd auto_tests
uv sync --frozen --extra dev
uv run --frozen python tools/cachyos_lab_readiness.py
```

This is a readiness probe only. It intentionally reports
`fullInstallationExecuted=false`, `dualBootVerified=false`,
`windowsRecoveryVerified=false` and `installerStable=false`.

The real VM campaign cannot be executed until the Windows app implements a
signed CachyOS backend, temporary EFI boot into the official live Archiso,
a trusted installation agent in that Archiso, a rollback-safe pacstrap target
installation and complete Windows recovery after failure.

## Independent signed campaign evidence

`auto_tests/tools/cachyos_release_gate.py` requires:

- Exact, pinned source Git commit SHA and the built installer SHA-256.
- An independently signed, canonical JSON report using Ed25519.
- A public reviewer key installed by project maintainers at
  `.github/trust/cachyos-lab-reviewer.pem`. This file does not exist yet;
  its absence causes a hard failure, as intended.
- Exactly one authorized Windows 10 UEFI VM and one Windows 11 UEFI VM,
  each bound to an existing pre-install snapshot.
- Ten test cases on EACH Windows guest (20 VM/scenario cells):
  Windows-first nominal, Linux-first nominal, cross-boot after a kernel
  update, network failure rollback, package failure rollback, EFI-write
  failure rollback, power-cut rollback, requested post-install rollback,
  Secure Boot refusal and BitLocker refusal.
- Per-case assertions covering applicable GPT partition restoration,
  EFI boot entry restoration, BCD/WinRE health, successful Windows boot,
  Linux boot and preservation of the Windows EFI loader.
- Two independently hashed evidence files per case (minimum 40 files).
  Missing/altered/symlinked evidence or wrong source commit is rejected.

To avoid accidentally authorizing a destructive release, the current command
returns `ready=false` even when its signed test evidence is valid: reviewer
signoff and integration of the real installer, Windows signed catalog, boot
chain and physical hardware tests remain separate requirements.

This release gate has been tested using **synthetic, locally signed fixtures
only**. These are NOT actual Windows/CachyOS lab results.

## What must happen before a real-disk installer can be released

1. Install the actual CachyOS ISO in each disposable Windows 10/11 guest.
   Boot Linux and Windows at least twice each, preserving WinRE and BCD.
2. Exercise the failure matrix on known Proxmox snapshots and record
   immutable evidence, independent hashes and reviewer signatures.
3. Test the same Windows machine across a Linux kernel/GRUB update.
4. Independently review the Windows source disk before/after GPT layout,
   EFI boot entries, BitLocker state, shutdown/reboot and power-cut recovery.
5. Verify that the signed, pinned final executable is the EXACT binary
   exercised by those campaigns; don't substitute a new executable after
   testing.
6. Repeat with backups and restore validation on representative physical
   UEFI systems, checking multiple OEMs and varying EFI NVRAM behavior.
7. Get maintainer approval before adding CachyOS to `release-config.json`.

**No such complete Windows/CachyOS evidence is available in this project as
of this implementation.** It would be inaccurate to mark a downloadable
real-disk installer as stable.

References:
- auto_tests/README.md
- auto_tests/app/services/automation_campaign.py
- auto_tests/app/services/automation_postinstall.py
- docs/CACHYOS_VALIDATION_MATRIX.md
- https://wiki.cachyos.org/cachyos_basic/download/
