# Gaslux multidistribution and BIOS/MBR expansion plan

**Status: design / development guidance, not a released installer.**
Date: 2026-11-16. This document describes an engineering target, not a claim that any new distribution is ready for real disks.

## 1. Baseline (inspected from repository)

The main branch inherits Libertix's Windows WPF/.NET 4.8 setup, signed release catalog, PowerShell storage/firmware preparation, two mini-ISOs, shared Debian-oriented live installer, typed plans, stage-ledger and Windows rollback verification. The release-config.json on main lists **Linux Mint 22.3 Cinnamon** and **Zorin OS 18.1 Core**; README.md explicitly describes both **BIOS/MBR** and **UEFI/GPT** support for the current installer. Thus BIOS/MBR is an extension of an existing path, not a new partitioning subsystem.

The existing source discovery under assets/live/libertix-distribution-common.sh requires one filesystem.squashfs with dpkg/update-grub/update-initramfs capabilities. That is not a general installer interface.

Experimental CachyOS work exists in feature branches, including reports of pacstrap and an installed Linux first boot inside disposable QEMU/OVMF guests. This does **not** demonstrate Windows 10/11 dual boot, updates, complete rollback, or production stability. Issue #3 tracks the release blockers. Keep production CachyOS disabled.

## 2. Proposed compatibility matrix

Legend: Existing = main currently supports this combination (with its existing preflight limits). Candidate = upstream-compatible concept, requiring a complete Gaslux backend and tests. Reject = explicitly unsupported.

| Distribution/backend | BIOS/MBR | UEFI/GPT | Primary blocker |
| --- | --- | --- | --- |
| Linux Mint — Debian squashfs | Existing | Existing | Preserve regression coverage and release pinning |
| Zorin OS — Debian/Ubuntu squashfs | Existing | Existing | Maintain Zorin 18.1; validate each future ISO |
| CachyOS — Archiso | Candidate | Candidate | Trusted Archiso handoff, pacstrap, GRUB/BIOS or EFI, recovery |
| Pop!_OS — System76 | Candidate | Candidate | Release-aware install flow, GRUB on BIOS vs systemd-boot on UEFI, recovery |
| Q4OS — Debian live/installer | Candidate | Candidate | Select installable native media; validate package/boot path |
| Bazzite — Atomic image | Reject | Candidate | UEFI/GPT-only, Atomic deployment, boot/update and dual-boot constraints |

Neither candidate nor existing means every partition arrangement is supported. All paths must satisfy the exact preflight. Do not add Windows 11 BIOS/MBR to the mandatory release matrix: target documented Windows 11 UEFI/GPT.

**Sources checked:** CachyOS installation documentation explicitly includes MBR/BIOS and UEFI/GPT; System76 documents legacy GRUB vs UEFI systemd-boot and requires Secure Boot disabled for installing Pop!_OS; Bazzite documentation explicitly requires UEFI and GPT; Q4OS publishes native installation media and also a fundamentally different folder-based Windows setup. See references.

## 3. Split policy from backend implementation

Add a versioned, signed capability record to the distribution manifest, with backward compatibility rules:
- ID and immutable release identity: exact os-release identity, architecture, source URL, sha256, bytes and signing/provenance
- backend ID, source format, trusted installation environment, target provisioning method
- allowed firmware/disk-style pairs, Secure Boot policy, optional required human firmware action
- minimum tested capacity and bootloader/update mechanism
- explicit status: unavailable, lab-only or released, with an evidence-backed release gate

Do not infer backend from display name, ISO filename, desktop theme or a loose os-release substring. Validate the field in C#, PowerShell, Python and JSON Schema. Maintain the current signed catalog and its offline/test exception behavior; do not insert fabricated hashes or test-only entries into stable release-config.json.

Proposed backend boundaries:
1. **Debian squashfs adapter:** preserve existing Mint and Zorin behavior; Q4OS only if an exact, verified ISO conforms to the required extraction capabilities.
2. **Archiso adapter:** verify official CachyOS media and boot kernel/initramfs with a transaction-bound handoff; provision from Archiso with pacstrap and preserve pacman/mirror/hook contracts.
3. **System76 adapter:** validate Pop!_OS release/variant and dedicated installation steps; UEFI boot entries/systemd-boot rather than assuming the Mint GRUB update hooks apply; BIOS GRUB where supported.
4. **Atomic adapter:** Bazzite-specific supported deployment and firmware chain. Do not use Debian extraction, pacstrap or a generic Fedora squashfs copy. Confirm the exact current installer/manual-partitioning limitations before offering an unattended dual boot.

Separate payload verification, target provisioning, boot/update integration and post-boot/uninstall evidence. Preserve shared storage/ownership/rollback infrastructure.

## 4. Firmware and partition-table rules

**Preflight is read-only and fail-closed.** Authoritative inputs include Windows boot mode, disk signature/GUID, partition-style, sector size, geometry (byte-exact offsets and lengths), system/recovery partition identities, BitLocker/device encryption state, WinRE, filesystem health, free space/shrink capacity, and proven target disk.

- Allow BIOS with MBR only when the existing BIOS adapter can preserve Windows MBR boot chain and restore it exactly; allow UEFI with GPT only when the existing EFI adapter can preserve ESP/BootOrder and rollback.
- Do not add automatic BIOS-to-UEFI or MBR-to-GPT conversion. Treat UEFI/MBR and BIOS/GPT as unsupported unless independently designed and certified.
- BIOS/MBR: preserve disk signature, partition table, PBR/MBR boot code backup, active partition and Windows BCD. Require safe primary/extended layout capacity. A four-primary-partition disk is not a reason to rewrite EBRs automatically. Reject unproven extended/logical modifications and ambiguous Windows/OEM/WinRE layouts.
- Compute MBR addressability from actual sector geometry, and reject unrepresentable ranges, overflows and unintended partition movement. Honor alignment and the existing staging-to-final partition lifecycle.
- UEFI/GPT: keep Windows EFI files intact, validate ownership of every created ESP file/NVRAM entry, and use reversible temporary next-boot selection with explicit checks.
- Never auto-disable Secure Boot, BitLocker, Fast Startup, CSM or Windows recovery. If a distro requires a changed setting, explain the requirement and re-check before any mutation. When unsupported, refuse; leave Windows bootable.
- Bazzite: hard-reject MBR and BIOS/CSM before any mutation regardless of any generic installer feature flag.
- Distinguish unallocated capacity from Windows' online shrinkable NTFS capacity; do not re-partition without the proven source volume and geometry.

## 5. Lifecycle, rollback and failures

Use docs/ARCHITECTURE.md as the authority. The state/plan is immutable except the already documented runtime-observed fields. Authenticated ISO handoff must carry signed plan identity, exact transaction ID, source/target UUIDs, stage ledger, and recovery authority across reboots and potentially different live environments.

Recovery must work when:
- download, hash or source-media verification fails;
- connectivity is unavailable during package install;
- NTFS shrinking/partition staging fails;
- bootloader generation or installation is interrupted;
- electricity fails between any two committed stages;
- a wrong disk, wrong transaction marker, unexpected ESP entry, mutated BCD or foreign partition is detected;
- first Linux boot, Windows return, system update or user-requested uninstall fails.

No function may overwrite an unowned filesystem/boot asset. A recovery report is successful only after verifying Windows boot state, original geometry, WinRE/BCD and firmware-specific code/entries. Protect Windows Boot Manager content and never claim successful rollback from log files alone.

## 6. Phased delivery

### Phase A — shared contracts and safe detection
- Add source-independent distro capability metadata and schema tests.
- Create read-only Windows and live preflight for every firmware/layout pair (including intentionally rejected pairs).
- Preserve already shipped Mint/Zorin behavior and test parity.
- No mutation permitted from new code, no production catalog changes.

### Phase B — reusable, proven firmware/storage adapters
- Extend *existing* MBR tests to cover slot exhaustion, primary vs extended/logical partition chains, unknown active partition, disk signature collisions, sector-size limits, BCD restoration, and recovery after partial writes.
- Extend UEFI tests to cover Secure Boot policy differences, ESP ownership, boot entry cleanup, firmware fallbacks and Windows Boot Manager integrity.
- Test read-only simulation of every failure before optional VM writes.

### Phase C — distro backends, independently gated
- **CachyOS:** complete the existing Archiso experiment, including BIOS/MBR (separate from prior UEFI-only prototypes), target provisioning, signed handoff, boot/update guards, Windows re-entry and rollback.
- **Pop!_OS:** implement verified System76 media and account/partition provisioning, with BIOS GRUB vs UEFI systemd-boot strategy and versioned update hooks.
- **Q4OS:** choose one exact stable x86_64 native ISO flavor (Trinity or Plasma), inspect its real rootfs and provisioning mechanics, then implement only that tested path. Its existing folder-based WinSetup is not this partitioned installer.
- **Bazzite:** last, because Atomic deployment and upstream installer constraints differ substantially. UEFI/GPT only; reject BIOS/MBR and unsupported unattended-manual-layout cases before any write.
- Each backend must include complete first-boot evidence, kernel update survival, Windows boot and uninstall support; release one at a time.

### Phase D — integration and release
- Produce reproducible, version-pinned Windows executable and BIOS/UEFI mini-ISO artifacts with signed manifest.
- Run end-to-end VM installs and verified recovery matrix.
- Require reviewed logs/screenshots/checkpoint evidence for every case; publish known limitations.
- Only then consider supervised physical-disk testing with independently verified backup/restore, followed by human approval for stable release exposure.

## 7. Minimum acceptance matrix

For every candidate distribution and combination not rejected:
- Fresh Windows 10 BIOS/MBR where supported, Windows 10 UEFI/GPT, and Windows 11 UEFI/GPT.
- One-disk and validated second-internal-disk topology; disk geometry and partition/boot snapshots before and after.
- Install through the Windows UI without USB; boot Linux; reboot into Windows; reboot Linux.
- System package/kernel boot update, preserved boot menu and login; remove Linux from Windows; verify full Windows integrity and original disk/boot configuration.
- Power loss or killed VM at every persistent transition; network outage, invalid SHA/ISO, unreachable mirror, insufficient space, full 4-primary MBR slots, BitLocker active, Secure Boot-policy mismatch, mismatched disk/UUID and foreign recovery state.
- Read-only/VM CI is necessary but not sufficient. Smoke tests for EFI binaries, synthetic loopbacks or package installation in a pre-mounted root cannot substitute for the full flow.
- Bazzite negative tests: hard rejection for BIOS/MBR, UEFI/MBR and unsupported manual/Atomic workflows.

### Release gate

**Keep new distros disabled in stable catalog and release binaries until every required successful and rejection case has evidence.** A human maintainer must review results. Document exact unsupported combinations and rollback limitations. Do not mark VM-only or untested physical-hardware paths as generally stable.

## 8. Evidence and upstream references

Repository:
- docs/ARCHITECTURE.md
- docs/UEFI_BOOTNEXT_BOOTORDER.md
- release-config.json
- assets/live/libertix-distribution-common.sh
- GitHub issue #3: https://github.com/LMhdez/gaslux/issues/3
- CachyOS experimental draft PRs #4, #5 and #6

Distribution sources:
- CachyOS installation: https://wiki.cachyos.org/installation/installation_on_root/
- System76 bootloaders: https://support.system76.com/support/bootloader
- System76 Pop!_OS installation: https://support.system76.com/support/install-pop/
- Bazzite compatibility: https://docs.bazzite.gg/Gaming/Hardware_compatibility_for_gaming/
- Bazzite legacy ISO/manual partitioning note: https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
- Zorin OS installation: https://help.zorin.com/docs/getting-started/install-zorin-os/
- Q4OS native install guide: https://www.q4os.org/dqa018.html
- Q4OS Windows folder-based installer: https://www.q4os.org/dqa014.html

Upstream behavior can change. Re-check current release media, install method and documented support for each pinned version before implementation or release.
