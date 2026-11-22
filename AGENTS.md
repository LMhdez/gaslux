# AGENTS.md — Gaslux engineering instructions

These instructions apply throughout this repository. Gaslux extends Libertix; it does not replace the existing safety architecture.

## Objective and current baseline

Build an optional, verified, USB-free Windows-to-Linux installer that can install and later remove a supported Linux distribution alongside Windows, across supported firmware and disk layouts. The intended distribution set is Linux Mint, Zorin OS, CachyOS, Pop!_OS, Bazzite and Q4OS.

**Do not confuse a distribution's upstream ability to boot with Gaslux's proven ability to install it.** On main, the production catalog contains Mint 22.3 Cinnamon and Zorin OS 18.1 Core. Main already implements BIOS/MBR and UEFI/GPT infrastructure for those existing backends. Experimental CachyOS code exists on separate feature branches and draft PRs; it is not a finished installer. No additional distribution is production-ready merely because this document lists it.

Before changing disk, firmware, recovery, catalog, or installation logic, read:
- docs/ARCHITECTURE.md — authoritative runtime/transaction/rollback contract
- CONTRIBUTING.md and AI_POLICY.md — delegated multiagent workflow, accountable authority, evidence and license
- docs/RELEASES.md — signing and release gates
- docs/UEFI_BOOTNEXT_BOOTORDER.md — firmware recovery
- docs/MULTIDISTRO_PLAN.md — expansion matrix, phases and acceptance tests

## Delegated multiagent engineering and integration

Gaslux uses orchestrated agents for implementation, adversarial safety audits, evidence verification, PR review, forensic investigation and integration. Authorized agents may open/update PRs, answer review threads, run approved checks, fix defects, reconcile stacked branches and, when expressly delegated, merge vetted work or close proven-redundant PRs. Human oversight is **substantive and risk-based**, not a mandatory manual response or approval click for every operation.

Before acting, recheck GitHub branch/PR HEADs, the actual diff, current checks, dependencies and prior findings. Attribute actions and evidence to the executing agent and authorized account. A different agent name does not prove independent review. When integrating, preserve unique commits, artifacts, unresolved findings and rollback evidence; do not move an unverified experimental backend into the production installer or stable catalog.

### Operational merge rule for delegated integrators (dev only)

A maintainer's explicit delegation to **integrate vetted changes into `dev`** is standing authority for the assigned scope. **Do not request a separate human confirmation, approval click or formal GitHub review for each PR unless an actual GitHub branch protection/ruleset requirement, applicable repository policy, unresolved high-risk finding or separately reserved authority requires it.** Absence of an optional human review is not by itself a blocker. A reproducible independent technical Safety assessment may be documented in a PR comment; do not misrepresent it as a formal GitHub `APPROVE`.

For each delegated integration, **perform the operation rather than stop at `READY_FOR_HUMAN_REVIEW`** when all applicable gates are satisfied:

1. Revalidate the exact PR head, current `dev` head, changed files, dependency chain, mergeability, reviewer findings and all required checks. Prevent concurrent-head races using an exact-head merge precondition.
2. Confirm evidence appropriate to the risk: successful tests/CI on the exact candidate or validated merge composition; no unresolved safety findings, privilege escalation, new unverified writer/guest authority or accidental stable-catalog exposure. Apply independent technical review when warranted by the change, irrespective of whether formal GitHub approval is required.
3. Respect **enforced** branch protections, status checks, signed-commit/DCO requirements and repository policies. Never fabricate `Signed-off-by`, an independent approval or a test result; seek only the specific decision genuinely required.
4. When eligible, merge into `dev` with the permitted method, confirm the resulting commit, inspect post-merge CI and stop additional merges if a required regression fails. Leave `main`, physical disks, release promotion and production installation authority unchanged.
5. Reconcile historical/stacked PRs first where possible, preserve unique work and evidence, close **proven** duplicates, and delete **proven obsolete** branches only with authenticated permission and dependency checks. Avoid new reconciliation branches/PRs merely to reduce the queue.
6. Report actual merges, closures, branch deletions and before/after counts with URLs and SHAs. If blocked, state the precise enforced gate or concrete technical finding; continue with other eligible work instead of repeatedly requesting ceremonial approval.

**Green CI alone is not sufficient for a safety-critical merge**; the evidence and authority checks above still apply. This standing delegation applies only to repository integration in `dev` and never grants runtime disk/boot mutation, real-hardware testing or release/stability approval.

### GitHub Actions VM testing: standing authorization

**Agents may create, trigger and rerun GitHub Actions workflows using disposable QEMU virtual machines without a separate human approval for each test run.** This authorization covers SeaBIOS/MBR and OVMF/UEFI guests, KVM if the runner supports it, verified Linux/Windows test media, real guest installation and first boot, virtual GPT/MBR/NTFS/ESP/BCD changes, power-loss fault injection, updates, Windows/Linux dual boot and guest rollback **inside test-owned virtual disk images only**. It is not limited to read-only diagnostics. A workflow's explicit guest-destructive opt-in is sufficient when the controls below are satisfied.

- Use ephemeral, isolated CI runners and fresh **regular-file virtual disks** or known-restorable snapshots; verify exact image ownership, path, hash/geometry/backing where applicable, and recovery baseline before guest writes. Never attach host `/dev/` block devices, physical disks, production partitions, user data or external shared storage as writable guest media.
- Keep the guest's writable image and test outputs inside an isolated workspace; bound time, size, resources and networking. Avoid leaking credentials: workflow `permissions` should normally be `contents: read`, checkout credentials should not persist, and secrets must not reach untrusted PR guests.
- Pin and verify the intended ISO/OS media and test-image provenance. Deny absent/wrong images, ambiguous targets, unsupported firmware/layouts, insufficient space or failed snapshot preparation; do not assume nested KVM or Windows VM availability on every runner.
- Record actual QEMU configuration, boot observations, disk-image identity, pre/post geometry, state/checkpoints, Windows/WinRE/BCD checks when applicable, fault-injection result and rollback evidence. Distinguish live boot, installation, dual boot and in-place Windows recovery; **CI success alone never proves a stable backend**.
- If a job cannot maintain these boundaries, stop before mutation and report the blocker. GitHub Actions VMs are low-risk when isolated, **not literally risk-free**; do not expose host disks or relax privilege/safety controls.

**Existing coverage is not Mint-only.** Inspect the full workflow set on `dev` **and on the relevant PR/feature branch**, including Linux guest boots (`mint-223-live-ovmf-boot.yml`, `zorin-real-iso-preflight.yml`, `gaslux-q4os-official-iso.yml`); historical/experimental Windows and distro QEMU suites (`windows-x64-two-stage-firstboot.yml`, `cachyos-windows10-shared-root-pacstrap.yml`, `zorin-windows10-cow-firstboot.yml`, `gaslux-q4os-windows10-qcow2.yml`, `q4os-summary-repro-2vm.yml`); and Observer/Safety QEMU (`installer-observer-lab.yml`, `safety-qemu-gpt-host-guest.yml`). These are **examples across different refs, not a claim that all are present or runnable on `dev`**. Workflows with `QEMU` in their title may run offline contracts only; read the exact YAML and invoked scripts before declaring a real guest run. Use existing workflows/VM infrastructure before creating redundant pipelines, and confirm exact-head Actions status and artifacts before claiming results.

The project delegates this bounded CI VM test authority in [AI_POLICY.md](AI_POLICY.md). **No per-run human confirmation is required** when the workflow meets these guards. This does not authorize physical hardware experiments, production disk/boot writes, credential changes, or release/stable promotion.

Repository modification permissions never grant authority to mutate real disks or production boot state. Destructive *guest-only* experiments are permitted under the standing GitHub Actions VM authorization above; real-hardware experiments require separate explicit authorization. See [AI_POLICY.md](AI_POLICY.md) for the authority model and reporting requirements.

## Non-negotiable safety rules

1. Default to **read-only inspection**. Do not expose unfinished backends in release-config.json, the signed stable catalog, or the WPF distribution picker.
2. Never perform destructive operations on physical disks for development, demos, or automatic tests. Mutating integration tests must require an explicitly opted-in, disposable VM with verified disk identity and snapshots.
3. Before any disk, BCD, MBR, ESP or NVRAM mutation: validate signed metadata, artifact SHA-256, ISO identity, Windows system disk, exact geometry, firmware mode, partition table, encryption state, shrink capacity, transaction ID and rollback readiness. Reject ambiguous or unsupported states.
4. Preserve Windows data, OEM/Recovery partitions, WinRE, BCD, Windows Boot Manager, boot priority, and unrelated partitions/disks. Never select a disk by /dev/sdX, drive-letter or enumerate-first shortcuts alone.
5. Installation is a transaction. Keep the existing stage ledger and compensating rollback semantics. Every persistent write must have an ownership proof, a stage checkpoint, a revalidation on resume and a verified recovery path. A log or marker alone is not proof of success.
6. Never silently convert MBR to GPT, change BIOS to UEFI, enable/disable Secure Boot, change firmware keys, or rewrite an unowned bootloader. Unsupported configurations fail closed, with a clear message and no mutation.
7. Do not assume a common root filesystem, package manager, initramfs tool, bootloader, Secure Boot signing policy or update hook across distributions. Never extract an Archiso live root or an Atomic OS image as though it were an installable Debian target.
8. Do not bypass release signature verification in production, manufacture checksums, weaken existing preflight, or change release metadata before end-to-end acceptance.
9. Keep Mint and Zorin regressions green. New backend development must not alter the production path's safety guarantees.
10. Do not describe a smoke test, mocked ISO, CI green status, or first-stage provisioning as proof of full boot, Windows dual boot, complete rollback, or physical-disk stability.

## Explicit compatibility policy

- BIOS/MBR and UEFI/GPT are distinct, explicitly tested firmware adapters. Do not infer support for UEFI/MBR or BIOS/GPT. Preserve existing validated BIOS/MBR support.
- MBR has four primary partition entries, subject to extended/logical layout constraints. Refuse plans without a safe slot or a provably supported existing logical-layout path. Never rewrite an extended partition chain speculatively. Check addressing limits using actual logical sector size and exact bytes rather than a blanket disk-size heuristic.
- Mint and Zorin: maintain existing Debian/Ubuntu-family extraction path; validate per-release image capabilities rather than assuming an arbitrary new ISO uses the same layout.
- CachyOS: upstream documents BIOS/MBR as well as UEFI/GPT, but Gaslux has proven neither complete install path. Implement a separately authenticated Archiso handoff and Arch-native target/boot management. Do not reuse dpkg/shim hooks.
- Pop!_OS: implement an independently validated System76 path. UEFI normally uses systemd-boot; Legacy BIOS uses GRUB. Secure Boot must be disabled according to current System76 installation guidance. Verify specific releases before enabling.
- Bazzite: **UEFI/GPT only**. BIOS/CSM and MBR are hard preflight rejections. The Atomic deployment/boot/update workflow requires its own backend, including installer constraints and supported Secure Boot enrollment. Do not pretend this is an rpm/deb squashfs extraction.
- Q4OS: evaluate its Debian live/installer media by verified capabilities. The upstream Windows setup is a filesystem-contained installation, not equivalent to Gaslux's native partitioned dual boot; do not import its assumptions.
- Unsupported combinations remain hidden or explicitly disabled with precise user-facing reasons.

## Architecture of new work

Model distribution capabilities (release identity, source/installer format, backend ID, firmware/layout matrix, package/update system, boot manager, Secure Boot policy and minimum disk resources) separately from branding. All metadata must be schema-validated and authenticated. Pin an exact image version/size/hash; reject unsupported media updates.

Use backend-specific modules for: source acquisition and verification; trusted live-environment handoff; target provisioning; bootloader integration and kernel update persistence; first-boot evidence; uninstall/rollback. Reuse the existing typed plan, transaction ownership, storage preflight, stage ledger and Windows integrity checks. An experimental backend must not be reachable through the production dispatch.

Keep contracts in sync across Installation/*.cs, Scripts/modules and Scripts/uefi, assets/live, schemas, iso-tools and signed catalog logic; explicitly update tests when schemas or stage order change. Follow the existing firmware adapters instead of implementing a parallel disk writer.

## Where to work

- Windows UI/plans: Pages/, Models/, Installation/
- Storage preflight/Windows preparation: Scripts/modules/, Scripts/uefi/, Scripts/libertix-*.ps1
- Live runtime and distro backends: assets/live/, iso/, iso-uefi/
- Contracts and releases: schemas/, release-config.json, iso-tools/
- Existing tests: Libertix.Tests/, PowerShell.Tests/, auto_tests/
- Review experimental CachyOS branches and draft PRs as **research**, not as stable baselines.

## Implementation and test sequence

1. Document exact capabilities and preflight rejections, add non-mutating contract/unit tests.
2. Implement one backend at a time behind explicit feature gates. Start with existing Zorin/Mint regressions and an incremental CachyOS path; then Pop!_OS, Q4OS, Bazzite according to backend feasibility.
3. Validate signed download and live handoff, then target creation, bootloader, first boot, Windows re-entry, update behavior, uninstall and recovery.
4. Test on disposable virtual disks under SeaBIOS/MBR and OVMF/GPT as applicable; include Windows 10 BIOS/MBR, Windows 10 UEFI/GPT and Windows 11 UEFI/GPT. Add Bazzite BIOS/MBR rejection assertions.
5. Inject failures at each mutating stage (hash mismatch, network loss, interrupted writes, wrong UUID, power loss, boot manager tampering, full disk) and verify Windows boot, partition geometry, WinRE, BCD, ESP or MBR restoration.
6. Require actual boots of Linux and Windows, distro updates and post-update reboot, plus user-requested uninstall in addition to read-only mocks.
7. Only after all gates pass may a human maintainer consider supervised physical-hardware testing with proven backups and restores, and then stable catalog enablement.

## Definition of done for every PR

Describe supported and rejected firmware/distro combinations, exact code paths and version-pinned artifacts, threat/rollback model, tests actually executed, links to CI/VM evidence, reproducible remaining blockers, and effect on Mint/Zorin. Mark unverified claims as unverified. Keep incomplete work in draft PRs. Apply risk-based human oversight and traceable, evidence-based technical review under AI_POLICY.md. An explicitly delegated integrator may merge a vetted PR without per-PR manual approval, but no reviewer or agent may waive safety, release, recovery or physical-disk authorization gates. Contributions must respect GPL-3.0, provenance and DCO guidance.
