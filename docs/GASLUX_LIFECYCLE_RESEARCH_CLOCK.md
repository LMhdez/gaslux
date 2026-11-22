# GASLUX — autonomous distro lifecycle research clock

This default-branch GitHub Actions workflow is a **read-only research stage** toward
complete unattended Windows + Linux installer acceptance. It is deliberately not
a claim of installation, dual boot, upgrade, removal or recovery.

## Native schedule

- Every 30 minutes, execute six independently reported distro agents: Mint,
  Zorin, CachyOS, Pop!_OS, Q4OS and Bazzite.
- Read the current `dev` acceptance matrix and independently review the goal
  supervisor's fail-closed policy.
- Re-run applicable actual repository contract tests under separate ephemeral
  runners, with no repository write token, and save a JSON report identifying
  the earliest missing platform/gate for that distro.
- Measure the available GitHub runner capacity for a disposable 60-GiB sparse
  Windows/Mint VM target. Capacity measurements never authorize a disk writer.
- Once per day, download the official SHA-256-pinned Mint 22.3 ISO and attempt
  to boot its real Linux kernel and serial login in a private QEMU/OVMF guest.
  Logs are saved as evidence; ISO and guest disk images are never uploaded.

Each workflow may also be dispatched manually, but it does not depend on
ChatGPT schedules or recurring paid API usage.

## Required evidence before full installer completion

The existing `docs/autonomy/goal.json` on `dev` requires the following gates,
for every supported Windows platform/distro combination:

1. Source authenticity and official media hashes.
2. Windows preflight and authenticated disk/partition provenance.
3. Installation in a **disposable VM**, with a pre-install snapshot and
   measured, explicitly authorized, isolated guest write targets.
4. A guest-origin-attested first Linux boot with independent observations.
5. Windows return boot with before/after partition, ESP/BCD and recovery
   comparisons.
6. Linux update and second boot.
7. Uninstallation with Windows system and boot integrity evidence.
8. Injected failures and verified snapshot restoration/recovery.

The Mint *live ISO* experiment does not satisfy gate 3 or 4: a live session
is not the installed guest. A sparse QCOW2 also does not satisfy them.

Real acceptance needs a lawful verified Windows 10/11 installation source,
bounded runner storage, instrumented dual-boot VMs, independent Safety review
of disk-write ownership, and actual installed-guest evidence. These prerequisites
are not silently assumed to exist. This workflow never upgrades a research
report to release eligibility or grants arbitrary AI-generated installer code
the authority to merge.

The existing coding agent still has automatic merge authority only for the
separately validated, exact low-risk keyboard mappings. Full-distro code
changes must first enter a dedicated draft review and full VM acceptance
process; there is no unrestricted installer auto-merge.
