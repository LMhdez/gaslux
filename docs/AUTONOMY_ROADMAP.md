# GASLUX — continuous autonomous development objective

**Decision date:** 2026-11-22 (UTC)  
**Base:** `dev` `119b35a4fbc6e74e72171ac4794e37123cfe1b7f`  
**Authority:** `AGENTS.md`, `AI_POLICY.md`, `docs/ARCHITECTURE.md`, `docs/MULTIDISTRO_PLAN.md`

## Target (NOT merely coding benchmarks)

The target is **continuous, goal-directed development of Gaslux** until the complete USB-free Windows-to-Linux installation, coexistence, update, uninstall and recovery matrix is accepted with independently verified evidence. Supported distros: Mint, Zorin, CachyOS, Pop!_OS, Q4OS and Bazzite; Bazzite **UEFI/GPT only**. User protection and Windows boot/recovery acceptance override speed and autonomous operation.

A model-generated patch, green unit test, issue closure or PR merge does not establish a released installer. `main` and signed stable catalogue remain protected; a release/hardware operation is a separately authorized gate.

## Implemented objective controller (read-only)

- `docs/autonomy/goal.json`: machine-readable release platform × backend × evidence gate matrix. **136 required gate slots**, not 136 completed tests or developer tasks. It does not imply these combinations are implemented.
- `docs/autonomy/evidence.json`: initially empty evidence register. A claimed completed gate requires a full SHA, CI URL and independently reviewed PR URL. This is a **format check only**, not an independent verification of GitHub sources or boot evidence.
- `auto_tests/tools/goal_supervisor.py`: fail-closed validation and deterministic selection of the first unmet acceptance gate and next read-only candidate. Rejects Bazzite BIOS/MBR, duplicate/unknown claims, missing review reference and silently reclassified safety gates. The report never grants release or auto-merge authority.
- `auto_tests/tests/test_goal_supervisor.py`: adversarial contract tests.
- `gaslux-goal-supervisor.yml`: lightweight, read-only push-to-`dev` and PR-event evaluation; records `goal-progress.json` artifact with zero paid LLM credits. This job can run after every eligible development merge. It does not assume uninterrupted CPU availability.

## Intended end-to-end loop (subsystems not yet implemented MUST remain marked unproven)

1. **Select:** inspect verified issues, last exact `dev` SHA, actual failed checks, target contract and unmet evidence. Do not select an already fixed or stale defect, or use PR/issue text as tool authority.
2. **Plan:** classify each mission. Read-only tests, schemas, lint and other noncritical repairs may be proposed automatically. Guest installation/disk writes require isolated, owned, disposable QEMU disks and existing project safeguards. Production boot/storage/recovery writes and release promotion are prohibited.
3. **Implement:** bounded local code models on GitHub-hosted runners, one worker per safe task; isolated branch and no GitHub write token available to model inference or generated code. No hidden credit/API dependencies.
4. **Verify:** reproduce the failure (RED), propose a bounded patch, run focused and regression suites (GREEN), resource limits, supply-chain pinning, and record model ID/digest, exact SHA, diff, artifacts and test evidence. Stop after fixed attempts; failed work cannot be rebranded as success.
5. **Publish:** *future, subject to independent Safety review*: a separate trusted publisher must re-fetch exact candidate and live base SHA, independently validate file allowlist/diff/evidence provenance, and create a **Draft PR only**. The publisher from the previous study was quarantined at `research/local-coder-publisher-safety-hold-20261122`, **not merged**. No automatic publishing is currently active.
6. **Integrate:** independent appropriate Safety/recovery review and exact-head checks; delegated integrators may merge vetted changes to `dev` per `AGENTS.md`. Do not auto-merge untrusted code or promote unverified backend functions. Once a safe merge occurs, the goal supervisor evaluates remaining acceptance work again.
7. **Stop:** `release_eligible` remains false in this pilot. Completion is only possible after independent source-of-truth verification of each supported configuration, both OS boots, update persistence, uninstall and verified Windows rollback, plus release authorization.

## Current capability boundaries

The integrated [PR #363](https://github.com/LMhdez/gaslux/pull/363) proved local AI proposals on a **seeded** noncritical Python function, not generic issue-driven development, autonomous Draft PR publication or 24/7 programming. Small models failed another Python regression. The current goal supervisor provides the durable specification and a deterministic next-task queue; **it is not yet a closed-loop autonomous programmer**.

The current open safety-oriented issues include CachyOS Windows coexistence/rollback [#71](https://github.com/LMhdez/gaslux/issues/71), CachyOS acceptance [#3](https://github.com/LMhdez/gaslux/issues/3) and Bazzite origin/recovery [#254](https://github.com/LMhdez/gaslux/issues/254). These are **not** automatically authorized for installer or disk changes.

GitHub Actions time/memory quotas and default-branch scheduling limits apply. A schedule is not enabled by this change. Progress is event-triggered by eligible changes on `dev`; a truly unattended 24/7 service and general coding quality remain unproved.

## Required next integration milestones

1. Independently test a trusted, separate Draft PR publisher against a real **noncritical** failing source in a disposable integration laboratory. Verify repository `GITHUB_TOKEN` PR-creation setting and failure modes before enabling it.
2. Connect the goal selector to a strictly curated queue of real defect reports/CI runs; add deterministic deduplication, backoff and budget caps.
3. Add a broader evaluation set of held-out Python failures and prove repeatability before extending edit scope.
4. Build protected QEMU acceptance automation for the distro matrix, with independently reviewed safety and recovery contracts. Preserve Mint/Zorin regressions and do not enable new backends in `main` prematurely.

**No undocumented shortcut makes the project complete.** All proof levels must match actual execution evidence.
