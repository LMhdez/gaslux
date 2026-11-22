# GASLUX — GitHub-native autonomous Integrator

**Date:** 2026-11-22 UTC. **Scope:** default-branch workflow infrastructure only, not installer/recovery code. Operates alongside `.github/workflows/gaslux-agent-clock.yml` (Supervisor + Qwen3.5 9B role worker + Safety + Windows acceptance).

## Own independent executor

The Integrator is `.github/workflows/gaslux-agent-integrator.yml`, scheduled on the default branch at **minute 53 each hour** and available by `workflow_dispatch`. The Supervisor runs at minute 37, a staggered schedule; GitHub queues are best-effort and may delay or skip a scheduled run. Both are GitHub-hosted processes, not ChatGPT tasks. GitHub Actions minutes, ephemeral storage and model download resources are finite.

## Exactly what may merge automatically into dev

The complete automatic merge allowlist is **two additions** to `Installation/WindowsKeyboardLayout.cs`:

- `MINT-PT-KEYBOARD-01`: Windows `00000816` → XKB `pt`, inserted once after existing `00000809` mapping.
- `ZORIN-BR-KEYBOARD-01`: Windows `00000416` → XKB `br`, inserted once after existing `0000040C` mapping.

The trusted Integrator refuses any other source, added or removed line, changed existing code, unrecognized role, PR created by a non-bot account, fork, extra commits, stale `dev`, non-draft PR, mismatched bot branch suffix, review requesting changes, `SAFETY_DENIED`/`BLOCKED_SAFETY`/`DO_NOT_MERGE` comment, or unresolved failing candidate checks.

Only `github-actions[bot]` Draft PRs whose HEAD is **one commit directly descended from the exact current `dev`** may be considered. The Integrator fetches the original and modified C# bytes independently from GitHub and verifies the entire file equals precisely the permitted single-line insertion. It does not trust model-authored evidence or execute candidate code in the privileged job.

## Execution sequence and evidence

1. **Read-only selector (Ubuntu):** revalidate exact GitHub bot PR, `dev` HEAD, ancestry, changed files, contents, Safety objections, and existing CI outcomes. Run adversarial offline tests. If none, IDLE (no Windows build).
2. **Windows acceptance (Windows 2022):** checkout precisely the validated PR HEAD (not the moving branch), verify `git rev-parse HEAD`, build the actual .NET Framework WPF product and run the C# test project. The worker has no write token.
3. **Trusted merge (Ubuntu):** only if the Windows job finishes **successfully**, checkout the trusted workflow source from `main`, revalidate the PR and live `dev` twice, then request a **squash merge into `dev`** with the exact SHA precondition. The only write-capable job has `contents:write` and `pull-requests:write` permissions. GitHub branch protection can still deny the merge. No change to `main` source or signed release catalogue occurs through this component.

A PR created using the workflow `GITHUB_TOKEN` may not itself trigger pull_request CI. The Integrator compensates for that by explicitly running its own exact-HEAD Windows build and contract tests before attempting merge. **Its scheduled run is associated with the trusted main workflow commit**; log and artifact SHA must be inspected to validate the candidate. This is a bounded delegated integration for noncritical code, **not** a general autonomous Safety approval.

## Non-claims, limitations, and future work

- No arbitrary LLM-authored patch can be merged by this Integrator; other distro roles have no merge authority.
- A Windows C# keyboard mapping, even when compiled and merged, does not demonstrate USB-free installation, Windows/Mint dual-boot, update survival, uninstall, WinRE or rollback. Those remain separate 136 objective gates and require VM or genuine system evidence.
- A GitHub `success` on a unit test, a mock API or a scheduled run does not mean the model successfully implemented a feature; inspect the recorded candidate SHA, Windows build result and actual merge.
- Do not add permissions for disks, boot, firmware, recovery or stable release. Future new tasks and new code allowlists require independent adversarial tests and risk-appropriate Safety review.
- Two timed workflows cannot guarantee 24/7 continuous compute, exactly-once delivery or global task completion. For full autonomy, extend verified functionality selection, broader coding ability, VM infrastructure, genuine end-to-end tests, automatic repair and evidence-based integration without diluting these safeguards.

**Prerequisites:** the GitHub Actions setting allowing workflow-created PRs was demonstrated in the earlier isolated bot PR #367. The trusted `main` clock from PR #371 and the model developer in `dev` must remain operational. PR #374 fixed stale source SHA in Windows acceptance. Do not merge this Integrator merely because the Python mock tests pass; validate exact PR HEAD and operational trial first.

Generated-by: GPT-6.

## Event-driven continuation on trusted model completion

The Integrator also listens to GitHub's `workflow_run: completed` notification for the first-party **Gaslux autonomous GitHub agents** workflow, restricted to `main`. It only selects work if the producer has `conclusion=success`, `head_branch=main` and the correct repository origin. The privileged Integrator independently parses and checks the originating GitHub event JSON again, including producer name, origin and trusted trigger type; a different or failed workflow cannot grant merge authority. This avoids having to wait until the next hourly slot after a successful bot Draft PR. The minute-53 schedule remains a fallback.

The job still performs its own read-only source/PR selection, complete Windows WPF build + MSTest on the exact immutable candidate, and a final privileged dev-only merge gate. A GitHub event notification is not an approval, and cannot bypass either acceptance step.

