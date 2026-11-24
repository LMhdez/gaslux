# GASLUX autonomous development: restricted Draft PR publisher pilot

**Date:** 2026-11-22 UTC  
**Status:** experimental Draft PR, live isolated publication VERIFIED; not merged into `dev` pending independent Safety review and exact-head checks.  
**Related:** `docs/AUTONOMY_ROADMAP.md`, `docs/LOCAL_CODER_ACTIONS_FEASIBILITY.md`, merged #363/#364.

## Why this exists

The project target is autonomous development toward complete safe Windows-to-Linux installation, **not** a benchmark. An actionable closed loop requires converting verified model-generated fixes into reviewable PRs. This pilot exercises exactly that trust boundary for one noncritical Python ranking defect; it is not yet broad project autonomy.

## Threat model and hard restrictions

- Untrusted Ollama output is only interpreted in the **unprivileged** GitHub Actions worker, without write token or persisted checkout credentials.
- The candidate job must observe a **genuine test RED** on a trusted `dev` file (not a seeded PR simulation), generate at most two model attempts, and obtain independent focused test GREEN.
- A separate publisher job has `contents: write` / `pull-requests: write` **only on a trusted `push` to `refs/heads/dev`**, never on pull_request or fork events. Publisher source is checked out from the triggering exact commit.
- Publisher does not compile, import, execute or test model-generated source while holding credentials. It validates artifact hashes, evidence status, fixed Ollama model identity, source SHA-256 and current `dev` commit.
- Publisher only permits the exact one-line correction from `reverse=False` to `reverse=True` in `auto_tests/tools/rank_capture_changes.py` within `ranked_changes`. A matching source must have exactly one such return. Every other file, construct or purported repair is rejected.
- The branch `bot/ai-rank-repair-<dev-sha12>` is unique and created only when not already present, avoiding duplicate proposals for the same failing commit. GitHub's endpoint-level ability to create Draft PRs has now been **verified in an isolated laboratory**, not yet exercised in integrated `dev`.
- The output is **Draft PR only**, never auto-merge, release, installation, firmware, partitioning or Windows recovery mutation.

## Evidence required before merge

1. Adversarial no-network unittest suite, including fake REST write sequence, stale-`dev` denial, source mismatch, non-approved code denial, RED/GREEN evidence validation and pull_request trigger denial.
2. PR exact-head applicable CI must pass. A successful test using a mocked GitHub API **is not** evidence of actual GitHub repository permission to open PRs.
3. Independent Safety assessment of credentials and artifact provenance, branch race conditions, issue/PR injection, write scope, idempotency and platform Actions settings. **Still pending.**
4. A separate disposable integration lab must verify successful authenticated Draft PR publication from an actual **noncritical failing test** without deliberately breaking `dev`. **PROVEN in run #45052761838.**
5. Full project autonomy needs a curated task selector, broader model performance, review automation and CI proof for each distro. This narrow pilot cannot be presented as the completed system.

## Fail-closed behavior

A moved `dev` SHA, wrong artifact digest, missing independently witnessed RED/GREEN status, wrong model, simulated run, unexpected path/diff, existing proposal branch or insufficient GitHub token permissions must never produce an accepted PR. The GitHub setting allowing Actions-created PRs is **functionally VERIFIED** by the actual workflow-created Draft PR #367. This only resolves the prior HTTP 403 and does not assert Safety signoff or general agent capabilities.

The previous, more broadly permissive publisher remains quarantined on `research/local-coder-publisher-safety-hold-20261122`. This pilot was authored with tighter one-line constraints, but independent technical review is still pending.

## Successful real GitHub Actions publication — 2026-11-22 UTC

- [Actions run #45052761838](https://github.com/LMhdez/gaslux/actions/runs/45052761838), disposable lab HEAD `5fd56b4b76d2b85289fdfa0966647c529b92e06c`: **SUCCESS, 3/3 jobs**, including nonprivileged Qwen3.5 9B RED→GREEN correction, adversarial publisher contract suite and tokened publisher.
- `github-actions[bot]` **automatically created** [Draft PR #367](https://github.com/LMhdez/gaslux/pull/367) with head `520d44087a27179dd53c5d4f290a0d43c8265f1a`, targeting the disposable laboratory branch. The diff contained **only** `auto_tests/tools/rank_capture_changes.py` with the permitted `reverse=False` → `reverse=True` correction.
- The laboratory PR was **closed without merge** after verification. This is proof that the repository now allows GitHub Actions to create a Draft PR using its `GITHUB_TOKEN`; it is **not** a claim that the production `dev` publisher was activated.
- Compared with the prior 403, the setting restriction was resolved by the user. The current source also includes the no-orphan cleanup path and its negative tests.
- **Remaining:** independent security review of privileged token/artifact boundaries on the exact PR #365 HEAD; full-project task discovery, generic code-correction reliability and unattended safe integration remain future engineering steps. No installer, boot, partitioning, rollback or production release authority was granted.

## Earlier negative lab evidence — 2026-11-22 UTC

- [GitHub Actions #45051774631](https://github.com/LMhdez/gaslux/actions/runs/45051774631) executed on disposable branch `autonomy/lab-ai-rank-publisher-20261122`, HEAD `0904bc5c3703a37ddacacd502c7ca7a3f44fcbb0`; deliberately inserted the `reverse=False` regression **only on that lab branch**, not `dev`.
- **Worker: SUCCESS.** Qwen3.5 9B produced the expected correction and passed the focused RED→GREEN assertions. The no-network privileged publisher adversarial tests also passed.
- **Publisher: FAILED at GitHub POST `/pulls` with HTTP 403.** Earlier API calls successfully created the bot branch `bot/ai-rank-repair-0904bc5c3703`, commit `daaf342877024e4d14bc5456cbe23deddd0d9470`, containing exactly one Python line change. The 403 confirms a GitHub-token authorization blocker; whether caused by the repository's Actions PR-creation setting or another permission must be verified separately, not guessed.
- [Lab Draft PR #366](https://github.com/LMhdez/gaslux/pull/366) was created using the **connected maintainer GitHub integration**, *not* the workflow, to independently inspect the bot branch diff; it showed only `reverse=False` → `reverse=True`. It was then **CLOSED UNMERGED**. This does not demonstrate automated PR publication.
- The publisher pilot is updated to clean up its **own exact bot branch** after a failed PR API call, but only when the ref still points at the commit this job created. This new failure-path logic requires another exact-head CI run and Safety review.
- **Activation now remains blocked only by applicable Safety review and integration checks**, not by the previous token permission or lab PR creation. No privileged publisher has been merged into `dev`.

