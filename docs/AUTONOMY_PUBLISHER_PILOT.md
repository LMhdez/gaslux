# GASLUX autonomous development: restricted Draft PR publisher pilot

**Date:** 2026-11-22 UTC  
**Status:** experimental Draft PR, NOT merged or enabled until independent Safety review and exact-head checks.  
**Related:** `docs/AUTONOMY_ROADMAP.md`, `docs/LOCAL_CODER_ACTIONS_FEASIBILITY.md`, merged #363/#364.

## Why this exists

The project target is autonomous development toward complete safe Windows-to-Linux installation, **not** a benchmark. An actionable closed loop requires converting verified model-generated fixes into reviewable PRs. This pilot exercises exactly that trust boundary for one noncritical Python ranking defect; it is not yet broad project autonomy.

## Threat model and hard restrictions

- Untrusted Ollama output is only interpreted in the **unprivileged** GitHub Actions worker, without write token or persisted checkout credentials.
- The candidate job must observe a **genuine test RED** on a trusted `dev` file (not a seeded PR simulation), generate at most two model attempts, and obtain independent focused test GREEN.
- A separate publisher job has `contents: write` / `pull-requests: write` **only on a trusted `push` to `refs/heads/dev`**, never on pull_request or fork events. Publisher source is checked out from the triggering exact commit.
- Publisher does not compile, import, execute or test model-generated source while holding credentials. It validates artifact hashes, evidence status, fixed Ollama model identity, source SHA-256 and current `dev` commit.
- Publisher only permits the exact one-line correction from `reverse=False` to `reverse=True` in `auto_tests/tools/rank_capture_changes.py` within `ranked_changes`. A matching source must have exactly one such return. Every other file, construct or purported repair is rejected.
- The branch `bot/ai-rank-repair-<dev-sha12>` is unique and created only when not already present, avoiding duplicate proposals for the same failing commit. GitHub's endpoint-level permission is still needed and has not been verified in a live run.
- The output is **Draft PR only**, never auto-merge, release, installation, firmware, partitioning or Windows recovery mutation.

## Evidence required before merge

1. Adversarial no-network unittest suite, including fake REST write sequence, stale-`dev` denial, source mismatch, non-approved code denial, RED/GREEN evidence validation and pull_request trigger denial.
2. PR exact-head applicable CI must pass. A successful test using a mocked GitHub API **is not** evidence of actual GitHub repository permission to open PRs.
3. Independent Safety assessment of credentials and artifact provenance, branch race conditions, issue/PR injection, write scope, idempotency and platform Actions settings.
4. A separate disposable integration lab should verify successful authenticated Draft PR publication from an actual **noncritical failing test** without deliberately breaking `dev`.
5. Full project autonomy needs a curated task selector, broader model performance, review automation and CI proof for each distro. This narrow pilot cannot be presented as the completed system.

## Fail-closed behavior

A moved `dev` SHA, wrong artifact digest, missing independently witnessed RED/GREEN status, wrong model, simulated run, unexpected path/diff, existing proposal branch or insufficient GitHub token permissions must never produce an accepted PR. The required GitHub setting allowing Actions-created PRs is **unverified**, so no live publication success is claimed.

The previous, more broadly permissive publisher remains quarantined on `research/local-coder-publisher-safety-hold-20261122`. The code in this pilot is independently written with tighter one-line constraints, but the technical review is still pending.

## Live isolated lab evidence — 2026-11-22 UTC

- [GitHub Actions #45051774631](https://github.com/LMhdez/gaslux/actions/runs/45051774631) executed on disposable branch `autonomy/lab-ai-rank-publisher-20261122`, HEAD `0904bc5c3703a37ddacacd502c7ca7a3f44fcbb0`; deliberately inserted the `reverse=False` regression **only on that lab branch**, not `dev`.
- **Worker: SUCCESS.** Qwen3.5 9B produced the expected correction and passed the focused RED→GREEN assertions. The no-network privileged publisher adversarial tests also passed.
- **Publisher: FAILED at GitHub POST `/pulls` with HTTP 403.** Earlier API calls successfully created the bot branch `bot/ai-rank-repair-0904bc5c3703`, commit `daaf342877024e4d14bc5456cbe23deddd0d9470`, containing exactly one Python line change. The 403 confirms a GitHub-token authorization blocker; whether caused by the repository's Actions PR-creation setting or another permission must be verified separately, not guessed.
- [Lab Draft PR #366](https://github.com/LMhdez/gaslux/pull/366) was created using the **connected maintainer GitHub integration**, *not* the workflow, to independently inspect the bot branch diff; it showed only `reverse=False` → `reverse=True`. It was then **CLOSED UNMERGED**. This does not demonstrate automated PR publication.
- The publisher pilot is updated to clean up its **own exact bot branch** after a failed PR API call, but only when the ref still points at the commit this job created. This new failure-path logic requires another exact-head CI run and Safety review.
- **Activation remains blocked** until the GitHub Actions PR-writing permission is resolved, full non-mocked publication succeeds in the isolated lab, and an independent Safety assessment approves the tokened job. No privileged publisher was merged into `dev`.

