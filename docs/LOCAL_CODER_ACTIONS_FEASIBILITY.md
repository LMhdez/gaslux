# GitHub Actions local-coder feasibility and bounded repairs (2026-11-22 UTC)

## Verified experimental evidence

Repo: `LMhdez/gaslux`. Baseline at research start: `dev` `8e68a475d6397ba8fef2e0f9f83758545e202a5f`.

1. [Actions #45044956114](https://github.com/LMhdez/gaslux/actions/runs/45044956114), code HEAD `30b954110195349c0d09f42fc945a76a9b0b6336`: **SUCCESS**. Ollama Qwen2.5-Coder 1.5B and 3B independently passed six deterministic expression checks. Inference time was approximately 2.07 seconds (1.5B), 2.88 seconds (3B); not full CI startup times.
2. [Actions #45045177815](https://github.com/LMhdez/gaslux/actions/runs/45045177815), code HEAD `6ca8f3c92858cd3bc100bc01606c455db3b74659`: **SUCCESS**. The local 3B model repaired a deliberately mutated in-memory copy of the actual Gaslux utility `rank_capture_changes.py` in one attempt. RED/isolated GREEN; 6.616 seconds local repair cycle, excluding setup. The real repo module itself was not defective.
3. [Actions #45045568126](https://github.com/LMhdez/gaslux/actions/runs/45045568126) and [#45045926549](https://github.com/LMhdez/gaslux/actions/runs/45045926549): **FAIL**. Attempts to repair a deliberately missing `handler.close()` in a disposable copy of the actual logging module produced extraneous code (3B) or attempted to close the wrong handler (3B), rejected by test/AST guards.
4. [Actions #45046288165](https://github.com/LMhdez/gaslux/actions/runs/45046288165) and [#45046635949](https://github.com/LMhdez/gaslux/actions/runs/45046635949): **FAIL**. 3B and 7B respectively proposed incorrect log handler operations. The publisher was skipped and no bad code published.
5. [Actions #45046883051](https://github.com/LMhdez/gaslux/actions/runs/45046883051), code HEAD `e4b33bdcb639e103859dd89fc43cba1371f69356`: **SUCCESS**, RED then GREEN using one explicitly labeled **deterministic** missing-close correction. `attempts=[]`, repair cycle 0.646 seconds, with unnecessary Ollama downloads still present in that workflow revision.
6. [Actions #45047071724](https://github.com/LMhdez/gaslux/actions/runs/45047071724), code HEAD `a9cf98c723f8e8584470fb223f27cae1671ddb18`: **SUCCESS**. The bounded repair workflow no longer downloads any AI model; isolated test RED then deterministic GREEN passed, credentialed Draft PR publisher correctly skipped on `pull_request` event.

## Scope of proposed automation

`.github/workflows/research-local-coder-smoke.yml` retains the **read-only local AI research** (1.5B/3B plus isolated 3B mutated-function benchmark) without paid inference APIs.

`.github/workflows/gaslux-local-coder.yml` is now a separate **bounded deterministic regression-repair proposal** on one narrow file (`auto_tests/app/logging_config.py`), tested with existing `auto_tests/tests/test_logging_config.py`. It is **not** an AI coder and must not be presented as one.

- On PR events, it injects a missing-close fault **only into its disposable runner checkout**, proves RED, inserts a strictly allowlisted `handler.close()`, checks GREEN, restores original source, uploads evidence, and **does not publish a PR**.
- On eligible trusted `dev` pushes or dispatch/schedule once deployed, the worker checks the actual focused test. If green: idle with no patch. If RED and matches exactly one known missing-close pattern: only that insertion is allowed, with test GREEN and source/content SHA-256 evidence. Other regressions stop with `unsupported_regression`.
- The unprivileged worker has `contents:read` only, checkout credentials are not persisted. The separately credentialed publisher receives an artifact only in non-PR events after passing focused tests. It checks evidence, exact current file hash, exact **single-line insertion**, duplicate agent branch, and creates at most one **Draft** PR if repository settings allow it. It never executes candidate code while holding a write token.
- No auto-merge, stable catalog promotion, disk, BCD/ESP/firmware, recovery, physical disk writes or unrelated source changes.

## Limitations and activation blockers

- This remains **Draft PR #363** targeting `dev`; no reviewed integration or autonomous recurring service is active.
- GitHub `schedule` triggers only from the **default branch (`main`)**; merging to `dev` alone would not activate the schedule. Push/path events on `dev` would be possible only after the workflow is integrated there.
- A real existing failure on `dev` resulting in automatic Draft PR creation has **not** been demonstrated. Repo setting permitting `GITHUB_TOKEN` to create PRs is unverified. Workflow publisher is security-sensitive and needs independent review and exact-head integration CI.
- Python test dependencies are not hash-locked. AI research workflow still uses an unpinned upstream Ollama install script; its output must never automatically acquire write credentials or installation authority.
- The tested 3B/7B models did not demonstrate reliable repair of the logging regression. General CI diagnosis, arbitrary Python patch generation, rapid autonomous complex development, multiagent concurrency, sustained 24/7 availability and unlimited free compute are **not established**. Hosted Actions remain subject to GitHub limits, resource policies and availability.
- No Windows-to-Mint installation, dual boot, recovery, uninstall or release proof results from this research; Draft PR #361 remains separate.

Review `AGENTS.md`, `AI_POLICY.md`, and the current exact SHA/CI before any integration or expansion.
