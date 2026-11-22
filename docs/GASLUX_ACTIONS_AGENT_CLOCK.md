# GASLUX — GitHub Actions native scheduler and specialist agent runtime

## Operational design, 2026-11-22 UTC

The **main/default branch** owns the clock workflow `.github/workflows/gaslux-agent-clock.yml`: `schedule` at minute 37 each hour, plus manually invoked `workflow_dispatch`. It runs on GitHub-hosted runners, not ChatGPT tasks. `dev` provides the reusable `gaslux-agent-builder.yml` implementation worker. A missing-feature selector chooses at most **one** eligible, curated product task per run. New model inference is skipped when all tasks are done or a candidate branch already exists for the same dev SHA.

The initial two approved tasks are genuine product features in the shared `Installation/WindowsKeyboardLayout.cs`: missing Portuguese (Portugal) `00000816` → `pt` and Brazilian Portuguese `00000416` → `br`. They are intentionally low-risk code changes. Other specialist backend roles (CachyOS, Pop!_OS, Q4OS, Bazzite) are registered but cannot write or create tasks until separately reviewed scope/acceptance tests exist.

## Github Actions job boundaries

1. **Supervisor:** checkout `dev` read-only, run offline tests, identify a missing real feature, deduplicate bot ref. Does not download the model if no work.
2. **Backend developer:** separate Ubuntu job, reusable `@dev` workflow, downloaded SHA-256 checked Ollama and Qwen3.5 9B model. No `GITHUB_TOKEN` passed to the local model, no persisted git credentials. Model proposes exactly one C# mapping line. Reads only the task and bounded source context and produces candidate + report artifact.
3. **Safety:** separate unprivileged runner, loads validation code **from exact `main` commit**, separately fetches live `dev` ref and source content, independently verifies SHA-256, model identity, mission, syntax and byte-exact one-line edit. No generated code executed while holding GitHub write credentials.
4. **Windows WPF acceptance:** separate `windows-2022` runner builds and tests the C# product candidate in a disposable checkout, never a user's Windows drive.
5. **Integrator publisher:** short-lived final job, least-needed `contents:write` and `pull-requests:write`, trusted code from `main`, live `dev` SHA revalidation, exactly one allowlisted C# mapping insertion, temporary branch per task/SHA and **Draft PR only**. No merges or release promotions.

*Security distinction:* successful GitHub Actions tests and automated Draft publication do not constitute independently certified code or verified Windows/Mint installation. GitHub workflows started by a `GITHUB_TOKEN`-created PR may not run automatically; manual/reviewed integration into `dev` remains a separate gate. No API credits, Oracle or Proxmox required, but GitHub Actions minutes/storage/fair-use quotas apply and hourly scheduling is not a hard real-time guarantee.

## Branch ownership

- The scheduled entrypoint must be merged to **`main`** to execute regularly; `schedule` defined only on `dev` does not run. The first merge of this workflow to main also triggers a one-time `push` execution for immediate, observable functional validation.
- The reusable model worker, curated tasks and adversarial tests **were merged into `dev`** as PR #370 (commit `aad7fdb96973a8b8333255778160612ba00764c3`) and the post-merge task-idle regression test fix PR #372 (commit `66c4bb77cdaa8ce5d2c52a34d2fb859742f655cc`). The `main` scheduler references `@dev` and cannot run the builder before that workflow exists there.
- The current `main` bootstrap-only workflow is left untouched. The existing Draft PR #362 is a separate read-only monitor, not this programming-agent scheduler.
- No production installer C# logic is altered by merging this orchestration workflow alone; the protected `main` stable catalog is untouched.
- Auto-merging model PRs, opening writer access to disk/ESP/BCD/WinRE, promoting `main`, or declaring the 136 release acceptance gates complete is not authorized.

## Validation

`python3 -B -m unittest discover -s auto_tests/tests -p test_gaslux_agent_trusted_publish.py -v` runs on the workflow PR itself. The worker has a second offline suite `test_gaslux_agent_implement.py`. A live scheduled run is the final operational acceptance gate: selected role, pinned model, genuine product candidate, independent Safety and Windows build, successful bot-created Draft PR. Until a successful run exists, that end-to-end behavior is **not yet demonstrated**.

Generated-by: GPT-6.


## Windows acceptance across partial GitHub Actions retries — 2026-11-22 UTC

[First main Actions run #45058019123](https://github.com/LMhdez/gaslux/actions/runs/45058019123) chose real Mint keyboard support. In the first attempt the 9B model missed C# punctuation and failed closed. The safe normalization was merged to `dev` via [PR #373](https://github.com/LMhdez/gaslux/pull/373), commit `55a70a90bdde29d0d41d4592de205013ee61bc16`. A **failed-jobs-only rerun** then succeeded in generating real product code and passed independent Safety review, but the Windows acceptance step failed before compilation with `Artifact/source identity mismatch`: the retained Supervisor output referred to old dev SHA `66c4bb77cdaa8ce5d2c52a34d2fb859742f655cc`, while the rerun developer artifact had used updated SHA `55a70a90bdde29d0d41d4592de205013ee61bc16`. No code or PR was published.

This change keeps the fail-closed identity checks and makes Windows acceptance bind to the *actual independently Safety-reviewed worker artifact's source commit*, even on partial failed-job re-runs. The report SHA is validated as 40 lowercase hex, the original source is checked out by that exact commit, and the committed Git blob plus candidate bytes are hashed against the report before compiling the Windows .NET Framework 4.8 installer. The artifact downloads to `RUNNER_TEMP` outside the checkout workspace so checkout cleaning cannot remove it. If dev subsequently advances, the trusted publisher must still deny stale source, preventing stale Draft PRs.

**Status:** change requires exact-head tests, fresh main workflow execution and successful downstream Windows build before claiming the product agent published a Draft PR. The full Windows+Mint installation/boot/uninstall/rollback remains unverified.
