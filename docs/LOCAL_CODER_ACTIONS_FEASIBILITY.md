# GitHub Actions local-coder feasibility and bounded automation (2026-11-22 UTC)

## Objective and verified evidence

This is an **experimental, no-paid-LLM-API, GitHub-hosted CPU worker**. It is not an unlimited programmer or a certified Gaslux installer. No Oracle or Raspberry Pi is required.

- Verified baseline at start: `dev` `8e68a475d6397ba8fef2e0f9f83758545e202a5f`.
- [Actions #45044956114](https://github.com/LMhdez/gaslux/actions/runs/45044956114), exact head `30b954110195349c0d09f42fc945a76a9b0b6336`: **SUCCESS**. Qwen2.5-Coder 1.5B and 3B each passed six expression cases. Local inference response took approximately **2.07 s** (1.5B) and **2.88 s** (3B); these are *not* end-to-end runner startup times or sustained throughput.
- [Actions #45045177815](https://github.com/LMhdez/gaslux/actions/runs/45045177815), exact head `6ca8f3c92858cd3bc100bc01606c455db3b74659`: **SUCCESS**, 3/3 jobs. The 3B model repaired a deliberately mutated `ranked_changes` function extracted from `auto_tests/tools/rank_capture_changes.py` **on the first attempt**; the injected failure was reproduced before repair (RED), and isolated regression checks passed after repair (GREEN). Its measured in-process repair cycle was **6.616 s**, excluding model download and runner setup.
- The real source was not defective in this benchmark; these results **do not demonstrate detecting or fixing a live CI regression**. Model-generated code was not committed or pushed.
- First run [#45044622336](https://github.com/LMhdez/gaslux/actions/runs/45044622336) failed from benchmark-validator defects, not incorrect math: one fenced answer and an omitted `ast.Pow` node. The benchmark was corrected and rerun.

## Added narrow operational design

`.github/workflows/research-local-coder-smoke.yml` performs read-only comparison and a controlled regression benchmark.

`.github/workflows/gaslux-local-coder.yml` is a separate **proof-of-concept** for real test-failure detection and a candidate Draft PR. Its initial allowlist is intentionally only `auto_tests/app/logging_config.py`, checked by `auto_tests/tests/test_logging_config.py`.

1. The *read-only-worker* uses the 3B model without a write token. It first checks the existing test. On PR events it deliberately injects a temporary logging regression **into the disposable checkout only**; it must demonstrate RED then model-generated GREEN. On trusted `dev` push, dispatch, or eligible schedule it runs in real mode, and **does nothing if the focused test is already green**.
2. It stops after two attempts, limits model response size/diff and checks AST/imports. The short-lived artifact records the original SHA-256, source path, tests and candidate digest. These guards are task-specific and are not a general sandbox.
3. A separate *draft-pr-publisher* job can receive `contents: write` and `pull-requests: write` **only on non-PR events and only when the worker produces a test-passing candidate**. It never executes model-generated source. It rechecks the live `dev` file SHA-256 and path, rejects stale proposals and duplicate branch names, and creates at most one **Draft** PR. There is **no auto-merge or stable promotion**.
4. On PRs, publication is disabled. Disk/boot/ESP/BCD/firmware/recovery files remain entirely excluded.

## Activation and safety gates

- The new workflow is in **Draft PR #363**, not `dev` or `main`, until appropriately reviewed and integrated. Thus scheduled operation is **not active**. GitHub scheduled workflows run only on the repository default branch (`main`), not `dev`. A `dev` push-based worker is possible only after the workflow has been vetted and merged into `dev`.
- Github repository settings must permit Actions to create pull requests for the `GITHUB_TOKEN` Draft-PR publisher to work. This setting was **not verified**. Generated PRs may also require approval for downstream workflow execution.
- The experimental worker currently downloads Ollama through an **unversioned remote install script**, and dependencies and model blobs are not yet reproducibly pinned. Its safety comes in part from isolation and the absence of write credentials in the worker; **do not enable privileged unattended production runs before pinning and verification**.
- The pilot validates a single focused regression; arbitrary issues, GitHub CI failure selection, broad fixes, repo-wide tests, secure execution of arbitrary model code, prompt-injection resistance, model independence and continuous 24/7 availability remain **unproved**.
- Do not merge into `main`, publish releases, alter the stable distro catalog or run on physical disks based on this research. Safety and normal Gaslux project integration gates still apply.
- The hosted compute is subject to GitHub's terms, resource and scheduling limits. Nothing here grants unlimited free inference or service-level uptime.

This PR remains entirely separate from the Mint/WPF integration and recovery proof in Draft PR #361.
