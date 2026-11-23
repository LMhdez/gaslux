# GASLUX — independent GitHub Actions schedule fallback

**STATUS: DRAFT / NOT DEPLOYED / NOT ACTIVE / INDEPENDENT SAFETY PENDING.**

## Context
GitHub explicitly documents that scheduled workflow events may be delayed or dropped during high load; current 2026-11 community reports include hours-long gaps with successful manual dispatches. Gaslux #390 has four genuine `schedule` events at 00:58–01:08 UTC on 2026-11-23, then >5 hours without another event despite 15-/30-minute cron. GitHub internal cron repair cannot be guaranteed by changing YAML.

The optional Cloudflare Worker here uses **an independent timer** (`8,23,38,53 * * * *`, UTC). On each tick it reads GitHub's existing workflow run history, and **only** when the latest real `main` schedule/dispatch/workflow_run has completed more than **45 minutes** ago, it can dispatch the existing **read-only** `gaslux-agent-lifecycle-research.yml` workflow, with `mint_live_boot=false`. It does not modify GitHub repository files. It uses the workflow's existing `workflow_dispatch` input, not a parallel GitHub workflow.

## Hard security boundaries
- **Paused and dry-run by default:** `GASLUX_EXTERNAL_PAUSED=true`, `GASLUX_EXTERNAL_DISPATCH_ENABLED=false`, `GASLUX_EXTERNAL_PRIVILEGED_ENABLED=false`, `GASLUX_EXTERNAL_DRY_RUN=true`.
- No public HTTP trigger: all HTTP requests return 404.
- Fixed repository, fixed workflow allowlist, fixed `main` branch, fixed inputs. No user- or LLM-supplied workflow filename, branch, script, input or token.
- An unknown/bad SHA, non-main run, API error, missing identity or run still in progress **blocks** dispatch. A recently completed run also blocks duplicate dispatch.
- **Publishing, integration and code-generation workflows stay disabled in the external fallback by default.** Even if enabled separately, a previous failed generated-code run halts that fallback, rather than weakening the AST/Safety validator. A maximum of two dispatches per Worker tick is enforced.
- A GitHub fine-grained token limited to `LMhdez/gaslux` and **Actions: Read and Write** is required; store it only as the Worker secret `GITHUB_ACTIONS_DISPATCH_TOKEN`. Never put it in Git, PR comments, ChatGPT messages, logs or Action artifacts. Rotate after testing and limit its lifetime.
- Cloudflare pause is separate from the GitHub repository variable `GASLUX_AUTONOMY_PAUSED`; for emergency shutdown, pause **both**, cancel in-flight jobs, and disable the external Cron Trigger.
- A race between Cloudflare and GitHub can still produce a duplicate read-only run (no durable cross-provider lock). **Do not enable privileged external dispatch without an independently reviewed durable lease/idempotency mechanism.** This code does not prove a continuous 15-minute SLA.
- A fallback-created GitHub run has event `workflow_dispatch`, not `schedule`. The reporter and Issue #390 must distinguish them.

## Review and deployment, in that order
1. GASLUX-SAFETY independently reviews exact #389 HEAD: runtime and offline tests, permissions, fail-closed defaults, concurrency and secret confinement. Approve or request precise corrections.
2. GASLUX-INTEGRATOR verifies main branch rules and integrates #389 only after Safety and GitHub protections; the cloud fallback remains **paused**, irrespective of the merge.
3. Account owner provisions a **Cloudflare Workers** account and deploys from `ops/autonomy/fallback/` using `npx wrangler deploy`. Set GitHub's fine-grained token interactively with `npx wrangler secret put GITHUB_ACTIONS_DISPATCH_TOKEN`. Cloudflare deployment is external and cannot be performed with the current GitHub connector.
4. Operator changes Cloudflare Worker flags to `GASLUX_EXTERNAL_PAUSED=false`, `GASLUX_EXTERNAL_DISPATCH_ENABLED=true`, `GASLUX_EXTERNAL_PRIVILEGED_ENABLED=false` and retains `GASLUX_EXTERNAL_DRY_RUN=true`; redeploy and verify `WOULD_DISPATCH` logs, **zero GitHub POSTs**.
5. After read-only canary review, change `GASLUX_EXTERNAL_DRY_RUN=false`, redeploy and verify one legitimate **workflow_dispatch** run in the existing Lifecycle workflow, then a tick without a duplicate. Record GitHub run IDs and Cloudflare timestamps on [P0 Issue #390](https://github.com/LMhdez/gaslux/issues/390).
6. Keep the GitHub cron enabled. If its events resume, this fallback should see recent runs and remain idle. Escalate the missing native schedule events to [GitHub Support](https://support.github.com/contact) with run IDs and missed UTC slots.

## Tests
`node --test ops/autonomy/fallback/worker.test.mjs`

No external credentials or Cloudflare account needed for these tests.

**Non-goals:** full-size Windows/Mint Guest VM, installation, dual boot, production writers, data recovery, automatic stable promotion, and independent product acceptance are neither implemented nor authorized here.
