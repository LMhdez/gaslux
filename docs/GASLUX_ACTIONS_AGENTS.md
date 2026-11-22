# Gaslux — GitHub Actions specialist programming agents

**Pilot decision:** 2026-11-22 UTC. Runtime: GitHub-hosted Ubuntu with pinned local Qwen3.5 9B; no ChatGPT scheduled task, paid inference API, Oracle, Proxmox or physical disk access.

## Execution topology

`main` (default branch) must own the **scheduled Supervisor workflow**. It will read `dev` at execution time, choose one curated *actual product feature gap*, call a `dev` reusable **Backend agent workflow** on a separate ephemeral runner, invoke independent **Safety** checks and, if admissible, a separate **Integrator publisher** running immutable trusted code from `main` with the minimal GitHub token permissions. The agent roles are `mint`, `zorin`, `cachyos`, `popos`, `q4os`, `bazzite`, `safety`, `integrator` and `supervisor`. A role is an execution contract, **not** a new continuously running paid model or a claim of independent review.

`dev` holds `.github/workflows/gaslux-agent-builder.yml`, a `workflow_call` reusable role worker. It takes role input, proves a task is missing in a real product source file, downloads verified Ollama Qwen3.5 9B *only when work exists*, emits one candidate source file and a SHA-256/report artifact, and cannot write to the repo. Pull-request events run adversarial unit tests only, never inference.

## First real implementation work

The initial bounded feature queue is `docs/autonomy/agent_missions.json`, starting with missing Windows keyboard layout support in the actual WPF installer helper `Installation/WindowsKeyboardLayout.cs`:

- MINT-PT-KEYBOARD-01: Windows Portuguese (Portugal) input identifier `00000816` → Linux XKB `pt`.
- ZORIN-BR-KEYBOARD-01: Windows Portuguese (Brazil) identifier `00000416` → XKB `br`.

Both are **genuinely absent** from the baseline source. The first model generates a real C# dictionary entry; strict validation prevents unrelated edits, method invocations, arbitrary paths, or production installation/disk changes. The reusable worker does not seed a fake defect. Model output passing static acceptance is only a candidate; independent Windows C# build/test and Draft PR review are later gates.

Other distribution roles exist in the manifest but are **not supplied product editing authority or tasks yet**. Extending to C#, Python, PowerShell or shell changes in other modules requires a reviewed mission, independent tests and bounded writeset, never a model-provided shell command.

## Default-branch and integration boundary

GitHub `schedule` events only run workflows defined on the default `main` branch. A worker added to `dev` **does not automatically schedule itself**. The paired main scheduler must be merged separately, with `workflow_call` to the worker on `dev`. Until both merges succeed, the pilot does not run periodically.

The trusted publisher must independently re-fetch `dev` head and source content, verify artifact SHA-256, file allowlist, exact one-line insertion, model digest and role, then create **Draft PR only**. It does not execute model-generated code with a token, merge its own PR, release anything, write installer disks, or grant Safety approval. Failure or stale head is a bounded no-op, not permission to retry untrusted operations indefinitely.

`AGENTS.md` and `AI_POLICY.md` still govern risk-based independent review and *delegated* vetted merges into `dev`. No autonomous high-risk merge, `main` release promotion, Windows ESP/BCD/WinRE write or 136 acceptance-gate completion is asserted. If the task queue is exhausted, the scheduler produces an idle report instead of inventing code requirements.

## Evidence required

1. Offline exact-head CI tests validate task selection, missing-feature detection, distinct roles, safe one-line output and rejection of model-generated side effects.
2. Real local-model workflow run demonstrates that a genuine missing feature produces a candidate from a Linux runner, not a planted regression.
3. Separate Safety validation on a runner without write credentials checks the candidate, with Windows .NET Framework WPF compilation where available.
4. The trusted publisher publishes a Draft PR; exact base/ref check, deduplication, permissions and rate limits are tested.
5. Only a vetted, independently reviewed PR may merge into `dev`. The supervisor loops to the next task on the following schedule.

This pilot is an incremental product implementation workflow, **not a general-purpose self-developing agent already proven to build Gaslux end-to-end**. Windows + Mint real guest installation and rollback remain separate, unproven acceptance gates.

## First native scheduler execution — 2026-11-22 UTC

[Action #45058019123](https://github.com/LMhdez/gaslux/actions/runs/45058019123), main SHA `055e825c74e23740126155f824062965e25db080`, **FAILED CLOSED** in the model implementation job. The Supervisor actually chose a missing Mint Portuguese keyboard mapping on dev `66c4bb77cdaa8ce5d2c52a34d2fb859742f655cc`. Ollama and the pinned Qwen3.5 9B model installed successfully. The local model produced a malformed first answer, then a semantically correct mapping `{ "00000816", Mapping("pt") }` missing its C# dictionary comma. Strict validation rejected both; no code was published and Safety/Windows/publisher jobs were correctly skipped. The bounded correction accepts **only** an absent terminal comma on an otherwise exactly allowlisted mapping; no broader code authority is granted. New negative tests reject multiline/side-effect outputs. This is a real product feature task, not a seeded regression or proof of Linux installation.
