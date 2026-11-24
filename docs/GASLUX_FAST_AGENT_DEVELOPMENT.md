# Fast autonomous Gaslux development — GitHub Actions
The scheduler is GitHub-native; no ChatGPT tasks, external LLM API keys or artificial recurring prompts are needed.
- 15 minutes: existing Mint/Zorin low-risk feature coder (Qwen3.5 9B); duplicate task detection before inference.
- 15 minutes (offset): independent Integrator; also retries after successful producer/goal workflows.
- 15 minutes: six-backend feature-proposal factory selects one unclaimed role for a real backend source change. The model has **no GitHub write credentials**. A second runner validates exact evidence and pure-function behavior. A trusted publisher only creates a **Draft PR to dev**, never merges it.
- 30 minutes: research and existing backend contract tests for Mint, Zorin, CachyOS, Pop!_OS, Q4OS and Bazzite. Independent per-backend reports.
- Daily: official SHA-pinned Mint 22.3 live guest boot attempt in isolated QEMU (not an installation or dual-boot certification).
## Code authority
The new factory is confined to one allowlisted live backend module per task and appends one fail-closed, read-only lifecycle assessment helper. It cannot edit workflow YAML, boot managers, recovery scripts, storage writers, release manifests or GitHub protections. It validates every eight-gate lifecycle observation, rejects unproved install/release authority, pins the model digest and exact dev source SHA, and refuses a stale base before publication. The existing keyboard-only auto-merger **does not accept** feature-factory bot branch names.
A Draft PR is a proposed product modification, not verified installation. Full installer implementation across six distributions remains conditional on per-backend signed-media provenance, an isolated Windows/Linux VM lab with owned writable media, snapshot restoration and boot attestation, and independent Safety review before any protected write or main release. The first pass expands **actual source development**, not write authorization.
## Resource safeguards
The feature worker selects only an unclaimed role, deduplicated by role/source SHA and remote bot ref; otherwise inference is skipped. GitHub Actions serialization prevents overlapping downloads. Fixed model SHA, no model tokens in write jobs, limited output size, SHA-256 evidence binding, separate Safety gate and path/AST scope checks restrict AI proposals. More frequent schedules can consume Actions minutes and do not guarantee exact cron start times.

## Goal-driven discovery when safe coding scope is exhausted (Phase 1)

After all six previously approved read-only `assess_<backend>_lifecycle` helpers exist or are claimed, the Factory no longer reports a bare `idle`: its read-only selector also inspects the actual `dev:docs/autonomy/goal.json` matrix and `dev:docs/autonomy/evidence.json` and emits `blocked` with the next required gate per backend. This identifies outstanding objectives in the existing workflow's run log and Step Summary while leaving model, Safety and publication jobs skipped until a separately vetted, genuinely actionable code scope exists.

The selector treats an evidence record as **declared, not independently verified**. It cannot certify any installed guest, Windows return, dual boot, uninstall, rollback, or stable readiness. The matrix, supported platform combinations, gate order and safety split are validated against a conservative allowlist; malformed or unbounded data fails closed.

This first phase does **not** yet convert arbitrary gate gaps into autonomous Qwen coding or merge rights. That handoff requires a dedicated, independently reviewed task specification with exact target files, positive/negative acceptance tests, dependency and duplicate detection, and the relevant Safety/Windows/VM gates. The follow-on work is tracked in [issue #401](https://github.com/LMhdez/gaslux/issues/401). Existing PRs #395/#396/#398/#399/#400 need their own exact-HEAD CI and technical review rather than regenerated duplicate patches.

## Phase 2A — automatic task intake from real missing gates (pending Safety)

The existing Factory (no new schedule/workflow) is extended with a **separate,
main-only** `triage_missing_gates` job triggered only by the Phase 1
`status=blocked` selector. It reads the pinned current `dev` goal matrix and
the open PR / full bounded issue history via the GitHub API, refuses stale data,
and creates **at most one** review issue per run with the stable key
`backend/platform/gate`. An already open six-distro Qwen Draft is processed
first; existing backend issues win over automated duplicates.

The triage job requests only `issues:write` plus read-only contents and PR
metadata. There is no model download, editable source from `dev` execution,
GitHub App private key access or installation/boot authority. It runs trusted
`main` Python, interprets `dev` as data, and validates repository, exact
`main` ref, unpaused state, accepted event, current `dev` SHA and issue
identity before any write. It fails closed when the API, matrix, or bounded
dedup history is incomplete.

**An issue is a request for scope and acceptance tests, not an approved
programming task.** Issue states remain `NEEDS_SCOPE_REVIEW` until a backend
owner and independent GASLUX-SAFETY approve exact allowed source paths, test
fixtures, dependencies and protected-gate policy. The existing Qwen code
generator continues to accept only the previously reviewed AST-restricted
six-distro helpers; it is not expanded by task intake. This phase does not
implement generic automatic coding, installation, dual boot, uninstall or
recovery, and is not a successful GitHub App Draft-publication smoke test.

### F-403-01 and F-403-03: issue scope and GitHub App provenance

An issue number found in the untrusted `dev` goal matrix is **not** proof that
the issue covers the selected gate. Existing manual trackers #3, #71 and #254
are only accepted where a **trusted main-source canonical mapping** binds the
exact GitHub issue number, maintainer login, full title, backend, platform and
acceptance gate. The live GitHub issue must also be open, from this repository,
and must not be a pull request. A same-backend but unrelated owner-authored
issue, a forged user issue marker or a nonexistent issue ID cannot suppress
the legitimate backlog. This is a deduplication rule, not a declaration that
the linked issue satisfies an acceptance gate.

The original `github-actions[bot]` publisher and the new GitHub App have
different authenticated GitHub actor logins. The task-triage script accepts
only the exact legacy login, or **one explicitly configured App bot login** from
the trusted repository variable `GASLUX_PUBLISH_APP_BOT_LOGIN`, additionally
requiring `user.type=Bot` and same-repository head/base refs with the scoped
bot branch pattern. Configure that variable with the **actual GitHub App bot
login observed on an App-authored PR**, not the Client ID, arbitrary
`*[bot]` pattern, synthetic test value or unknown guessed slug. The installed
App bot's actual login has not yet been verified operationally.

If the triage sees an unrecognized Bot author on a same-repository scoped PR,
it fails closed without publishing a duplicate issue, while keeping the
absence of the trusted App login visible as an operational configuration
prerequisite. This does not require exposing an installation token or key,
and the model/publisher permissions are unchanged.
