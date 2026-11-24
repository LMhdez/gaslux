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

## Phase 2B pilot — reviewed issue to real read-only code (Safety pending)

The existing six-distro Factory model/Safety/PR pipeline can now select a
**separately reviewed, trusted-main code scope** after its six original helper
tasks are exhausted. Phase 2B initially proposes just one bounded product
improvement, tied to [Mint task #404](https://github.com/LMhdez/gaslux/issues/404):
`mint-iso-pins-v1` for `mint/windows10-bios-mbr/source-authenticity`.

This scope appends exactly one pure, read-only function
`match_mint_223_iso_descriptor(candidate: dict) -> dict` to the existing
`assets/live/gaslux_distribution_capabilities.py` product source. Its only
positive result, `pinnedDescriptorMatches`, requires the **exact four** existing
Mint 22.3 release descriptor fields: identity, official ISO URL, ISO SHA-256
string and expected byte size. The other three flags,
`sourceAuthenticityVerified`, `installationAuthorized` and
`releaseEligible`, must stay **False even for exact matches**. Pin comparison
cannot prove that media bytes were downloaded, hashed, or authenticated by a
trusted upstream signer; it never satisfies a lifecycle gate by itself.

The selector authenticates the issue number, repository, original
`github-actions[bot]` author, canonical title and exact backend/platform/gate
marker via the GitHub API; checks that live `dev` release-config pins match the
trusted `main` allowlist; and rejects already-implemented functions, stale
bases and an existing scoped bot branch. Neither editable issue content nor
`dev` JSON authorizes arbitrary new Python code.

The model's exact Qwen 3.5 9B digest is unchanged. The new code must pass the
existing restricted AST, additional adversarial behavior fixtures, SHA-256
evidence binding, the relevant real backend regression suite, and a separate
tokenless independent Safety job. The trusted publisher executes **no model
code** and uses the existing `gaslux-main-publisher` Environment/App token to
create **Draft PRs to `dev` only**, with no auto-merge. On forward-only
`dev` advancement, both the product source and test bytes must remain
identical and the pinned ISO metadata must still match. The emergency pause
and all existing GitHub protections remain effective.

This is a **proposed code scope**, not an already approved implementation.
It must undergo independent GASLUX-SAFETY review at an exact PR HEAD before
merging to trusted `main`; the issue's initial `NEEDS_SCOPE_REVIEW` state
alone never authorizes the model. The backend PR subsequently generated by
Qwen requires its own CI, backend owner review and independent Safety.
No installer writes, Windows ESP/BCD/WinRE, physical disk tests or stable
promotion are introduced. General multi-task coding beyond this specific
reviewed scope remains separate future work under #401.

## Phase 2C — full six-distro acceptance inventory (read-only)

After the first **real** Qwen → AST → Safety → GitHub App Draft pipeline
([Mint #407](https://github.com/LMhdez/gaslux/pull/407), merged to `dev`
following independent exact-HEAD Safety and CI), the remaining objective is
**not** completed: all six backends must pass actual, independently observed
Windows/Linux VM lifecycle acceptance gates before any release can be promoted.

The existing Factory selector now enumerates the bounded goal matrix into
**136 exact backend/platform/gate slots**: five backends × three Windows
platforms and Bazzite × two supported UEFI/GPT platforms, each with eight
gates. Of these, **34** concern the `source-authenticity` /
`windows-preflight` class requiring separately reviewed coding and evidence
scopes; **102** concern protected install, boot, update, Windows return,
uninstall or recovery evidence that cannot be promoted without an isolated,
disposable VM lab and independent Safety review.

The `work_items` snapshot is derived from the current `dev` goal/evidence
files under the trusted `main` allowlist. Each item records backend,
platform, gate, ordered gate dependencies, a static existing source/test
candidate, evidence declaration state and explicit `code_authorized=false`,
`installation_authorized=false`, `release_eligible=false`. Even an evidence
record claiming success is `declared_unverified`, **never** independently
accepted. The six historical `next_gates` are preserved for the existing
safe issue-triage/dedup job; no new generic Qwen execution scope is granted.

On `status=blocked` the **existing** Factory workflow uploads the bounded
`gaslux-six-backend-gate-backlog` JSON artifact and publishes counts in the
GitHub Step Summary. The snapshot is a planning/evidence-inspection input,
**not** a write token, immutable code authorization, signed ISO proof, or
installation certificate. The scheduler, independent Safety chain and
publisher are unchanged; existing lifecycle research keeps running separately.

Next required work under [#401](https://github.com/LMhdez/gaslux/issues/401):
approve genuinely actionable, narrow source/test scopes for other distros
without relaxing AST; obtain authentic ISO provenance **from upstream evidence**
rather than mere metadata equality; provision an authorized Windows test image
and isolated QEMU/OVMF **disposable** guest disks/snapshots; attest actual guest
observations; and test installation, dual boot, update/reboot, Windows return,
uninstall, fault injection and rollback per supported backend/platform.
None may write to physical disks or promote stable from an unverified report.
