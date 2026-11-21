# Observer GPT IMMEDIATE — BLOCKED pending protected external controller

**Current security verdict:** [GASLUX-SAFETY #273 review](https://github.com/LMhdez/gaslux/pull/273#pullrequestreview-6005022413) = **BLOCKED_PENDING_FIX**. The earlier technical approval on [PR #272](https://github.com/LMhdez/gaslux/pull/272#pullrequestreview-6004845263) was LIMITED to a future one-time synthetic read-only QEMU exercise, subject to separate human approval. Neither review authorizes QEMU now.

## Vulnerability and mandatory correction

The original branch-controlled authorization in #273 checked only that the
final approval commit parent descended from the audited GPT source SHA. The
last commit could add only the JSON while **unreviewed intervening commits**
modified the workflow, Python preflight or both. Safety reproduced all three
bypasses on real temporary Git histories (3/3 accepted by the old logic).
The requesting branch also controlled the workflow and guard code. Checking
the producer source SHA alone does not make its execution controller trusted.

The corrected `validate_git` no longer uses `git merge-base --is-ancestor`.
It requires ALL of the following separately supplied by the trusted controller:

- **Exact** approved preparation commit SHA; `event.before` and `git HEAD^`
  must both equal it, byte-for-byte.
- **Exact** approved authorization commit SHA; `event.after` and `git HEAD`
  must both equal it, byte-for-byte.
- Actual final Git diff must be exclusively one addition of the permitted
  approval JSON, even when the event claims otherwise.
- A **verified and atomically consumed external one-shot grant**, reported
  to the method only by the trusted controller after consumption. A Boolean
  is a caller assertion, NOT itself a durable ledger. Missing or already-used
  grant => refusal.

These values must NOT be taken from the requester JSON, untrusted workflow
inputs, mutable variables, or files controlled by the authorization branch.
The current branch-level CLI **never accepts these inputs** and calls the
validator without them; it always refuses before any QEMU launch.

## Resolution of the trust boundary: protected default-branch controller

The chosen target is option A: a **reviewed and protected `main` workflow**
triggered via `workflow_dispatch`, using a GitHub **Environment** with
independent required reviewers and branch restrictions, plus an external
durable once-ever authorization ledger. The workflow itself and the actual
Python guard must come from the protected `main` code, not from any
authorization-requesting branch or the JSON it contains.

Current proof of feasibility stops at source-level tests. The repository's
default branch is `main`, and the existing GPT producer workflow is NOT
present there. Branch protection, Environment reviewers, deployment-branch
restriction, independent preparation/authorization pins and durable atomic
single-use ledger have NOT been confirmed configured or operational.
Consequently there is **no currently deployable trusted controller**.

A non-executable design scaffold lives in
`docs/INSTALLER_OBSERVER_GPT_PROTECTED_CONTROLLER.template.yml`. It is
outside `.github/workflows/`, remains hard-disabled (`if: false`) and
contains no QEMU command. GASLUX-INTEGRATOR must integrate and configure it,
subject to human review, rather than moving branch-controlled QEMU code into
the trusted workflow without verification.

The old `.github/workflows/observer-gpt-qemu-one-shot.yml` is replaced on
the correction branch by a deliberately inert `workflow_dispatch` job
with `if: false` and no QEMU/libguestfs. Because it is absent from
`main`, it also cannot be dispatched normally. There is **no trigger**
on `qemu-approved/...` or file addition. The branch
`qemu-approved/observer-gpt-dd3e7bf2-20261121` and its JSON must NOT
be created. The original unmerged #273 still contains the old workflow:
this fix only becomes protective operationally when the corrected branch
replaces it under reviewed integration and/or an administrative rule
disables that old route. A branch in a draft PR cannot revoke an older
untrusted workflow elsewhere in the repository.

## Reproducible synthetic gates (NO QEMU)

The new tests import actual `validate_trigger` / `validate_git` and use
real disposable local Git repositories. They reproduce the exact three
attacks (intermediate workflow, preflight, both), plus modified final diff,
forged `event.before`, unapproved authorization SHA, missing external
preparation anchor, JSON-supplied fake anchor, missing/consumed grant and
rerun. The positive case is purely synthetic and supplies independent
**test-only** pins; it does not establish a working production trust root.
Every rejected case must fail before a QEMU-capable step could run; the
branch-local workflow has no such step at all.

The production GPT producer is unchanged at audited commit
`dd3e7bf26e36499f89701393773df464ce713e4f`, Safety unchanged at
`0be04192acd542646a5b6cd952e01620379edf5d`. Historical laboratory
scope remains 64 MiB disposable GPT, 512-byte sectors, read-only
libguestfs/KVM, fresh post-QEMU IMMEDIATE export, no selected physical disks
and no Windows image. No new QEMU execution is performed in this correction.

Future trusted runtime, once independently reviewed and enabled, must check
original GPT primary/secondary headers, CRC32, SHA-256, GUID/PARTUUID, exact
geometry, overlay and backing chain, distinct HOST/GUEST/IMMEDIATE acquisitions
and Safety v1. It may publish only JSON/text evidence, no QCOW2, Windows
images or keys. Even that evidence remains `NOT_INDEPENDENT` and
`DIAGNOSTIC_ONLY`.

Mandatory flags remain `inputAuthorized=false`,
`diskWritesAuthorized=false`, `productionInstallationAuthorized=false`
and `productionWriteAuthorized=false`. No hardware identity, independent
administrative attestation, real Windows dual boot, rollback, recovery or
production write authorization follows from these synthetic contracts.

## External integration blockers

GASLUX-INTEGRATOR must obtain human review for the final preparation/approval
SHAs, integrate an independently protected main-workflow/controller, confirm
branch protection and required Environment reviewers with protection against
reviewer self-approval, and supply a real external durable atomic one-use
grant mechanism. A GitHub actor, JSON `humanApproved=true`,
`run_attempt=1`, or `concurrency.cancel-in-progress=false` does **not**
implement that grant; deleting and recreating a branch can otherwise reuse
authorization. The controlled workflow must not execute checked-out code from
the requesting branch. Until EVERY dependency is operational and independently
reaudited by GASLUX-SAFETY, QEMU remains **BLOCKED**, including requests for
human permission to run it.
