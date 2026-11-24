# Distro admission (read-only stage)

The existing Integrator schedule gains a read-only job for PRs #395, #400,
#411, #412 and #413. No new schedule, privileged job or merge allowlist.
The job uses main source and only GitHub API GET requests; candidate code
is parsed with the existing Factory AST validator, never executed.

The independent Safety identity must be provisioned separately by an
administrator using repository variable GASLUX_SAFETY_REVIEWER_ID (numeric
GitHub user ID of an independently controlled reviewer, not a shared author
or publisher identity). An actual GitHub APPROVED review must be bound to
the HEAD via commit_id and include an exact line:

    GASLUX-SAFETY-V1 head=<40-hex-head> base=<40-hex-current-dev>

No text-only comment, label, self-review, stale/dismissed review or missing
identity is accepted. A technical objection, incomplete response or drift
blocks the relevant gate. A stale base must be regenerated/re-reviewed.
A reviewer ID is not proof of institutional independence; it must be
configured outside the developer's control. No reviewer is assumed.

Normal CI requires the observed named GitHub Actions checks on the exact
HEAD, with successful conclusions; missing, skipped or incomplete checks
cannot pass. The current backend-owner and full Windows/Linux VM acceptance
gates have no authenticated evidence transport, so they remain false.
Every report has merge_authorized=false and release_eligible=false.
This is an admission observation stage, not a grant of merge authority.
The existing keyboard Integrator and all existing Safety contracts remain
unchanged. A separate independently reviewed change must authenticate the
remaining gates and enforce branch protection before any distro merge.

## Ruff-repair history (2026-11-24)

The five current candidates (#395/#400/#411/#412/#413) contain two commits:
original bot append plus a maintainer formatting repair. The original check
mistook the repair's immediate parent for the original dev base, and rejected
Ruff's additional blank line. The read-only admission now checks bounded
one- or two-commit linear ancestry, compares each commit's file scope,
verifies the branch suffix against the original base, validates both appends
with the unchanged AST validator (never executes), and requires AST identity
for the formatting repair. The repaired commit's authenticated author cannot
be the Safety reviewer. More than two commits, off-scope intermediates,
changed semantics, unknown repair identity and noncanonical append fail closed.
Historical original bases remain stale; exact-current-base, exact-HEAD CI,
independent Safety, owner/VM evidence and no-merge/no-release invariants remain.
No candidate is approved by this change. Independent review and CI required.

### Whole-inspection regression (2026-11-24)

The exact candidate base-to-HEAD comparisons were inspected via GitHub for
#395, #400, #411, #412 and #413: each reported two commits and one modified
allowlisted source file, +20/-0 lines, with the original source prefix
preserved and the expected formatted helper appended. This is static source
inspection, not an independent Safety approval or VM acceptance.

The contract suite now exercises the complete read-only inspection path for
a representative two-commit candidate, mocking only GitHub API transport
and running the real AST validator without executing candidate code. It
covers a valid structural candidate, absent approval, repair-author review,
stale base, concurrent HEAD drift and an off-scope intermediate commit.
Even the valid fixture must report blocked, with owner and VM evidence,
merge and release authorization false. This is an offline regression; live
scheduled admission and independent review remain separate gates.
