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
