# App-sourced gate migration — staged production adapter

## Evidence
Isolated repository gaslux-merge-lab PR #2 merged as ad479c4d810d55ae0bbafba56775de876b61ebd6.
Ruleset 28171885 enforced CI (15368), Safety (5938492) and Owner (5938509) with no bypass.
Runs 45843634131, 45843746011, 45843855938 and 45843979208 rejected pending, missing owner approval, wrong issuer, and revoked Safety respectively. Run 45844106529 confirmed the exact tree, parent and closure.

## Production phase 1
Read-only audit even during pause, separate status-capable identities, exact receipt join and canonical inspection.
Existing reviews and VM gates remain mandatory; no automatic semantic approval of arbitrary dynamic/multifile functionality.
Publishers require explicit opt-in and explicit unpause. Status contexts gaslux-dev/safety-v1 and gaslux-dev/owner-v1 are not required production rules yet.
No new merge endpoint, ruleset write, branch protection relaxation, stable authority or secret changes.

## Before activation
Independent Safety review of this exact PR; prove trust of main and workflow environment restrictions.
Resolve target confinement: REST merge pins HEAD but not target ref/base atomically; isolated lab does not prove production confinement. Keep production merge paused.
Verify production App IDs and expand ONLY their commit-status permission after approval; use distinct source-pinned rules and preserve CI, conversation resolution, deletion/non-fast-forward protections.
Do not replace the native review count until independent gate equivalence and server enforcement have been reviewed and approved. Test negative and positive cases in a bounded production pilot, including retarget and base advancement, with real functional evidence and VM requirements.
Do not enable the migration flag or clear the pause merely because this PR is green.
Historical PR reconciliation requires exact ancestry or complete-tree equivalence, no unresolved discussion, and head/target revalidation. Existing paused automatic closure is not enabled by this change.
