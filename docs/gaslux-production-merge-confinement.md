# Production merge activation — fail-closed target confinement

This change adds a separate default-deny GASLUX_PRODUCTION_MERGE_ENABLED flag.
It does not unpause development, grant semantic approval or configure rules.
Both existing merge entry points require the flag, explicit unpause, trusted
main checkout, existing exact review/CI/base checks, and live server policy.

Before enabling the merge flag, independently review and test a dedicated
server ruleset covering all branch refs (~ALL), excluding exactly refs/heads/dev,
with Restrict updates. The actual Integrator credential must report
current_user_can_bypass=never. Other actors may need scoped exceptions to
maintain publisher branches and main; do not grant the Integrator bypass.
Check the effect on the actual publisher and all existing automation in a
disposable repository first. Do not apply a blanket rule blindly.

Main must have no bypass, required PR, deletion/force-push prevention,
strict source-pinned required CI, at least one independent approval, stale
approval dismissal, last-push approval and conversation resolution. Choose
a required CI job that runs on every main PR; avoid path-filter deadlocks.

The existing dev policy and named-role review gate remain mandatory.
App-sourced status migration remains staged; no generic review count
substitution or arbitrary product approval is introduced here.
Server-side retarget rejection, stale-base rejection, role revocation and
legitimate exact dev integration must be tested under the actual intended
credential before changing production settings. A mock test or read-only
policy observation cannot establish this. No stable or physical writer authority.

2026-11-26 baseline: main ruleset 28152434 lacks required CI/reviews;
dev ruleset 28107915 lacks the source-pinned Safety/Owner status checks.
The current production pause remains true. Lab PR #431 remains inert.

## Follow-up: production App source compatibility
The paused credential pilot run 45899011473 verified distinct exact inert
receipts 60004875747 (Safety) and 60004894056 (Owner). These are not
production authorization. The strict dev validator now recognizes the two
source-pinned production contexts gaslux-dev/safety-v1 and gaslux-dev/owner-v1,
rejects partial or wrong-source policies, and uses the real production App
registration IDs in GASLUX_SAFETY_APP_ID and GASLUX_OWNER_APP_ID. The pilot
reports these IDs from authenticated production App registrations; publication
rechecks them. Laboratory IDs 5938492/5938509 and bot actor IDs are explicitly
rejected. Missing or shared IDs fail closed. The verifier
and still requires both native reviews and existing CI. Production supervised
integration also checks both live exact receipts twice around readiness/merge.
The legacy keyboard path has no matching production status publisher and
remains closed. Native named-role protection is not replaced: changing a
review to dismissed does not atomically revoke a separately published status.
A future reviewed authorization design must resolve that race before replacing
native named-role enforcement. The activation audit is GET-only, works while
paused, and never grants merge authority. Main PRs always trigger the
adversarial_contracts CI check, avoiding path-filter deadlocks. No server
configuration has been changed by this proposal.

## Real retarget denial — 2026-11-26
Private standalone gaslux-merge-lab run 45901329724, runner HEAD
4d33640e8a7bc52d6c2d2811523834f5cc0b1e75, job 140187551249, proved
that a conflict-free inert PR #3 retargeted to lab-confinement-deny was
rejected with HTTP 405 by active wildcard update ruleset 28195442. The
candidate remained open and both target refs unchanged. The ruleset API
returned a parameterless update rule despite submission of an explicit
false fetch/merge exception. The production reader now accepts that observed
shape only after confirming the exact non-fork repository, and rejects
unknown parameters or a true exception. This proof is limited to the private
lab's own Actions token; production policy, actor-specific bypass boundaries,
functional acceptance and native independent role enforcement remain pending.
