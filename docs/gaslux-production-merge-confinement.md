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
