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

### Fixed semantic admission and remaining authorization gates (2026-11-24)

The generic Factory AST allowlist is necessary but not sufficient to prove
all-input non-writer behavior. For these five known lifecycle helpers, the
admission stage additionally requires AST equivalence to a fixed trusted
function: precisely eight named gates, strict identity with True, sorted
missing gates, correct backend and literal False installation/release flags.
Only the two observed local variable names are permitted. A Ruff repair must
still preserve the original AST. This does not execute candidate code or
prove the behavior of the rest of its enclosing module. Unusual but equivalent
helpers are rejected rather than extending the scope automatically.

Before granting integration authority, require: independent Safety identity
and exact-HEAD review; exact current dev base; authenticated candidate and CI
provenance; backend-owner acceptance; independently checked full VM evidence;
verified branch protection and exact-head merge mechanism; successful live
read-only admission on trusted main; and separate reviewed, bounded merge
implementation with pause, race, revocation and post-merge checks. The current
PR is read-only and does not grant that authority. Never reuse the CI from a
previous HEAD. No credentials or Safety approval are provisioned here.


## Follow-on: authenticated backend owner review (read-only)

Dependent on #417 at `f41ea7b91b4cdbef5be16780954a5997795de4f3`.
The original reviewed head is preserved. No new workflow or write permissions.
The repository administrator may provision `GASLUX_BACKEND_OWNER_IDS`, a JSON
mapping of role to positive numeric GitHub user ID. Missing, malformed, duplicate,
unknown or oversized configuration fails closed. Example shape (illustrative
only; these are not configured accounts): `{"zorin":123,"cachyos":456}`.

An actual GitHub APPROVED review from the configured backend owner must have the
exact candidate commit_id and contain a line in this form:

    GASLUX-BACKEND-OWNER-V1 role=<role> head=<40-hex-head> base=<40-hex-current-dev>

The owner must be distinct from the configured Safety identity, PR publisher and
repair author. Safety must also be distinct from publisher and repair author.
A stale base, changes requested, dismissed review, identity collision, wrong
role, missing review, API failure or observed HEAD drift blocks verification.
A plain comment or generated JSON does not constitute an attestation.
Configuration must be controlled by the administrator, with real role
separation; numeric IDs alone do not establish operational independence.

The v2 report identifies configured roles and can attest the owner-review gate.
It still never grants merge, writer or release authority. Full VM acceptance
remains false pending independent, exact-candidate Windows/Linux evidence and
a trusted evidence transport. No account has been provisioned by this change.

Live inspection (2026-11-24): all five candidate formal-review lists and #417's
formal-review list were empty. Historical contract workflow successes are not
installed-guest proof. #263 contains historical Windows/CachyOS experiments;
these do not prove the current candidate or current dev. Revalidate exact
ancestry, current base, actual CI and independent evidence before any merge.


## CI provenance and historical lab receipts (2026-11-24)

The read-only admission now requires successful named check runs AND actual
pull_request workflow runs for the immutable repository ID 1460159259, candidate
HEAD, observed workflow IDs (420402269, 420417743 and either 420471368 or
420371034), and exact run attempt/job metadata. Incomplete pages, mismatched
origin, unknown workflow, failed/skipped jobs, duplicate job names and stale
HEADs fail closed. It adds only actions:read to the existing admission job.
These checks identify workflow provenance, not a proof of actual installed
guest behavior or of an independently observed checkout tree. Live API
compatibility and scheduled behavior still need verification on trusted main.
No merge authority is granted.

Existing historical laboratory evidence, inspected via authenticated GitHub
run/job logs and artifact metadata (not downloaded or independently rehashed):

- #383 HEAD f6c79778b780d8abdfaf73a8beeef664dbca6a5c:
  run [45064724367](https://github.com/LMhdez/gaslux/actions/runs/45064724367),
  artifact 14770149177, reported ZIP SHA256
  9f387e95c5fe1e9d7166aa150a2eb11fbf91411224d4ac982c92827af06a2a82.
  Private synthetic QCOW2/OVMF restore verified; writer and quota denied.
- #388 HEAD ba1817d41330d33e500c36dc17c2f88e313c5fee:
  run [45067845469](https://github.com/LMhdez/gaslux/actions/runs/45067845469),
  artifact 14771887332, reported ZIP SHA256
  63c48150bb0108be5934c5b24dc9079780ec316dc319ce11cfb68258d69229e0.
  Actual 384-MiB ENOSPC/restore fixture and 60-GiB physical reservation plus
  synthetic overlay write/reset verified; not full-size exhaustion or guest
  recovery. Readiness report 2/11, next gate windows_iso_exact_microsoft_hash
  BLOCKED_MEDIA. Both artifacts expire 2026-12-06 unless retained elsewhere.

These are historical receipts, NOT current candidate acceptance. They do not
set full_vm_acceptance_verified or alter dev:docs/autonomy/evidence.json.
#418 is the existing private media preflight path; legal media provenance,
private environment, source URL, digest and exact byte length must be
provisioned independently before enabling it. #416 and #418 overlap the
Lifecycle workflow and require reviewed composition. #383/#388 remain Draft.
Do not reuse the old quota results as a guarantee of current runner capacity.
The full VM producer does not yet exist at the required evidence level;
do not introduce a permissive synthetic VM acceptance verifier to compensate.
