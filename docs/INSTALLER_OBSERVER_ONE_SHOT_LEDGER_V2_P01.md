# P-01 — Offline one-shot grant v2 (experimental, deny-only)

**Status: offline model only.** This patch is stacked on draft PR #283 at
`dda54ffa34a7cf4b93e781e02aeec7a408640aa2`.
It has no protected controller, signing authority, trusted clock, guest
transport, QEMU launch, writer, or production installation capability.
All `CAPABILITIES` remain `false`.

## Reproduction before fix

On initial PR #284 HEAD `7b8dc05774d04842f0750fee56b2df9daba394b8`,
[CI #44913404915](https://github.com/LMhdez/gaslux/actions/runs/44913404915)
ran 19 unittest cases: the 18 existing tests passed, but the new
`test_p01_distinct_uuids_cannot_reserve_or_consume_same_authorization`
failed with `AssertionError: Refused not raised`.
The original SQLite schema made only `grant_id` unique, permitting a second
reservation with a different UUID for the same experiment/commit/review.
The tests were published *before* the model was changed.

## Breaking v2 contract: no unsafe migration

- The original v1 schema remains available solely as historical reference.
- New grants must have `contractVersion=2` and a
  `externalDecisionId` UUID v4. This is a **synthetic claimed reference**
  whose value is matched against `TrustedDecisionFixture` on approval and
  consumption; it is NOT a verified credential.
- `schemas/observer-one-shot-grant-v2.schema.json` is the active schema;
  the fixture is migrated explicitly to v2.
- Opening an existing v1 SQLite database, an unknown `user_version`,
  or missing unique indexes raises `LEGACY_OR_AMBIGUOUS_LEDGER`.
  **Never** infer identity keys from old payloads, auto-upgrade old rows,
  delete history, or turn a previous grant into a new approval.
- The test database uses SQLite `user_version=2`.

## Canonical reservation keys and SQL invariants

Four additional columns hold persisted, non-rotating identities, with
unique constraints implemented **inside SQLite**, alongside the grant UUID:

| Column | Unique semantic identity |
| --- | --- |
| `grant_id` | One specific UUID (original invariant) |
| `authorization_key` | SHA-256 over canonical JSON tuple `(repository, experimentId, requestRef, authorizationSha, scope)` |
| `execution_key` | SHA-256 over `(repository, experimentId, authorizationSha, scope)`, **without requestRef** (prevents rotating the branch/reference) |
| `external_decision_id` | Claimed external decision UUID v4; globally unique within the ledger |
| `review_key` | SHA-256 over `(repository, humanReviewId)`; prevents giving the same human review another synthetic decision ID |

The keys intentionally **exclude** rotatable `grantId`, approval time,
expiry, reviewer name and external decision ID. A different request branch,
different reviewer or changed claimed approval ID cannot reserve another
grant for the same experiment/commit. Genuine distinct experiment/commit
pairs and distinct external decisions can be reserved independently.

`request()` first validates the v2 schema. Under a single `BEGIN IMMEDIATE`
transaction it attempts the SQL INSERT with all five unique constraints.
`sqlite3.IntegrityError` is converted into a deterministic denial.
Even for an unsuccessful **new** UUID, a durable DENIED row is inserted into
`decisions` and committed in the same transaction. No prior Python SELECT
is trusted as the uniqueness mechanism. Existing UUIDs are refused and
audited as before. No state transition, revocation or expiration deletes a
reservation or unique key. The original state machine remains unchanged.

The `TrustedDecisionFixture.external_decision_id` field is matched on
both APPROVED and CONSUMED; no ID supplied solely in JSON authenticates a
decision. In particular, `APPROVED` and `CONSUMED` are offline simulated
state transitions, **not approval to execute**.

## Adversarial tests

The suite tests two UUIDs for one authorization; same decision under a
different authorization SHA; review-ID reuse despite rotating the synthetic
decision UUID; same experiment/commit under a different request ref or
human reviewer; eight simultaneous reservation attempts; two concurrent
consumers; abort before commit; crash after commit; DB reopen; revocation;
expiration; v1 DB refusal; external authority unavailable; clock rollback;
write scope refused; and unchanged historical Git identity regressions.

The snapshot-rollback and out-of-band database edit cases **deliberately**
demonstrate that SQLite cannot protect itself against an administrator who
can replace its file or restore an old snapshot. A local filesystem is not
an independent trust root. `synchronous=FULL` protects ordinary transaction
commit ordering, not privileged deletion, replacement, host rollback,
distributed state, trusted wall-clock or revocation.

## Remaining mandatory controls (NOT implemented)

A separately administered protected controller (currently absent), a
durable external atomic consumption registry and a trusted expiry/revocation
authority are required before even a read-only QEMU execution request.
The separate #275 `validate_trigger/validate_git` remains the only
source of Git authorization checks; #267 owns GPT identity validation.
Neither is copied into this offline model. Gaslux Safety and Observer must
reaudit this exact new HEAD, and a human maintainer must approve changes
before merge. No writer, installation, Windows recovery, real-device
operation or execution authority follows from passing these tests.

`protectedControllerOperational=false`,
`externalLedgerOperational=false`,
`guestAttestationVerified=false`,
`qemuExecutionAuthorized=false`,
`guestCommandChannelAuthorized=false`,
`diskWritesAuthorized=false`,
`productionInstallationAuthorized=false`.
