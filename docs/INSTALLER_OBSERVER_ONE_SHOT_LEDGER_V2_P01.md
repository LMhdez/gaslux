# P-01 / S-01 / S-02 — Offline grant JSON v2, SQLite storage v3 (deny-only)

**Status: offline model only.** PR #284 is stacked on draft PR #283 at
`dda54ffa34a7cf4b93e781e02aeec7a408640aa2`; the S-01/S-02 storage
hardening is developed on a separate draft branch based on PR #284 HEAD
`b12dcf8cff82739aad819a84b4289f604235b8cf`.
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

## Grant JSON v2, storage SQLite v3: no unsafe migration

- The original v1 schema remains available solely as historical reference.
- New grants must have `contractVersion=2` and a
  `externalDecisionId` UUID v4. This is a **synthetic claimed reference**
  whose value is matched against `TrustedDecisionFixture` on approval and
  consumption; it is NOT a verified credential.
- `schemas/observer-one-shot-grant-v2.schema.json` is the active schema;
  the fixture is migrated explicitly to v2.
- Opening any existing SQLite v1/v2 database, an unknown `user_version`,
  or incomplete storage schema raises `LEGACY_OR_AMBIGUOUS_LEDGER`.
  **Never** infer identity keys from old payloads, auto-upgrade old rows,
  delete history, or turn a previous grant into a new approval.
- The unchanged grant JSON schema is `contractVersion=2`; the independent
  SQLite storage contract uses `PRAGMA user_version=3` with no automatic
  migration, deletion, or inference from existing rows.

## Canonical reservation keys and SQL invariants

Five additional columns hold persisted, non-rotating identities, with
unique constraints implemented **inside SQLite**, alongside the grant UUID:

| Column | Unique semantic identity |
| --- | --- |
| `grant_id` | One specific UUID (original invariant) |
| `authorization_key` | SHA-256 over canonical JSON tuple `(repository, experimentId, requestRef, authorizationSha, scope)` |
| `execution_key` | SHA-256 over `(repository, experimentId, authorizationSha, scope)`, **without requestRef** (prevents rotating the branch/reference) |
| `commit_key` | SHA-256 over `(repository, authorizationSha, scope)` **without experimentId** (rejects a second grant for the same commit across allegedly different experiments) |
| `external_decision_id` | Claimed external decision UUID v4; globally unique within the ledger |
| `review_key` | SHA-256 over `(repository, humanReviewId)`; prevents giving the same human review another synthetic decision ID |

The keys intentionally **exclude** rotatable `grantId`, approval time,
expiry, reviewer name and external decision ID. A different request branch,
different reviewer or changed claimed approval ID cannot reserve another
grant for the same repository/commit/scope, even when `experimentId` changes.
Different commits with independent review/decision identifiers are allowed.
A user-provided `experimentId` cannot authenticate genuine independence of
experiments; allowing the same commit in distinct experiments would require
an independently verified external policy and provenance, which do not exist.

`request()` first validates the v2 schema. Under a single `BEGIN IMMEDIATE`
transaction it attempts the SQL INSERT with all six unique constraints.
`sqlite3.IntegrityError` is converted into a deterministic denial.
Even for an unsuccessful **new** UUID, a durable DENIED row is inserted into
`decisions` and committed in the same transaction. No prior Python SELECT
is trusted as the uniqueness mechanism. Existing UUIDs are refused and
audited as before. No state transition, revocation or expiration deletes a
reservation or unique key. The original state machine remains unchanged.

Before opening a previously existing database, the constructor enforces the
exact storage-v3 table definitions for both `grants` and `decisions`; it checks
column ordering, declared types, NOT NULL/default/PRIMARY KEY layout,
`PRAGMA table_xinfo`, `index_list`, `index_xinfo`, each six-column-identity
single-key UNIQUE index (no partial, expression, descending or non-BINARY
substitute), database integrity, and the storage version. Unknown triggers,
indexes, altered DDL or empty existing databases are refused. No automatic
repair of storage schemas or historical data is attempted. These checks do
not authenticate a database file controlled by a privileged actor.

The `TrustedDecisionFixture.external_decision_id` field is matched on
both APPROVED and CONSUMED; no ID supplied solely in JSON authenticates a
decision. In particular, `APPROVED` and `CONSUMED` are offline simulated
state transitions, **not approval to execute**.

## Adversarial tests

The suite tests two UUIDs for one authorization; same decision under a
different authorization SHA; review-ID reuse despite rotating the synthetic
decision UUID; same experiment/commit under a different request ref or
human reviewer; cross-experiment same-commit rotations; 16 simultaneous
cross-experiment reservations; 16 concurrent consumers; exact S-01 malformed
tables, missing/partial UNIQUE indexes; abort before commit; crash after
commit; DB reopen; revocation;
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
