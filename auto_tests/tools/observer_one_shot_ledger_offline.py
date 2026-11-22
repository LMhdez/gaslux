"""SQLite one-shot state model for disposable offline tests, NOT an authority service.

No executable or guest interface, no QEMU imports, and no issuance of usable grants.
The trusted decision input is only a model of external controls, NOT authentication.
Do not load this module from a GitHub Actions execution controller.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = Path(__file__).resolve().parents[2] / "schemas/observer-one-shot-grant-v2.schema.json"
SCHEMA_VALIDATOR = Draft202012Validator(
    json.loads(SCHEMA.read_text(encoding="utf-8")), format_checker=FormatChecker()
)

CAPABILITIES = {
    "protectedControllerOperational": False,
    "externalLedgerOperational": False,
    "guestAttestationVerified": False,
    "qemuExecutionAuthorized": False,
    "guestCommandChannelAuthorized": False,
    "diskWritesAuthorized": False,
    "productionInstallationAuthorized": False,
}

STATES = frozenset(
    {"REQUESTED", "REVIEW_PENDING", "APPROVED", "CONSUMED", "REVOKED", "EXPIRED", "REFUSED"}
)
TRANSITIONS = {
    "REQUESTED": {"REVIEW_PENDING", "REVOKED", "EXPIRED", "REFUSED"},
    "REVIEW_PENDING": {"APPROVED", "REVOKED", "EXPIRED", "REFUSED"},
    "APPROVED": {"CONSUMED", "REVOKED", "EXPIRED", "REFUSED"},
    "CONSUMED": set(),
    "REVOKED": set(),
    "EXPIRED": set(),
    "REFUSED": set(),
}


class Refused(ValueError):
    """A denied action has no authority and must not be retried as success."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class TrustedDecisionFixture:
    """Synthetic *out-of-band* approval snapshot, not a verifiable credential."""

    repository: str
    experiment_id: str
    preparation_sha: str
    authorization_sha: str
    protected_controller_sha: str
    audited_code_sha: str
    requester_id: str
    approver_id: str
    human_review_id: str
    external_decision_id: str
    review_verified: bool
    authority_available: bool


@dataclass(frozen=True)
class RunObservationFixture:
    """Caller-supplied simulated observations; NOT a substitute for #275 validate_git."""

    repository: str
    experiment_id: str
    request_ref: str
    preparation_sha: str
    authorization_sha: str
    protected_controller_sha: str
    audited_code_sha: str
    run_id: str
    run_attempt: int = 1
    branch_created: bool = False
    branch_recreated: bool = False
    forced_update: bool = False
    scope: str = "READ_ONLY_DIAGNOSTIC"


def _utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Refused("INVALID_TIME") from exc
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise Refused("INVALID_TIME")
    return value.astimezone(UTC)


def _iso(value: datetime | str) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _check_grant(grant: dict[str, Any]) -> tuple[str, str]:
    errors = list(SCHEMA_VALIDATOR.iter_errors(grant))
    if errors:
        raise Refused("GRANT_SCHEMA_INVALID")
    if grant["preparationSha"] == grant["authorizationSha"]:
        raise Refused("SAME_PREPARATION_AUTHORIZATION_SHA")
    if grant["requesterId"].casefold() == grant["externalApproverId"].casefold():
        raise Refused("SELF_APPROVAL")
    start, end = _utc(grant["issuedAt"]), _utc(grant["expiresAt"])
    if end <= start:
        raise Refused("INVALID_GRANT_WINDOW")
    payload = json.dumps(grant, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return payload, hashlib.sha256(payload.encode("ascii")).hexdigest()


def _decision_reason(grant: dict[str, Any], trusted: TrustedDecisionFixture | None) -> str | None:
    if trusted is None or trusted.authority_available is not True:
        return "EXTERNAL_AUTHORITY_UNAVAILABLE"
    if trusted.review_verified is not True or not trusted.human_review_id:
        return "HUMAN_REVIEW_NOT_VERIFIED"
    expected = (
        ("repository", trusted.repository),
        ("experimentId", trusted.experiment_id),
        ("preparationSha", trusted.preparation_sha),
        ("authorizationSha", trusted.authorization_sha),
        ("protectedControllerSha", trusted.protected_controller_sha),
        ("auditedCodeSha", trusted.audited_code_sha),
        ("requesterId", trusted.requester_id),
        ("externalApproverId", trusted.approver_id),
        ("humanReviewId", trusted.human_review_id),
        ("externalDecisionId", trusted.external_decision_id),
    )
    if any(grant[key] != value for key, value in expected):
        return "TRUSTED_DECISION_PIN_MISMATCH"
    if trusted.approver_id.casefold() == trusted.requester_id.casefold():
        return "SELF_APPROVAL"
    return None


def _run_reason(grant: dict[str, Any], run: RunObservationFixture) -> str | None:
    if run.branch_created or run.branch_recreated or run.forced_update:
        return "BRANCH_CREATION_OR_RECREATION_REFUSED"
    if type(run.run_attempt) is not int or run.run_attempt != 1:
        return "WORKFLOW_RERUN_REFUSED"
    if not run.run_id:
        return "MISSING_RUN_ID"
    if run.scope != "READ_ONLY_DIAGNOSTIC":
        return "WRITER_OR_INSTALLATION_REFUSED"
    checks = (
        ("repository", run.repository),
        ("experimentId", run.experiment_id),
        ("requestRef", run.request_ref),
        ("preparationSha", run.preparation_sha),
        ("authorizationSha", run.authorization_sha),
        ("protectedControllerSha", run.protected_controller_sha),
        ("auditedCodeSha", run.audited_code_sha),
    )
    if any(grant[k] != v for k, v in checks):
        return "UNAPPROVED_EXACT_COMMIT_OR_CONTEXT"
    return None


def _key(*values: str) -> str:
    """Canonical, unambiguous non-rotating identity; not a credential."""
    raw = json.dumps(values, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _identities(grant: dict[str, Any]) -> tuple[str, str, str]:
    # Exact grant identity is separately stored even though the stronger
    # execution identity also blocks branch/ref rotations for one commit.
    authorization_key = _key(
        grant["repository"],
        grant["experimentId"],
        grant["requestRef"],
        grant["authorizationSha"],
        grant["scope"],
    )
    execution_key = _key(
        grant["repository"],
        grant["experimentId"],
        grant["authorizationSha"],
        grant["scope"],
    )
    # Changing grantId, an allegedly external decision ID or approver cannot
    # turn the same human review into another reservation.
    review_key = _key(grant["repository"], grant["humanReviewId"])
    return authorization_key, execution_key, review_key


def _commit_key(grant: dict[str, Any]) -> str:
    # A caller-chosen experimentId does not establish independent authority.
    return _key(grant["repository"], grant["authorizationSha"], grant["scope"])


# The SQLite storage version is independent of the grant JSON contract version.
STORAGE_VERSION = 3
GRANTS_DDL = (
    "CREATE TABLE grants ("
    "grant_id TEXT NOT NULL PRIMARY KEY, "
    "authorization_key TEXT NOT NULL UNIQUE, "
    "execution_key TEXT NOT NULL UNIQUE, "
    "commit_key TEXT NOT NULL UNIQUE, "
    "external_decision_id TEXT NOT NULL UNIQUE, "
    "review_key TEXT NOT NULL UNIQUE, "
    "payload TEXT NOT NULL, digest TEXT NOT NULL, "
    "state TEXT NOT NULL, created_at TEXT NOT NULL)"
)
DECISIONS_DDL = (
    "CREATE TABLE decisions ("
    "sequence INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL, "
    "at TEXT NOT NULL, before_state TEXT, after_state TEXT, "
    "decision TEXT NOT NULL, reason TEXT NOT NULL, run_id TEXT)"
)


def _verify_storage(con: sqlite3.Connection) -> None:
    """Reject schema drift, missing constraints and deceptive partial indexes.

    Exact DDL is a secondary guard for PK/AUTOINCREMENT/constraint semantics;
    structured introspection independently verifies column and index geometry.
    This is *not* protection against an actor controlling the database file.
    """
    refused = "LEGACY_OR_AMBIGUOUS_LEDGER"
    if con.execute("PRAGMA user_version").fetchone()[0] != STORAGE_VERSION:
        raise Refused(refused)
    objects = con.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    if {(kind, name) for kind, name, _ in objects} != {("table", "grants"), ("table", "decisions")}:
        raise Refused(refused)
    if {name: ddl for _, name, ddl in objects} != {
        "grants": GRANTS_DDL,
        "decisions": DECISIONS_DDL,
    }:
        raise Refused(refused)

    layouts = {
        "grants": (
            ("grant_id", "TEXT", 1, 1),
            ("authorization_key", "TEXT", 1, 0),
            ("execution_key", "TEXT", 1, 0),
            ("commit_key", "TEXT", 1, 0),
            ("external_decision_id", "TEXT", 1, 0),
            ("review_key", "TEXT", 1, 0),
            ("payload", "TEXT", 1, 0),
            ("digest", "TEXT", 1, 0),
            ("state", "TEXT", 1, 0),
            ("created_at", "TEXT", 1, 0),
        ),
        "decisions": (
            ("sequence", "INTEGER", 0, 1),
            ("grant_id", "TEXT", 1, 0),
            ("at", "TEXT", 1, 0),
            ("before_state", "TEXT", 0, 0),
            ("after_state", "TEXT", 0, 0),
            ("decision", "TEXT", 1, 0),
            ("reason", "TEXT", 1, 0),
            ("run_id", "TEXT", 0, 0),
        ),
    }
    for table, expected in layouts.items():
        columns = con.execute(f"PRAGMA table_xinfo({table})").fetchall()
        observed = tuple((row[1], row[2], row[3], row[5]) for row in columns)
        if observed != expected or any(
            row[0] != index or row[4] is not None or row[6] != 0
            for index, row in enumerate(columns)
        ):
            raise Refused(refused)

    expected_unique = {
        "grant_id",
        "authorization_key",
        "execution_key",
        "commit_key",
        "external_decision_id",
        "review_key",
    }
    indexes = con.execute("PRAGMA index_list(grants)").fetchall()
    if (
        len(indexes) != len(expected_unique)
        or con.execute("PRAGMA index_list(decisions)").fetchall()
    ):
        raise Refused(refused)
    observed_unique: set[str] = set()
    for index in indexes:
        # index_list: seq, name, unique, origin, partial.
        if index[2] != 1 or index[3] not in {"u", "pk"} or index[4] != 0:
            raise Refused(refused)
        details = con.execute(f"PRAGMA index_xinfo({json.dumps(index[1])})").fetchall()
        # Exactly one BINARY ascending key column plus the implicit rowid.
        keys = [entry for entry in details if entry[5] == 1]
        if (
            len(keys) != 1
            or len(details) != 2
            or keys[0][0] != 0
            or keys[0][1] < 0
            or keys[0][3] != 0
            or keys[0][4] != "BINARY"
            or any(entry[5] != 1 and (entry[1] != -1 or entry[5] != 0) for entry in details)
        ):
            raise Refused(refused)
        column = keys[0][2]
        if column in observed_unique or column not in expected_unique:
            raise Refused(refused)
        if (column == "grant_id") != (index[3] == "pk"):
            raise Refused(refused)
        observed_unique.add(column)
    if observed_unique != expected_unique:
        raise Refused(refused)
    if con.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise Refused(refused)


class OfflineLedger:
    """Single-file test-only SQLite model with serialized durable state transitions."""

    def __init__(self, path: Path):
        self.path = Path(path)
        if not self.path.parent.is_dir() or self.path.parent.is_symlink():
            raise Refused("UNSAFE_LEDGER_DIRECTORY")
        # Reject symlink/hardlink aliases before connecting. Model tests assume a private
        # directory; these checks do NOT eliminate races from an attacker with filesystem access.
        if self.path.is_symlink():
            raise Refused("LEDGER_SYMLINK_REFUSED")
        existing_file = self.path.exists()
        if existing_file:
            details = self.path.stat()
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise Refused("LEDGER_ALIAS_REFUSED")
        else:
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self.path, flags, 0o600)
            os.close(fd)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            if existing_file:
                _verify_storage(con)
            else:
                con.execute(GRANTS_DDL)
                con.execute(DECISIONS_DDL)
                con.execute(f"PRAGMA user_version = {STORAGE_VERSION}")
                _verify_storage(con)
            con.execute("COMMIT")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(str(self.path), timeout=15, isolation_level=None)
        try:
            con.execute("PRAGMA busy_timeout=15000")
            con.execute("PRAGMA synchronous=FULL")
            con.execute("PRAGMA journal_mode=DELETE")
            yield con
        finally:
            con.close()

    @staticmethod
    def _record(
        con: sqlite3.Connection,
        grant_id: str,
        at: str,
        before: str | None,
        after: str | None,
        decision: str,
        reason: str,
        run_id: str | None = None,
    ) -> None:
        con.execute(
            "INSERT INTO decisions "
            "(grant_id, at, before_state, after_state, decision, reason, run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (grant_id, at, before, after, decision, reason, run_id),
        )

    @staticmethod
    def _row(con: sqlite3.Connection, grant_id: str) -> tuple[dict[str, Any], str]:
        row = con.execute(
            "SELECT payload, state FROM grants WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        if row is None:
            raise Refused("UNKNOWN_GRANT")
        return json.loads(row[0]), row[1]

    def request(self, grant: dict[str, Any], *, now: datetime | str) -> str:
        payload, digest = _check_grant(grant)
        at = _iso(now)
        if _utc(now) < _utc(grant["issuedAt"]) or _utc(now) >= _utc(grant["expiresAt"]):
            raise Refused("INVALID_REQUEST_TIME")
        gid = grant["grantId"]
        authorization_key, execution_key, review_key = _identities(grant)
        commit_key = _commit_key(grant)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            existing = con.execute("SELECT state FROM grants WHERE grant_id = ?", (gid,)).fetchone()
            if existing:
                self._record(con, gid, at, existing[0], existing[0], "DENIED", "GRANT_ID_REUSED")
                con.execute("COMMIT")
                raise Refused("GRANT_ID_REUSED")
            try:
                con.execute(
                    "INSERT INTO grants ("
                    "grant_id, authorization_key, execution_key, commit_key, "
                    "external_decision_id, review_key, payload, digest, state, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        gid,
                        authorization_key,
                        execution_key,
                        commit_key,
                        grant["externalDecisionId"],
                        review_key,
                        payload,
                        digest,
                        "REQUESTED",
                        at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                # The unique SQLite indexes, not a prior SELECT, decide the winner.
                # Preserve even the rejected candidate UUID as a durable audit event.
                constraints = (
                    ("authorization_key", authorization_key, "AUTHORIZATION_ALREADY_RESERVED"),
                    ("execution_key", execution_key, "EXPERIMENT_COMMIT_ALREADY_RESERVED"),
                    ("commit_key", commit_key, "REPOSITORY_COMMIT_ALREADY_RESERVED"),
                    (
                        "external_decision_id",
                        grant["externalDecisionId"],
                        "EXTERNAL_DECISION_ALREADY_RESERVED",
                    ),
                    ("review_key", review_key, "HUMAN_REVIEW_ALREADY_RESERVED"),
                )
                reason = "GRANT_UNIQUENESS_VIOLATION"
                for column, value, rejection in constraints:
                    if con.execute(f"SELECT 1 FROM grants WHERE {column} = ?", (value,)).fetchone():
                        reason = rejection
                        break
                self._record(con, gid, at, None, None, "DENIED", reason)
                con.execute("COMMIT")
                raise Refused(reason) from exc
            self._record(con, gid, at, None, "REQUESTED", "ACCEPTED", "REQUEST_CREATED")
            con.execute("COMMIT")
        return digest

    def transition(
        self,
        grant_id: str,
        to_state: str,
        *,
        now: datetime | str,
        trusted: TrustedDecisionFixture | None = None,
        run: RunObservationFixture | None = None,
    ) -> str:
        if to_state not in STATES or to_state in {"REQUESTED", "REVIEW_PENDING"} and trusted:
            raise Refused("INVALID_TRANSITION_INPUT")
        at = _iso(now)
        refused_reason = None
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            grant, before = self._row(con, grant_id)
            if _utc(now) >= _utc(grant["expiresAt"]) and before in {
                "REQUESTED",
                "REVIEW_PENDING",
                "APPROVED",
            }:
                refused_reason = "GRANT_EXPIRED"
                actual = "EXPIRED"
            elif to_state not in TRANSITIONS[before]:
                refused_reason = "INVALID_STATE_TRANSITION"
                actual = before
            elif to_state == "APPROVED":
                refused_reason = _decision_reason(grant, trusted)
                actual = before if refused_reason else to_state
            elif to_state == "CONSUMED":
                refused_reason = _decision_reason(grant, trusted)
                if refused_reason is None and run is None:
                    refused_reason = "RUN_PROOF_MISSING"
                if refused_reason is None and run is not None:
                    refused_reason = _run_reason(grant, run)
                actual = before if refused_reason else to_state
            elif to_state == "EXPIRED":
                refused_reason = "GRANT_NOT_EXPIRED"
                actual = before
            elif to_state == "REVIEW_PENDING":
                if trusted is not None or run is not None:
                    refused_reason = "UNTRUSTED_TRANSITION_INPUT"
                actual = before if refused_reason else to_state
            else:
                # Explicit, human-assessed revocation/refusal is represented offline;
                # this model cannot authenticate the caller who commands it.
                actual = to_state
            if actual != before:
                con.execute("UPDATE grants SET state = ? WHERE grant_id = ?", (actual, grant_id))
            self._record(
                con,
                grant_id,
                at,
                before,
                actual,
                "DENIED" if refused_reason else "TRANSITION",
                refused_reason or to_state,
                run.run_id if run is not None else None,
            )
            con.execute("COMMIT")
        if refused_reason:
            raise Refused(refused_reason)
        return actual

    def state(self, grant_id: str) -> str:
        with self._connect() as con:
            return self._row(con, grant_id)[1]

    def events(self, grant_id: str) -> list[tuple]:
        with self._connect() as con:
            return con.execute(
                "SELECT before_state, after_state, decision, reason, run_id "
                "FROM decisions WHERE grant_id = ? ORDER BY sequence",
                (grant_id,),
            ).fetchall()
