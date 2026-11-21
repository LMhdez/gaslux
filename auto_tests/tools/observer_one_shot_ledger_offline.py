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
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = Path(__file__).resolve().parents[2] / "schemas/observer-one-shot-grant-v1.schema.json"
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
    return value.astimezone(timezone.utc)


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
        if self.path.exists():
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
            con.execute(
                "CREATE TABLE IF NOT EXISTS grants ("
                "grant_id TEXT PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL, "
                "state TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS decisions ("
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL, "
                "at TEXT NOT NULL, before_state TEXT, after_state TEXT, "
                "decision TEXT NOT NULL, reason TEXT NOT NULL, run_id TEXT)"
            )

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
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            existing = con.execute("SELECT state FROM grants WHERE grant_id = ?", (gid,)).fetchone()
            if existing:
                self._record(
                    con, gid, at, existing[0], existing[0], "DENIED", "GRANT_ID_REUSED"
                )
                con.execute("COMMIT")
                raise Refused("GRANT_ID_REUSED")
            con.execute(
                "INSERT INTO grants VALUES (?, ?, ?, ?, ?)",
                (gid, payload, digest, "REQUESTED", at),
            )
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
                "REQUESTED", "REVIEW_PENDING", "APPROVED"
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
                con, grant_id, at, before, actual,
                "DENIED" if refused_reason else "TRANSITION", refused_reason or to_state,
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
                "FROM decisions WHERE grant_id = ? ORDER BY sequence", (grant_id,)
            ).fetchall()
