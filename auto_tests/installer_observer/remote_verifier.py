"""Fail-closed local verifier for signed, remote read-only Observer responses.

This module does not contact a broker, load trust from a response, verify TPM
quotes itself, or expose QMP/RFB/input operations. Trust anchors and workload
expectations must be provisioned by the caller through an independent channel.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import stat
import threading
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

_ROOT = Path(__file__).resolve().parents[2]
_REQUEST_SCHEMA = json.loads(
    (_ROOT / "schemas/observer-readonly-request.schema.json").read_text(encoding="utf-8")
)
_RESPONSE_SCHEMA = json.loads(
    (_ROOT / "schemas/observer-readonly-response.schema.json").read_text(encoding="utf-8")
)
_REQUEST_VALIDATOR = Draft202012Validator(_REQUEST_SCHEMA, format_checker=FormatChecker())
_RESPONSE_VALIDATOR = Draft202012Validator(_RESPONSE_SCHEMA, format_checker=FormatChecker())

_MAX_REQUEST_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_STATE_BYTES = 64 * 1024
_MAX_RESPONSE_LIFETIME = timedelta(seconds=30)
_MAX_SESSION_LIFETIME = timedelta(minutes=10)


class VerificationRefused(ValueError):
    """A response failed one or more mandatory verification gates."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _refuse(code: str, message: str) -> None:
    raise VerificationRefused(code, message)


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _refuse("json-duplicate-property", f"Duplicate JSON property: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    _refuse("json-invalid-number", f"Non-JSON numeric constant: {value}")


def _canonical(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise VerificationRefused(
            "canonicalization-failed", "RFC 8785 canonicalization failed"
        ) from exc


def _object(
    value: bytes | str | Mapping[str, Any], *, limit: int, label: str
) -> tuple[dict, bytes]:
    if isinstance(value, Mapping):
        try:
            canonical = _canonical(dict(value))
            parsed = json.loads(canonical.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
        except VerificationRefused:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError) as exc:
            raise VerificationRefused("json-invalid", f"{label} is not a JSON object") from exc
    elif isinstance(value, str):
        return _object(value.encode("utf-8"), limit=limit, label=label)
    elif isinstance(value, bytes):
        if len(value) > limit:
            _refuse("limit-exceeded", f"{label} exceeds its byte limit")
        try:
            parsed = json.loads(
                value.decode("utf-8"),
                object_pairs_hook=_pairs_no_duplicates,
                parse_constant=_reject_constant,
            )
        except VerificationRefused:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise VerificationRefused("json-invalid", f"{label} is invalid JSON") from exc
        if not isinstance(parsed, dict):
            _refuse("json-invalid", f"{label} must be a JSON object")
        canonical = _canonical(parsed)
    else:
        _refuse("json-invalid", f"{label} must be bytes, text or a mapping")
    if not isinstance(parsed, dict):
        _refuse("json-invalid", f"{label} must be a JSON object")
    if len(canonical) > limit:
        _refuse("limit-exceeded", f"{label} exceeds its canonical byte limit")
    return parsed, canonical


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise VerificationRefused("time-invalid", f"{field} is not a valid date-time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _refuse("time-invalid", f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        _refuse("time-invalid", f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _decode_nonce(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise VerificationRefused("nonce-invalid", "Nonce is not valid base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != 32 or canonical != value:
        _refuse("nonce-invalid", "Nonce must be canonical unpadded base64url for 256 bits")
    return decoded


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise VerificationRefused("signature-invalid", "Signature is not valid base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != 64 or canonical != value:
        _refuse("signature-invalid", "Ed25519 signature must be canonical 64-byte base64url")
    return decoded


@dataclass(frozen=True)
class TrustedController:
    """Externally provisioned controller, collector, guest and distribution expectations."""

    key_id: str
    public_key_raw: bytes
    controller_id: str
    controller_artifact_sha256: str
    policy_sha256: str
    collector_id: str
    collector_artifact_sha256: str
    vm_uuid: str
    qemu_executable_sha256: str
    distribution_id: str
    distribution_version: str
    iso_sha256: str
    installer_id: str
    attestation_verifier_id: str
    attestation_trust_anchor_id: str

    def __post_init__(self) -> None:
        if len(self.public_key_raw) != 32:
            raise ValueError("Pinned Ed25519 public keys must be exactly 32 raw bytes")
        for field in (
            "controller_artifact_sha256",
            "policy_sha256",
            "collector_artifact_sha256",
            "qemu_executable_sha256",
            "iso_sha256",
        ):
            if not _is_sha256(getattr(self, field)):
                raise ValueError(f"{field} must be a lowercase SHA-256 digest")
        if not all(
            (
                self.key_id,
                self.controller_id,
                self.collector_id,
                self.vm_uuid,
                self.distribution_id,
                self.distribution_version,
                self.installer_id,
                self.attestation_verifier_id,
                self.attestation_trust_anchor_id,
            )
        ):
            raise ValueError("All pinned identity fields must be non-empty")
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_raw)
        except ValueError as exc:
            raise ValueError("Invalid Ed25519 public key") from exc


@dataclass(frozen=True)
class TrustStore:
    """Pinned public keys and identity policy supplied independently of the server."""

    controllers: Mapping[str, TrustedController]

    def __post_init__(self) -> None:
        object.__setattr__(self, "controllers", MappingProxyType(dict(self.controllers)))
        for key_id, controller in self.controllers.items():
            if key_id != controller.key_id:
                raise ValueError("Trust-store map key must equal the pinned controller key ID")


class ReplayGuard(Protocol):
    """Atomic replay/session state; implementations must fail closed on storage errors."""

    def consume(
        self,
        *,
        operation: str,
        status: str,
        session_id: str | None,
        transaction_id: str,
        request_id: str,
        nonce: str,
        sequence: int,
        now: datetime,
        session_expires_at: datetime | None,
    ) -> None: ...


class InMemoryReplayGuard:
    """Thread-safe process-lifetime replay guard, intended for tests and short-lived tools."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: set[str] = set()
        self._request_ids: set[str] = set()
        self._sessions: dict[str, dict[str, Any]] = {}

    def consume(
        self,
        *,
        operation: str,
        status: str,
        session_id: str | None,
        transaction_id: str,
        request_id: str,
        nonce: str,
        sequence: int,
        now: datetime,
        session_expires_at: datetime | None,
    ) -> None:
        with self._lock:
            if nonce in self._nonces or request_id in self._request_ids:
                _refuse("replay", "Nonce or request ID has already been consumed")
            if operation == "session.identify":
                if status == "ok":
                    if session_id is None or session_id in self._sessions or sequence != 0:
                        _refuse(
                            "session-invalid",
                            "New session identity or initial sequence is invalid",
                        )
                    if session_expires_at is None or session_expires_at <= now:
                        _refuse("session-expired", "New session expiry is missing or expired")
                    self._sessions[session_id] = {
                        "transaction_id": transaction_id,
                        "last_sequence": 0,
                        "expires_at": session_expires_at,
                        "closed": False,
                    }
                elif session_id is not None:
                    _refuse("session-invalid", "Refused session creation must not create a session")
            else:
                if session_id is None or session_id not in self._sessions:
                    _refuse("stale-session", "Session is unknown to the replay guard")
                session = self._sessions[session_id]
                if session["closed"] or now >= session["expires_at"]:
                    _refuse("stale-session", "Session is closed or expired")
                if session["transaction_id"] != transaction_id:
                    _refuse("transaction-mismatch", "Session belongs to another transaction")
                if sequence != session["last_sequence"] + 1:
                    _refuse("replay", "Session sequence is not strictly monotonic")
                session["last_sequence"] = sequence
                if operation == "session.close" and status == "ok":
                    session["closed"] = True
            self._nonces.add(nonce)
            self._request_ids.add(request_id)


class SQLiteReplayGuard:
    """Durable replay guard for a client-owned private state directory.

    The parent directory must already exist and be private to the client. The
    database is created mode 0600; symlinks and non-regular database paths are
    refused. SQLite transactions serialize concurrent consumers.
    """

    def __init__(self, path: str | Path) -> None:
        if os.name != "posix" or not hasattr(os, "getuid"):
            raise ValueError("Durable replay guard currently requires a POSIX client")
        self.path = Path(path).absolute()
        parent = self.path.parent
        if parent.is_symlink() or not parent.is_dir() or parent.resolve(strict=True) != parent:
            raise ValueError("Replay database parent must be an existing non-symlink directory")
        parent_stat = parent.stat()
        if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
            raise ValueError("Replay database parent must be owned by this user and mode 0700")
        if self.path.is_symlink():
            raise ValueError("Replay database symlinks are refused")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise ValueError("Replay database must be a regular file owned by this user")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS sessions ("
                    "session_id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, "
                    "last_sequence INTEGER NOT NULL, expires_at TEXT NOT NULL, "
                    "closed INTEGER NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS consumed ("
                    "nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE)"
                )
        except sqlite3.Error as exc:
            raise ValueError("Could not initialize durable replay state") from exc

    def consume(
        self,
        *,
        operation: str,
        status: str,
        session_id: str | None,
        transaction_id: str,
        request_id: str,
        nonce: str,
        sequence: int,
        now: datetime,
        session_expires_at: datetime | None,
    ) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM consumed WHERE nonce = ? OR request_id = ?",
                    (nonce, request_id),
                ).fetchone():
                    _refuse("replay", "Nonce or request ID has already been consumed")
                if operation == "session.identify":
                    if status == "ok":
                        if session_id is None or sequence != 0 or session_expires_at is None:
                            _refuse("session-invalid", "New session identity is incomplete")
                        if session_expires_at <= now:
                            _refuse("session-expired", "New session expiry is expired")
                        connection.execute(
                            "INSERT INTO sessions VALUES (?, ?, 0, ?, 0)",
                            (session_id, transaction_id, session_expires_at.isoformat()),
                        )
                    elif session_id is not None:
                        _refuse(
                            "session-invalid",
                            "Refused session creation must not create a session",
                        )
                else:
                    row = connection.execute(
                        "SELECT transaction_id, last_sequence, expires_at, closed "
                        "FROM sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()
                    if row is None:
                        _refuse("stale-session", "Session is unknown to the durable replay guard")
                    stored_transaction, last_sequence, expires_at, closed = row
                    if closed or now >= _parse_time(expires_at, "stored session expiry"):
                        _refuse("stale-session", "Session is closed or expired")
                    if stored_transaction != transaction_id:
                        _refuse("transaction-mismatch", "Session belongs to another transaction")
                    if sequence != last_sequence + 1:
                        _refuse("replay", "Session sequence is not strictly monotonic")
                    connection.execute(
                        "UPDATE sessions SET last_sequence = ?, closed = ? WHERE session_id = ?",
                        (
                            sequence,
                            int(operation == "session.close" and status == "ok"),
                            session_id,
                        ),
                    )
                connection.execute(
                    "INSERT INTO consumed (nonce, request_id) VALUES (?, ?)",
                    (nonce, request_id),
                )
                connection.commit()
        except VerificationRefused:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise VerificationRefused(
                "replay-state-unavailable", "Durable replay state could not be updated"
            ) from exc


@dataclass(frozen=True)
class VerifiedRemoteResponse:
    """Verified envelope with trust dimensions kept separate."""

    status: str
    operation: str
    session_id: str | None
    transaction_id: str
    request_id: str
    controller_signature_verified: bool
    controller_workload_trusted: bool
    collector_trusted: bool
    guest_identity_assurance: str
    guest_attestation_status: str
    guest_attestation_assertion: str
    guest_attestation_verified_locally: bool
    distribution_id: str
    distribution_version: str
    iso_sha256: str
    result_sha256: str
    result: Mapping[str, Any]
    refusal_code: str | None = None


class RemoteResponseVerifier:
    """Verify signed response envelopes against independently pinned local policy."""

    def __init__(
        self,
        trust_store: TrustStore | None,
        replay_guard: ReplayGuard | None,
        *,
        require_guest_attestation: bool = True,
        clock_skew: timedelta = timedelta(seconds=5),
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        self.trust_store = trust_store
        self.replay_guard = replay_guard
        self.require_guest_attestation = require_guest_attestation
        self.clock_skew = clock_skew
        if max_response_bytes < 1 or clock_skew < timedelta(0):
            raise ValueError("Verifier byte limit and clock skew must be non-negative")
        self.max_response_bytes = min(max_response_bytes, _MAX_RESPONSE_BYTES)

    def verify(
        self,
        request: bytes | str | Mapping[str, Any],
        response: bytes | str | Mapping[str, Any],
        *,
        deadline: datetime,
        now: datetime | None = None,
    ) -> VerifiedRemoteResponse:
        if self.trust_store is None or not self.trust_store.controllers:
            _refuse("trust-anchor-missing", "No independently provisioned controller trust anchor")
        if self.replay_guard is None:
            _refuse("replay-state-unavailable", "No replay guard is configured")
        current = _aware(now or datetime.now(UTC), "now")
        absolute_deadline = _aware(deadline, "deadline")
        if current >= absolute_deadline:
            _refuse("deadline-exceeded", "Request deadline has already expired")

        request_value, request_canonical = _object(
            request, limit=_MAX_REQUEST_BYTES, label="request"
        )
        response_value, response_canonical = _object(
            response, limit=self.max_response_bytes, label="response"
        )
        try:
            _REQUEST_VALIDATOR.validate(request_value)
            _RESPONSE_VALIDATOR.validate(response_value)
        except (ValidationError, RecursionError) as exc:
            raise VerificationRefused(
                "schema-invalid", "Request or response schema validation failed"
            ) from exc

        _decode_nonce(request_value["nonce"])
        timeout_ms = request_value["timeout_ms"]
        if absolute_deadline - current > timedelta(milliseconds=timeout_ms) + self.clock_skew:
            _refuse("deadline-invalid", "Caller deadline exceeds the request timeout")
        if len(response_canonical) > min(
            request_value["max_response_bytes"], self.max_response_bytes
        ):
            _refuse("limit-exceeded", "Response exceeds the request or verifier byte limit")

        operation = request_value["operation"]
        if response_value["operation"] != operation:
            _refuse("operation-mismatch", "Response operation does not match the request")
        for field in ("transaction_id", "request_id", "nonce", "sequence"):
            if response_value[field] != request_value[field]:
                _refuse("request-binding-failed", f"Response {field} does not match the request")
        expected_request_hash = _sha256(request_canonical)
        if response_value["request_sha256"] != expected_request_hash:
            _refuse("request-binding-failed", "Signed request digest does not match this request")

        if operation == "session.identify":
            if request_value["session_id"] is not None or request_value["sequence"] != 0:
                _refuse(
                    "session-binding-failed",
                    "Initial request must have a null session and sequence zero",
                )
            if response_value["status"] == "ok":
                if response_value["session_id"] is None:
                    _refuse(
                        "session-binding-failed",
                        "Successful session creation lacks a session ID",
                    )
            elif response_value["session_id"] is not None:
                _refuse(
                    "session-binding-failed",
                    "Refused session creation must not create a session",
                )
        elif response_value["session_id"] != request_value["session_id"]:
            _refuse("session-binding-failed", "Response session ID does not match the request")

        controller = response_value["controller"]
        signature = response_value["signature"]
        key_id = signature["key_id"]
        if controller["key_id"] != key_id:
            _refuse("controller-identity-mismatch", "Controller and signature key IDs differ")
        trusted = self.trust_store.controllers.get(key_id)
        if trusted is None:
            _refuse("untrusted-key", "Signing key is not present in the external trust store")
        self._verify_identity(response_value, trusted)

        unsigned = dict(response_value)
        unsigned.pop("signature")
        signed_bytes = _canonical(unsigned)
        try:
            Ed25519PublicKey.from_public_bytes(trusted.public_key_raw).verify(
                _decode_signature(signature["value"]), signed_bytes
            )
        except InvalidSignature as exc:
            raise VerificationRefused(
                "signature-invalid", "Ed25519 response signature is invalid"
            ) from exc
        except ValueError as exc:
            raise VerificationRefused("signature-invalid", "Pinned Ed25519 key is invalid") from exc

        result = response_value["result"]
        result_hash = _sha256(_canonical(result))
        if response_value["result_sha256"] != result_hash:
            _refuse("result-integrity-failed", "Canonical result digest does not match")
        if result["kind"] == "state" and len(_canonical(result["snapshot"])) > _MAX_STATE_BYTES:
            _refuse("limit-exceeded", "State snapshot exceeds 64 KiB")
        if result["kind"] == "frame":
            self._verify_frame(result)

        issued_at = _parse_time(response_value["issued_at"], "issued_at")
        expires_at = _parse_time(response_value["expires_at"], "expires_at")
        if issued_at > current + self.clock_skew:
            _refuse("time-invalid", "Response was issued too far in the future")
        if issued_at > absolute_deadline:
            _refuse("deadline-exceeded", "Response was issued after the request deadline")
        if expires_at <= current or expires_at <= issued_at:
            _refuse("expired", "Response has expired or has an invalid expiry interval")
        if expires_at - issued_at > _MAX_RESPONSE_LIFETIME:
            _refuse("expiry-invalid", "Response validity exceeds the 30-second protocol limit")
        if result["kind"] == "state":
            observed_at = _parse_time(result["observed_at"], "observed_at")
            if (
                observed_at > issued_at + self.clock_skew
                or observed_at < issued_at - _MAX_RESPONSE_LIFETIME
            ):
                _refuse(
                    "observation-time-invalid",
                    "State observation is outside the response validity window",
                )

        session_expires_at: datetime | None = None
        if operation == "session.identify" and response_value["status"] == "ok":
            if result["kind"] != "session" or result["closed"]:
                _refuse("session-invalid", "Successful identify must return an open session")
            if result["session_expires_at"] is None:
                _refuse("session-invalid", "Successful identify must provide a session expiry")
            session_expires_at = _parse_time(result["session_expires_at"], "session_expires_at")
            if (
                session_expires_at <= current
                or session_expires_at > issued_at + _MAX_SESSION_LIFETIME
            ):
                _refuse(
                    "session-expired",
                    "Session expiry is outside the permitted ten-minute window",
                )
            if expires_at > session_expires_at:
                _refuse("session-expired", "Response expiry exceeds the session expiry")
        self._verify_operation_result(operation, response_value["status"], result)

        guest = response_value["guest"]
        distribution = guest["distribution"]
        if response_value["status"] == "ok":
            self._verify_guest(guest, distribution, trusted)

        self.replay_guard.consume(
            operation=operation,
            status=response_value["status"],
            session_id=response_value["session_id"],
            transaction_id=response_value["transaction_id"],
            request_id=response_value["request_id"],
            nonce=response_value["nonce"],
            sequence=response_value["sequence"],
            now=current,
            session_expires_at=session_expires_at,
        )

        attestation = guest["attestation"]
        attestation_assertion = (
            "trusted-controller-asserted" if attestation["status"] == "verified" else "not-verified"
        )
        return VerifiedRemoteResponse(
            status=response_value["status"],
            operation=operation,
            session_id=response_value["session_id"],
            transaction_id=response_value["transaction_id"],
            request_id=response_value["request_id"],
            controller_signature_verified=True,
            controller_workload_trusted=True,
            collector_trusted=True,
            guest_identity_assurance=guest["identity_assurance"],
            guest_attestation_status=attestation["status"],
            guest_attestation_assertion=attestation_assertion,
            guest_attestation_verified_locally=False,
            distribution_id=distribution["id"],
            distribution_version=distribution["version"],
            iso_sha256=distribution["iso_sha256"],
            result_sha256=result_hash,
            result=result,
            refusal_code=result.get("code") if response_value["status"] == "refused" else None,
        )

    @staticmethod
    def _verify_identity(response: Mapping[str, Any], trusted: TrustedController) -> None:
        controller = response["controller"]
        collector = response["collector"]
        if (
            controller["controller_id"] != trusted.controller_id
            or controller["artifact_sha256"] != trusted.controller_artifact_sha256
            or controller["policy_sha256"] != trusted.policy_sha256
        ):
            _refuse("controller-integrity-failed", "Controller identity or artifact is not pinned")
        if (
            collector["collector_id"] != trusted.collector_id
            or collector["artifact_sha256"] != trusted.collector_artifact_sha256
        ):
            _refuse("collector-integrity-failed", "Collector identity or artifact is not pinned")

    def _verify_guest(
        self,
        guest: Mapping[str, Any],
        distribution: Mapping[str, Any],
        trusted: TrustedController,
    ) -> None:
        process = guest["qemu_process"]
        if (
            guest["vm_uuid"] != trusted.vm_uuid
            or process["executable_sha256"] != trusted.qemu_executable_sha256
        ):
            _refuse("guest-identity-mismatch", "VM or QEMU executable identity is not pinned")
        if (
            distribution["id"] != trusted.distribution_id
            or distribution["version"] != trusted.distribution_version
            or distribution["iso_sha256"] != trusted.iso_sha256
            or distribution["installer_id"] != trusted.installer_id
        ):
            _refuse(
                "distribution-identity-mismatch",
                "Distribution, version, ISO or installer is not pinned",
            )
        attestation = guest["attestation"]
        if not self.require_guest_attestation:
            return
        if guest["identity_assurance"] != "cryptographically-attested":
            _refuse(
                "guest-attestation-required",
                "Guest identity is not cryptographically attested",
            )
        if (
            attestation["status"] != "verified"
            or attestation["evidence_sha256"] is None
            or attestation["verifier_id"] != trusted.attestation_verifier_id
            or attestation["trust_anchor_id"] != trusted.attestation_trust_anchor_id
        ):
            _refuse(
                "guest-attestation-failed",
                "Required guest attestation assertion is absent or untrusted",
            )

    @staticmethod
    def _verify_operation_result(operation: str, status: str, result: Mapping[str, Any]) -> None:
        if status == "refused":
            if result["kind"] != "refusal":
                _refuse("response-invalid", "Refused status must contain only a refusal result")
            return
        expected = {
            "session.identify": "session",
            "state.read": "state",
            "frame.read": "frame",
            "session.close": "session",
        }[operation]
        if result["kind"] != expected:
            _refuse("response-invalid", "Result kind does not match the requested operation")
        if operation == "session.close" and result["closed"] is not True:
            _refuse("response-invalid", "Successful session.close did not confirm closure")

    @staticmethod
    def _verify_frame(result: Mapping[str, Any]) -> None:
        try:
            data = base64.b64decode(result["data"], validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise VerificationRefused("frame-invalid", "Framebuffer is not valid base64") from exc
        if base64.b64encode(data).decode("ascii") != result["data"]:
            _refuse("frame-invalid", "Framebuffer base64 encoding is not canonical")
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            _refuse("frame-invalid", "Framebuffer is not a PNG image")
        if len(data) > _MAX_RESPONSE_BYTES or _sha256(data) != result["sha256"]:
            _refuse("frame-integrity-failed", "Framebuffer size or SHA-256 is invalid")
