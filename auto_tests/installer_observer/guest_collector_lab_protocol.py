"""Test-lab guest collector framing and durable local single-use ledger.

Not a production guest command protocol, attestation authority, or writer.
This validates *untrusted* bytes received over a QEMU-owned host socket.
Even a successful lab response is NOT independently guest-attested.
"""

from __future__ import annotations

import os
import re
import socket
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SESSION = re.compile(r"[a-zA-Z0-9_-]{8,80}\Z")
_MAX_FRAME = 512
_VERSION = "GASLUX-COLLECTOR-LAB-1"


class GuestCollectorDenied(ValueError):
    """Malformed, stale, ambiguous or replayed laboratory observation."""


def _check(valid: bool, reason: str) -> None:
    if not valid:
        raise GuestCollectorDenied(reason)


@dataclass(frozen=True)
class CollectorChallenge:
    session: str
    nonce: str
    collector_sha256: str

    def __post_init__(self) -> None:
        _check(
            type(self.session) is str
            and _SESSION.fullmatch(self.session) is not None
            and type(self.nonce) is str
            and _HEX64.fullmatch(self.nonce) is not None
            and type(self.collector_sha256) is str
            and _HEX64.fullmatch(self.collector_sha256) is not None,
            "INVALID_LAB_CHALLENGE",
        )

    def wire(self) -> bytes:
        return f"{_VERSION}|{self.session}|{self.nonce}\n".encode("ascii")


def response_bytes(
    challenge: CollectorChallenge, *, boot_id: str = "labboot01", counter: int = 1
) -> bytes:
    """Construct untrusted guest-like fixture bytes; NOT an attestation."""
    _check(type(boot_id) is str and _SESSION.fullmatch(boot_id) is not None, "BAD_BOOT_ID")
    _check(type(counter) is int and 1 <= counter <= 2147483647, "BAD_COUNTER")
    return (
        f"{_VERSION}|{challenge.session}|{challenge.nonce}|"
        f"{challenge.collector_sha256}|{counter}|{boot_id}\n"
    ).encode("ascii")


def read_frame(conn: socket.socket, *, max_bytes: int = _MAX_FRAME) -> bytes:
    """Bounded actual socket acquisition; no guest-origin inference."""
    _check(
        type(conn) is socket.socket and type(max_bytes) is int and 32 <= max_bytes <= 512,
        "INVALID_TRANSPORT",
    )
    payload = bytearray()
    try:
        while len(payload) <= max_bytes:
            byte = conn.recv(1)
            _check(bool(byte), "TRANSPORT_DISCONNECT_OR_TRUNCATION")
            payload.extend(byte)
            if byte == b"\n":
                _check(len(payload) <= max_bytes, "FRAME_TOO_LARGE")
                return bytes(payload)
    except (OSError, TimeoutError) as exc:
        raise GuestCollectorDenied("TRANSPORT_DISCONNECT_OR_TIMEOUT") from exc
    raise GuestCollectorDenied("FRAME_TOO_LARGE")


def validate_response(data: bytes, challenge: CollectorChallenge) -> dict[str, object]:
    """Never accept self-authenticated collector/guest status fields."""
    _check(type(data) is bytes and 1 <= len(data) <= _MAX_FRAME, "RESPONSE_SIZE_INVALID")
    _check(data.endswith(b"\n") and data.count(b"\n") == 1, "TRUNCATED_OR_MULTIFRAME")
    try:
        text = data[:-1].decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise GuestCollectorDenied("NON_ASCII_RESPONSE") from exc
    parts = text.split("|")
    _check(len(parts) == 6 and parts[0] == _VERSION, "RESPONSE_SCHEMA_INVALID")
    _, session, nonce, digest, counter_str, boot_id = parts
    _check(session == challenge.session, "WRONG_VM_SESSION")
    _check(nonce == challenge.nonce, "OLD_NONCE_OR_UNEXPECTED_CHALLENGE")
    _check(digest == challenge.collector_sha256, "COLLECTOR_HASH_MISMATCH")
    _check(bool(re.fullmatch(r"[1-9][0-9]{0,9}", counter_str)), "COUNTER_INVALID")
    counter = int(counter_str)
    _check(counter <= 2147483647, "COUNTER_INVALID")
    _check(_SESSION.fullmatch(boot_id) is not None, "BOOT_ID_INVALID")
    return {
        "guestMessageReceived": True,
        "guestCollectorExecutedObserved": False,  # requires separate boot witness
        "hostQemuPeerAuthenticated": False,  # requires separate SO_PEERCRED witness
        "guestOriginIndependentlyAttested": False,
        "guestChannelAuthenticated": False,
        "status": "BLOCKED_TRUST_ROOT",
        "classification": "NOT_ATTESTED",
        "session": session,
        "nonce": nonce,
        "collectorSha256Claimed": digest,
        "counter": counter,
        "bootIdClaimed": boot_id,
        "origin": "CLAIMED_GUEST",
        "inputAuthorized": False,
        "diskWriteAuthorized": False,
        "productionInstallationAuthorized": False,
        "rollbackProven": False,
        "stable": False,
    }


class LabChallengeLedger:
    """Durable lab-only ledger. Host compromise bypasses it. NO external trust."""

    def __init__(self, path: Path):
        _check(isinstance(path, Path) and path.is_absolute(), "INVALID_LEDGER_PATH")
        parent = path.parent
        _check(
            parent.is_dir()
            and not parent.is_symlink()
            and parent.stat().st_uid == os.getuid()
            and parent.stat().st_mode & 0o077 == 0
            and not path.is_symlink(),
            "UNOWNED_LEDGER_LOCATION",
        )
        fd = -1
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            st = os.fstat(fd)
            _check(
                stat.S_ISREG(st.st_mode)
                and st.st_uid == os.getuid()
                and st.st_mode & 0o077 == 0
                and st.st_nlink == 1,
                "LEDGER_OWNERSHIP_INVALID",
            )
            os.close(fd)
            fd = -1
            self._path = path
            with self._connect() as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS challenges ("
                    "session TEXT NOT NULL, nonce TEXT NOT NULL, collector TEXT NOT NULL,"
                    " used INTEGER NOT NULL CHECK(used IN (0,1)),"
                    " PRIMARY KEY(session, nonce))"
                )
        finally:
            if fd >= 0:
                os.close(fd)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self._path, timeout=4, isolation_level=None)
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def issue(self, challenge: CollectorChallenge) -> None:
        _check(type(challenge) is CollectorChallenge, "BAD_ISSUE")
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                # Session cannot be reused with a different nonce in this lab.
                _check(
                    db.execute(
                        "SELECT count(*) FROM challenges WHERE session=?", (challenge.session,)
                    ).fetchone()[0]
                    == 0,
                    "SESSION_REUSED",
                )
                db.execute(
                    "INSERT INTO challenges VALUES(?,?,?,0)",
                    (challenge.session, challenge.nonce, challenge.collector_sha256),
                )
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise GuestCollectorDenied("CHALLENGE_DUPLICATE") from exc

    def consume(self, challenge: CollectorChallenge, response: bytes) -> dict[str, object]:
        # Validate before consumption but use a durable transactional single-use update.
        record = validate_response(response, challenge)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE challenges SET used=1 WHERE session=? AND nonce=? "
                "AND collector=? AND used=0",
                (challenge.session, challenge.nonce, challenge.collector_sha256),
            ).rowcount
            _check(changed == 1, "OLD_NONCE_REPLAY_OR_UNISSUED")
            db.commit()
        return {
            **record,
            "localLabLedgerConsumed": True,
            "replayProtected": False,
            "externalLedgerAuthenticated": False,
        }

    def count_used(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT count(*) FROM challenges WHERE used=1").fetchone()[0])
