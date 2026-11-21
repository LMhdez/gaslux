"""Durable, fail-closed TPM quote replay ledger; NOT an independent trust anchor.

Reuses the existing Observer SQLiteReplayGuard's transaction/SQLite connection
configuration without changing the remote v1 replay contract. Provision once;
reopening NEVER recreates an absent or malformed TPM quote ledger.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from .guest_attestation import AttestationRefused, ident, require
from .remote_verifier import SQLiteReplayGuard

_META_SQL = (
    "CREATE TABLE tpm_quote_meta ("
    "id INTEGER PRIMARY KEY CHECK (id = 1), "
    "version INTEGER NOT NULL CHECK (version = 1), "
    "ledger_id TEXT NOT NULL)"
)
_CONSUMED_SQL = (
    "CREATE TABLE tpm_quote_consumed ("
    "challenge BLOB PRIMARY KEY CHECK (length(challenge) = 32), "
    "nonce BLOB NOT NULL UNIQUE CHECK (length(nonce) = 32), "
    "request_id TEXT NOT NULL UNIQUE, "
    "transaction_id TEXT NOT NULL, "
    "session_id TEXT NOT NULL, "
    "consumed_at TEXT NOT NULL, "
    "valid_until TEXT NOT NULL)"
)


class DurableQuoteReplayGuard:
    """POSIX-only, process-safe SQLite quote ledger with no automatic reset.

    This guards against accidents, link attacks, crashes and concurrent clients,
    not a malicious same-UID/root administrator who can replace the database.
    Never delete consumed rows or recycle nonce/request IDs after expiry.
    """

    @staticmethod
    def _identity(path: Path) -> tuple[int, int, int, int]:
        try:
            if os.name != "posix":
                raise ValueError("POSIX ownership semantics required")
            parent = path.parent
            if parent.resolve(strict=True) != parent or parent.is_symlink():
                raise ValueError("Replay parent is not canonical")
            directory = parent.stat()
            if (
                not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != os.getuid()
                or stat.S_IMODE(directory.st_mode) != 0o700
            ):
                raise ValueError("Replay parent must be private and owned")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(path, flags)
            try:
                file = os.fstat(fd)
                link = os.lstat(path)
                if (
                    not stat.S_ISREG(file.st_mode)
                    or file.st_uid != os.getuid()
                    or stat.S_IMODE(file.st_mode) != 0o600
                    or file.st_nlink != 1
                    or not stat.S_ISREG(link.st_mode)
                    or (file.st_dev, file.st_ino) != (link.st_dev, link.st_ino)
                ):
                    raise ValueError("Replay database ownership, links or mode invalid")
                return (directory.st_dev, directory.st_ino, file.st_dev, file.st_ino)
            finally:
                os.close(fd)
        except (OSError, ValueError, RuntimeError) as exc:
            raise AttestationRefused("REPLAY_STORAGE_UNAVAILABLE") from exc

    @classmethod
    def provision(cls, path: str | Path) -> DurableQuoteReplayGuard:
        """Explicit enrollment, exclusive creation; never silently reset a ledger."""
        target = Path(path).absolute()
        try:
            # Reuse the existing private parent-path contract.
            parent = target.parent
            if parent.resolve(strict=True) != parent or parent.is_symlink():
                raise ValueError("Unsafe ledger parent")
            info = parent.stat()
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("Ledger parent must be mode 0700 and owned")
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
            finally:
                os.close(fd)
            db = SQLiteReplayGuard(target)
            with closing(db._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(_META_SQL)
                connection.execute(_CONSUMED_SQL)
                connection.execute(
                    "INSERT INTO tpm_quote_meta VALUES (1, 1, ?)",
                    (secrets.token_hex(32),),
                )
                connection.commit()
            directory_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except (OSError, ValueError, sqlite3.Error) as exc:
            # Preserve any incomplete database for forensics; never delete it.
            raise AttestationRefused("REPLAY_STORAGE_UNAVAILABLE") from exc
        return cls(target)

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).absolute()
        self._stat = self._identity(self.path)
        try:
            self._db = SQLiteReplayGuard(self.path)
            with closing(self._db._connect()) as connection:
                self._validate(connection)
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise AttestationRefused("REPLAY_STORAGE_UNAVAILABLE") from exc
        self._check_path()

    def _check_path(self) -> None:
        if self._identity(self.path) != self._stat:
            raise AttestationRefused("REPLAY_STORAGE_CHANGED")

    @staticmethod
    def _validate(connection: sqlite3.Connection) -> None:
        try:
            check = connection.execute("PRAGMA quick_check").fetchone()
            if check != ("ok",):
                raise ValueError("SQLite integrity check failed")
            for name, definition in (
                ("tpm_quote_meta", _META_SQL),
                ("tpm_quote_consumed", _CONSUMED_SQL),
            ):
                row = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (name,),
                ).fetchone()
                if row is None or row[0] != definition:
                    raise ValueError("TPM quote schema missing or changed")
            meta = connection.execute(
                "SELECT version, ledger_id FROM tpm_quote_meta WHERE id = 1"
            ).fetchall()
            count = connection.execute("SELECT count(*) FROM tpm_quote_meta").fetchone()
            if (
                len(meta) != 1
                or count != (1,)
                or meta[0][0] != 1
                or not isinstance(meta[0][1], str)
                or len(meta[0][1]) != 64
            ):
                raise ValueError("TPM ledger marker missing or inconsistent")
        except (sqlite3.Error, ValueError) as exc:
            raise AttestationRefused("REPLAY_STORAGE_UNAVAILABLE") from exc

    def consume_challenge(
        self,
        challenge: bytes,
        *,
        nonce: bytes,
        request_id: str,
        transaction_id: str,
        session_id: str,
        now: datetime,
        valid_until: datetime,
    ) -> None:
        require(
            isinstance(challenge, bytes)
            and len(challenge) == 32
            and isinstance(nonce, bytes)
            and len(nonce) == 32
            and ident(request_id)
            and ident(transaction_id)
            and ident(session_id),
            "REPLAY_IDENTITY_INVALID",
        )
        require(
            isinstance(now, datetime)
            and isinstance(valid_until, datetime)
            and now.tzinfo is not None
            and valid_until.tzinfo is not None
            and now.astimezone(UTC) < valid_until.astimezone(UTC),
            "REPLAY_TIME_INVALID",
        )
        self._check_path()
        try:
            with closing(self._db._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._check_path()
                self._validate(connection)
                for column, value, code in (
                    ("challenge", challenge, "CHALLENGE_REPLAY"),
                    ("nonce", nonce, "NONCE_REPLAY"),
                    ("request_id", request_id, "REQUEST_REPLAY"),
                ):
                    # Column names are fixed in code, never derived from evidence.
                    if connection.execute(
                        f"SELECT 1 FROM tpm_quote_consumed WHERE {column} = ?", (value,)
                    ).fetchone():
                        raise AttestationRefused(code)
                connection.execute(
                    "INSERT INTO tpm_quote_consumed VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        challenge,
                        nonce,
                        request_id,
                        transaction_id,
                        session_id,
                        now.astimezone(UTC).isoformat(),
                        valid_until.astimezone(UTC).isoformat(),
                    ),
                )
                self._check_path()
                connection.commit()
            self._check_path()
        except AttestationRefused:
            raise
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise AttestationRefused("REPLAY_STORAGE_UNAVAILABLE") from exc
