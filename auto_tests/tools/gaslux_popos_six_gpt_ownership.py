#!/usr/bin/env python3
"""Transaction-scoped regular-file ownership for the Pop six-GPT preflight.

Only this narrow experiment uses this module. Never delete by prefix, glob,
recursive pathname walk, user ID, size or a caller-supplied signed-shaped JSON.
Keep a directory FD alive across ALL preflight, fsck and recovery operations.

IMPORTANT TRUST LIMIT: same-UID *concurrent* mutation after final inode check
and before unlinkat cannot be atomically excluded on an ordinary POSIX path.
On detected changes fail closed and retain evidence. An untrusted same-UID
process sharing the runner prevents any security claim about complete cleanup.
"""

from __future__ import annotations

import contextvars
import hashlib
import os
import secrets
import stat
from pathlib import Path

from gaslux_popos_reuse_snapshot_gate import (
    Refusal,
    need,
)
from gaslux_popos_reuse_snapshot_gate import (
    make_child as original_make_child,
)

_ACTIVE = contextvars.ContextVar("gaslux_six_gpt_owned_work", default=None)


class OwnedDirectory:
    """FD-pinned parent+child, explicit per-creation (device,inode) inventory."""

    def __init__(self, path: Path):
        path = Path(path)
        need(
            path.is_absolute() and path.name.startswith("gaslux-pop-six-gpt-"),
            "REFUSE_OWNERSHIP: unexpected laboratory directory",
        )
        self.path = path
        self.parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.dir_fd = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=self.parent_fd,
            )
        except BaseException:
            os.close(self.parent_fd)
            raise
        self.identity = self._identity(os.fstat(self.dir_fd))
        self.entries: dict[str, tuple[int, int]] = {}
        self.active_token = None
        self.closed = False
        self._check_directory()

    @staticmethod
    def _identity(st: os.stat_result) -> tuple[int, int]:
        return st.st_dev, st.st_ino

    @classmethod
    def create(cls, parent: Path) -> OwnedDirectory:
        parent = Path(parent)
        need(
            parent.is_absolute() and parent.is_dir() and not parent.is_symlink(),
            "REFUSE_OWNERSHIP: foreign temporary parent",
        )
        name = "gaslux-pop-six-gpt-" + secrets.token_hex(16)
        pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(name, mode=0o700, dir_fd=pfd)
        finally:
            os.close(pfd)
        return cls(parent / name)

    def __enter__(self):
        need(_ACTIVE.get() is None, "REFUSE_OWNERSHIP: nested owners")
        self._check_directory()
        self.active_token = _ACTIVE.set(self)
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.active_token is not None:
            _ACTIVE.reset(self.active_token)
        self.close()
        return False

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            os.close(self.dir_fd)
            os.close(self.parent_fd)

    def _check_directory(self):
        need(
            not self.closed
            and self._identity(os.fstat(self.dir_fd)) == self.identity
            and self._identity(
                os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
            )
            == self.identity,
            "REFUSE_OWNERSHIP: directory replaced/renamed",
        )
        own = os.fstat(self.dir_fd)
        need(
            stat.S_ISDIR(own.st_mode)
            and own.st_uid == os.geteuid()
            and stat.S_IMODE(own.st_mode) == 0o700,
            "REFUSE_OWNERSHIP: foreign laboratory directory",
        )

    def _name(self, path: Path) -> str:
        p = Path(path)
        need(
            p.is_absolute()
            and p.parent == self.path
            and p.name
            and p.name not in (".", "..")
            and "/" not in p.name,
            "REFUSE_OWNERSHIP: path outside pinned directory",
        )
        return p.name

    def _stat_owned(self, name: str):
        self._check_directory()
        need(name in self.entries, "REFUSE_OWNERSHIP: unregistered resource")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.dir_fd)
        try:
            st = os.fstat(fd)
            at = os.stat(name, dir_fd=self.dir_fd, follow_symlinks=False)
            need(
                self._identity(st) == self.entries[name]
                and self._identity(at) == self.entries[name]
                and stat.S_ISREG(st.st_mode)
                and st.st_nlink == 1
                and st.st_uid == os.geteuid(),
                "REFUSE_OWNERSHIP: resource swapped/linked",
            )
            return st
        finally:
            os.close(fd)

    def record_new(self, path: Path):
        """Only call at the creation site, never build ownership by scanning."""
        name = self._name(path)
        self._check_directory()
        need(name not in self.entries, "REFUSE_OWNERSHIP: reused resource name")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.dir_fd)
        try:
            st = os.fstat(fd)
            need(
                stat.S_ISREG(st.st_mode)
                and st.st_uid == os.geteuid()
                and st.st_nlink == 1
                and self._identity(os.stat(name, dir_fd=self.dir_fd, follow_symlinks=False))
                == self._identity(st),
                "REFUSE_OWNERSHIP: foreign newly-created resource",
            )
            self.entries[name] = self._identity(st)
        finally:
            os.close(fd)
        return path

    def create_file(self, path: Path, size: int):
        """O_EXCL + dirfd; register inode BEFORE ftruncate (ENOSPC-safe)."""
        name = self._name(path)
        self._check_directory()
        need(
            name not in self.entries and type(size) is int and size >= 0,
            "REFUSE_OWNERSHIP: invalid exclusive creation",
        )
        fd = os.open(
            name,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.dir_fd,
        )
        try:
            st = os.fstat(fd)
            need(
                stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.geteuid(),
                "REFUSE_OWNERSHIP: invalid exclusive inode",
            )
            self.entries[name] = self._identity(st)
            os.ftruncate(fd, size)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._stat_owned(name)
        return path

    def make_child(self, path: Path, base: Path):
        name = self._name(path)
        need(name not in self.entries, "REFUSE_OWNERSHIP: child name reused")
        self._check_directory()
        original_make_child(path, base)
        return self.record_new(path)

    def remove(self, path: Path):
        """Never unlink a foreign inode; quarantine under the PINNED dirfd.

        If the source is swapped between validation and the atomic rename,
        the displaced foreign entry is retained under its quarantine name
        (diagnostic refusal), never unlinked. Check quarantine identity again
        before unlinkat. A truly malicious same-UID concurrent process still
        requires OS isolation beyond POSIX inode checks.
        """
        name = self._name(path)
        self._stat_owned(name)
        stage = ".owned-six-remove-" + secrets.token_hex(16)
        self._check_directory()
        need(stage not in os.listdir(self.dir_fd), "REFUSE_OWNERSHIP: occupied quarantine")
        os.rename(name, stage, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd)
        try:
            fd = os.open(stage, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=self.dir_fd)
            try:
                st = os.fstat(fd)
                at = os.stat(stage, dir_fd=self.dir_fd, follow_symlinks=False)
                need(
                    self._identity(st) == self.entries[name]
                    and self._identity(at) == self.entries[name]
                    and stat.S_ISREG(st.st_mode)
                    and st.st_nlink == 1,
                    "REFUSE_OWNERSHIP: source swapped during quarantine",
                )
                self._check_directory()
                os.unlink(stage, dir_fd=self.dir_fd)
            finally:
                os.close(fd)
        except BaseException:
            # Deliberately do NOT delete the quarantined file on mismatch.
            # It may belong to an adversarial replacement of the same UID.
            raise
        del self.entries[name]
        self._check_directory()

    def read_bound(self, name: str) -> bytes:
        """Use openat rather than reopen by pathname to copy bounded evidence."""
        self._stat_owned(name)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.dir_fd)
        try:
            st = os.fstat(fd)
            need(
                self._identity(st) == self.entries[name] and st.st_size <= 256 * 1024,
                "REFUSE_OWNERSHIP: foreign/oversize evidence",
            )
            with os.fdopen(fd, "rb", closefd=False) as f:
                return f.read()
        finally:
            os.close(fd)

    def cleanup(self):
        """Only named, registered inodes; no recursion or wildcard deletion."""
        self._check_directory()
        names = set(os.listdir(self.dir_fd))
        need(names == set(self.entries), "REFUSE_OWNERSHIP: unregistered/foreign directory entries")
        for name in list(reversed(self.entries)):
            self.remove(self.path / name)
        self._check_directory()
        need(not os.listdir(self.dir_fd), "REFUSE_OWNERSHIP: nonempty directory after cleanup")
        os.rmdir(self.path.name, dir_fd=self.parent_fd)


def owner() -> OwnedDirectory:
    current = _ACTIVE.get()
    need(current is not None and not current.closed, "REFUSE_OWNERSHIP: no live pinned transaction")
    current._check_directory()
    return current


def new_file(path: Path, size: int) -> Path:
    return owner().create_file(Path(path), size)


def make_child(path: Path, base: Path) -> Path:
    return owner().make_child(Path(path), Path(base))


def remove(path: Path) -> None:
    owner().remove(Path(path))


def record_created(path: Path) -> Path:
    return owner().record_new(Path(path))


def execute_preflight(template: Path, evidence: Path) -> None:
    """One synchronous process holds directory FDs for the entire experiment."""
    from gaslux_popos_six_gpt_fsck import verify_read_only_fsck
    from gaslux_popos_six_gpt_lab import (
        prepare,
        rehearse_recovery,
        verify_checkpoint,
    )

    parent = Path(os.environ["RUNNER_TEMP"])
    with OwnedDirectory.create(parent) as owned:
        try:
            work = owned.path
            plan = prepare(work, template)
            verify_checkpoint(work, template)
            before = verify_read_only_fsck(work, "before")
            recovery = rehearse_recovery(work, template)
            verify_checkpoint(work, template)
            after = verify_read_only_fsck(work, "after")
            need(
                plan["transactionId"]
                == recovery["transactionId"]
                == before["transactionId"]
                == after["transactionId"]
                and plan["manifestSha256"]
                == recovery["manifestSha256"]
                == before["manifestSha256"]
                == after["manifestSha256"]
                and before["readOnlyFsckAllPassed"]
                and after["readOnlyFsckAllPassed"],
                "REFUSE_RECOVERY_UNPROVEN: cross-checkpoint evidence disagreement",
            )
            # Copy only named JSON through FDs, never a directory glob.
            files = (
                "pop-six-transaction.json",
                "recovery-proof.json",
                "filesystem-fsck-before.json",
                "filesystem-fsck-after.json",
            )
            os.mkdir(evidence, mode=0o700)
            for name in files:
                data = owned.read_bound(name)
                fd = os.open(
                    evidence / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(fd, "wb") as out:
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
            with (evidence / "evidence.sha256").open("x") as manifest:
                for name in files:
                    digest = hashlib.sha256((evidence / name).read_bytes()).hexdigest()
                    manifest.write(f"{digest}  {name}\n")
                manifest.flush()
                os.fsync(manifest.fileno())
            print("GASLUX_POP_SIX_GPT_NO_QEMU_PROOF=1", flush=True)
        finally:
            # If another same-UID actor replaced anything, refuse cleanup.
            # Never remove a foreign/unregistered directory or its contents.
            owned.cleanup()


def main():
    import argparse
    import subprocess
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("--ovmf-template", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        need(
            args.evidence.is_absolute()
            and args.evidence.parent == Path(os.environ.get("GITHUB_WORKSPACE", "/nonexistent"))
            and args.evidence.name == "pop-six-gpt-evidence",
            "REFUSE_OWNERSHIP: foreign evidence directory",
        )
        execute_preflight(args.ovmf_template, args.evidence)
    except (
        Refusal,
        OSError,
        ValueError,
        KeyError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        print("GASLUX_POP_SIX_GPT_OWNERSHIP_REFUSED=" + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
