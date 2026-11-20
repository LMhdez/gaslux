"""Cooperative, process-bound laboratory controller lease (never grants guest input).

A private flock prevents *cooperating* controller instances from sharing a run.
This does not exclude same-UID processes, QMP clients or other guest input paths.
"""

from __future__ import annotations

import fcntl
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .evidence import Refusal
from .lab_identity import ProcessSeal, process_seal


@dataclass
class ControllerLease:
    directory: Path
    expected: ProcessSeal
    _fd: int = -1
    _inode: tuple[int, int] | None = None
    _owner_pid: int = -1

    def __enter__(self) -> ControllerLease:
        if self._fd != -1:
            raise Refusal("Controller lease is already acquired")
        if os.geteuid() == 0:
            raise Refusal("Root cannot own an observer controller lease")
        path = self.directory
        try:
            if path.is_symlink() or path.resolve(strict=True) != path.absolute():
                raise Refusal("Noncanonical controller directory")
            info = path.stat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise Refusal("Controller directory is not private")
            if process_seal(self.expected.pid) != self.expected:
                raise Refusal("QEMU identity changed before controller lease")
            fd = os.open(
                path / ".observer-controller.lock",
                os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                identity = os.fstat(fd)
                leaf = (path / ".observer-controller.lock").lstat()
                if (
                    not stat.S_ISREG(identity.st_mode)
                    or identity.st_uid != os.geteuid()
                    or identity.st_mode & 0o077
                    or identity.st_nlink != 1
                    or (identity.st_dev, identity.st_ino) != (leaf.st_dev, leaf.st_ino)
                ):
                    raise Refusal("Controller lock is not a private regular file")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise Refusal("A second controller already holds the lease") from exc
                if process_seal(self.expected.pid) != self.expected:
                    raise Refusal("QEMU identity changed while acquiring lease")
                self._fd = fd
                self._owner_pid = os.getpid()
                self._inode = (identity.st_dev, identity.st_ino)
            except BaseException:
                os.close(fd)
                raise
        except (OSError, ValueError) as exc:
            raise Refusal("Controller lease acquisition failed closed") from exc
        return self

    def verify(self) -> None:
        if self._fd < 0 or self._owner_pid != os.getpid() or self._inode is None:
            raise Refusal("Missing or inherited controller lease")
        try:
            self_info = os.fstat(self._fd)
            named = (self.directory / ".observer-controller.lock").lstat()
            directory = self.directory.stat()
            if (
                (self_info.st_dev, self_info.st_ino) != self._inode
                or (named.st_dev, named.st_ino) != self._inode
                or not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != os.geteuid()
                or directory.st_mode & 0o077
                or process_seal(self.expected.pid) != self.expected
            ):
                raise Refusal("Controller lease or QEMU identity diverged")
        except OSError as exc:
            raise Refusal("Controller lease verification failed closed") from exc

    def __exit__(self, *_exc: object) -> None:
        if self._fd >= 0:
            fd = self._fd
            self._fd = -1
            self._inode = None
            self._owner_pid = -1
            os.close(fd)
