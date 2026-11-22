#!/usr/bin/env python3
"""Pop six-GPT synthetic workspace FD boundary, read-only and DENY-ONLY.

The canonical GPT parser lives unchanged in assets/live. This adapter binds
its input descriptor to an owned, private runner directory and exact file.
No authority is conveyed to installers, block devices or subprocess writers.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

from gaslux_popos_reuse_snapshot_gate import Refusal, need
from gaslux_popos_six_gpt_contract import COUNT, DISK_GUID, PARTS, SECTOR, SIZE

# The exact upstream blob is imported; do not fork/reimplement GPT parsing.
_CANONICAL_DIR = Path(__file__).resolve().parents[2] / "assets" / "live"
sys.path.insert(0, str(_CANONICAL_DIR))
from libertix_disk_identity_gate import (  # noqa: E402
    DiskIdentityError,
    assert_snapshot_matches,
    inspect_gpt_fd,
)

FILE_NAME = "prepared-six.raw"
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _identity(item: os.stat_result) -> tuple[int, int]:
    return item.st_dev, item.st_ino


def _exact_pread(fd: int, offset: int, size: int) -> bytes:
    """Finite, exact, read-only region from an already pinned descriptor."""
    need(
        type(offset) is int
        and type(size) is int
        and offset >= 0
        and size > 0
        and offset + size <= SIZE,
        "REFUSE_GPT_FD: invalid region",
    )
    data = bytearray()
    while len(data) < size:
        try:
            chunk = os.pread(fd, min(1024 * 1024, size - len(data)), offset + len(data))
        except OSError as exc:
            raise Refusal("REFUSE_GPT_FD: FD read failed") from exc
        need(bool(chunk), "REFUSE_GPT_FD: short read")
        data.extend(chunk)
    return bytes(data)


def _expected() -> dict:
    """Only synthetic geometry and GUIDs pinned by the existing Pop contract."""
    return {
        "partitionStyle": "GPT",
        "partitionTableId": "gpt:" + DISK_GUID,
        "sizeBytes": SIZE,
        "logicalSectorSizeBytes": SECTOR,
        "partitions": [
            {
                "number": item.index,
                "typeGuid": item.type_guid,
                "partGuid": item.partuuid,
                "offsetBytes": item.start * SECTOR,
                "sizeBytes": item.count * SECTOR,
                "attributes": 0,
            }
            for item in PARTS
        ],
    }


class PinnedSixGpt:
    """Own workspace and regular-file FDs; never authenticate an arbitrary FD.

    This is local runner provenance, NOT authentication of a physical disk,
    QEMU guest, backing-chain history or the caller's Python process.
    """

    def __init__(self, work: Path) -> None:
        work = Path(work)
        root = Path(os.environ.get("RUNNER_TEMP", ""))
        need(
            O_DIRECTORY != 0
            and O_NOFOLLOW != 0
            and work.is_absolute()
            and work.parent == root
            and root.is_absolute()
            and root.is_dir()
            and not root.is_symlink()
            and Path(os.path.realpath(root)) == root
            and work.name.startswith("gaslux-pop-six-gpt-")
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux",
            "REFUSE_GPT_FD: unauthenticated synthetic runner workspace",
        )
        self.work = work
        self.parent_fd = -1
        self.work_fd = -1
        self.fd = -1
        try:
            self.parent_fd = os.open(root, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            self.work_fd = os.open(
                work.name,
                os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
                dir_fd=self.parent_fd,
            )
            work_stat = os.fstat(self.work_fd)
            need(
                stat.S_ISDIR(work_stat.st_mode)
                and work_stat.st_uid == os.geteuid()
                and stat.S_IMODE(work_stat.st_mode) == 0o700,
                "REFUSE_GPT_FD: workspace not private",
            )
            self.work_identity = _identity(work_stat)
            self.fd = os.open(
                FILE_NAME,
                os.O_RDONLY | O_NOFOLLOW,
                dir_fd=self.work_fd,
            )
            item = os.fstat(self.fd)
            need(
                stat.S_ISREG(item.st_mode)
                and item.st_uid == os.geteuid()
                and item.st_nlink == 1
                and item.st_size == SIZE
                and stat.S_IMODE(item.st_mode) & 0o022 == 0,
                "REFUSE_GPT_FD: foreign or invalid synthetic RAW",
            )
            self.identity = _identity(item)
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self) -> os.stat_result:
        """Refuse renamed parent, replaced file, symlink, close and geometry drift."""
        need(
            self.parent_fd >= 0 and self.work_fd >= 0 and self.fd >= 0,
            "REFUSE_GPT_FD: descriptor closed",
        )
        try:
            pinned_work = os.fstat(self.work_fd)
            visible_work = os.stat(
                self.work.name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
            pinned = os.fstat(self.fd)
            visible = os.stat(FILE_NAME, dir_fd=self.work_fd, follow_symlinks=False)
        except OSError as exc:
            raise Refusal("REFUSE_GPT_FD: descriptor or workspace unavailable") from exc
        need(
            stat.S_ISDIR(pinned_work.st_mode)
            and _identity(pinned_work) == self.work_identity
            and _identity(visible_work) == self.work_identity
            and stat.S_ISREG(pinned.st_mode)
            and stat.S_ISREG(visible.st_mode)
            and _identity(pinned) == self.identity
            and _identity(visible) == self.identity
            and pinned.st_uid == os.geteuid()
            and pinned.st_nlink == 1
            and pinned.st_size == SIZE
            and stat.S_IMODE(pinned.st_mode) & 0o022 == 0,
            "REFUSE_GPT_FD: workspace RAW identity or geometry changed",
        )
        return pinned

    def inspect(self, *, expected_sector: int = SECTOR, supplied_fd: int | None = None) -> dict:
        """Derive ALL authoritative GPT fields and region digests from ONE FD."""
        need(
            supplied_fd is None or (type(supplied_fd) is int and supplied_fd == self.fd),
            "REFUSE_GPT_FD: foreign descriptor",
        )
        need(
            type(expected_sector) is int and expected_sector == SECTOR,
            "REFUSE_GPT_FD: sector geometry mismatch",
        )
        first_meta = self.verify()
        original = (
            first_meta.st_dev,
            first_meta.st_ino,
            first_meta.st_size,
            first_meta.st_mtime_ns,
            first_meta.st_ctime_ns,
        )
        try:
            first = inspect_gpt_fd(self.fd, logical_sector_size=expected_sector)
            assert_snapshot_matches(_expected(), first)
            pmbr = _exact_pread(self.fd, 0, 34 * SECTOR)
            backup = _exact_pread(self.fd, (COUNT - 33) * SECTOR, 33 * SECTOR)
            second = inspect_gpt_fd(self.fd, logical_sector_size=expected_sector)
            assert_snapshot_matches(first, second)
        except (DiskIdentityError, OSError, ValueError) as exc:
            raise Refusal("REFUSE_GPT_FD: canonical GPT/CRC/geometry invalid") from exc
        final_meta = self.verify()
        need(
            (
                final_meta.st_dev,
                final_meta.st_ino,
                final_meta.st_size,
                final_meta.st_mtime_ns,
                final_meta.st_ctime_ns,
            )
            == original
            and _exact_pread(self.fd, 0, 34 * SECTOR) == pmbr
            and _exact_pread(self.fd, (COUNT - 33) * SECTOR, 33 * SECTOR) == backup,
            "REFUSE_GPT_FD: mutated pinned GPT",
        )
        return {
            "diskGuid": DISK_GUID,
            "primaryAndBackupCrcVerified": True,
            "pmbrAndPrimary": hashlib.sha256(pmbr).hexdigest(),
            "secondary": hashlib.sha256(backup).hexdigest(),
            "partitions": [p.as_dict() for p in PARTS],
        }

    def close(self) -> None:
        for name in ("fd", "work_fd", "parent_fd"):
            fd = getattr(self, name, -1)
            if fd >= 0:
                setattr(self, name, -1)
                os.close(fd)

    def __enter__(self) -> PinnedSixGpt:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def inspect_owned_six_gpt(work: Path) -> dict:
    with PinnedSixGpt(work) as pinned:
        return pinned.inspect()
