#!/usr/bin/env python3
"""Six-GPT evidence export, anchored to the original work directory FD.

No deletion: POSIX unlinkat cannot atomically assert inode identity in the
presence of hostile same-UID rename/link races. Runner disposal owns cleanup.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

FILES = (
    "pop-six-transaction.json",
    "recovery-proof.json",
    "filesystem-fsck-before.json",
    "filesystem-fsck-after.json",
)


class OwnershipRefusal(Exception):
    pass


def export_evidence(work: Path, evidence: Path, pinned: tuple[int, int]) -> None:
    """Export only if original work dir is still linked at its original path."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(work.parent, flags)
    try:
        directory = os.open(work.name, flags, dir_fd=parent)
        try:
            d = os.fstat(directory)
            if (d.st_dev, d.st_ino) != pinned or d.st_nlink == 0:
                raise OwnershipRefusal("REFUSE_IDENTITY_MISMATCH: work directory replaced")
            if not stat.S_ISDIR(d.st_mode) or stat.S_IMODE(d.st_mode) != 0o700:
                raise OwnershipRefusal("REFUSE_IDENTITY_MISMATCH: work directory permissions")
            for name in FILES:
                # The original pathname and open directory descriptor must agree.
                current = os.stat(work.name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != pinned:
                    raise OwnershipRefusal("REFUSE_IDENTITY_MISMATCH: directory renamed")
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                except FileNotFoundError:
                    continue
                try:
                    st = os.fstat(fd)
                    linked = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (
                        not stat.S_ISREG(st.st_mode)
                        or st.st_nlink != 1
                        or (st.st_dev, st.st_ino) != (linked.st_dev, linked.st_ino)
                        or st.st_size > 2_000_000
                    ):
                        raise OwnershipRefusal("REFUSE_IDENTITY_MISMATCH: foreign evidence")
                    data = bytearray()
                    while len(data) <= 2_000_000:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        data.extend(chunk)
                    if len(data) != st.st_size or len(data) > 2_000_000:
                        raise OwnershipRefusal("REFUSE_IDENTITY_MISMATCH: evidence changed")
                    # Export only: no deletion of any resource.
                    out = os.open(
                        evidence / name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600,
                    )
                    with os.fdopen(out, "wb") as dest:
                        dest.write(data)
                        dest.flush()
                        os.fsync(dest.fileno())
                finally:
                    os.close(fd)
        finally:
            os.close(directory)
    finally:
        os.close(parent)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--dev", type=int, required=True)
    p.add_argument("--ino", type=int, required=True)
    args = p.parse_args()
    try:
        export_evidence(args.work, args.evidence, (args.dev, args.ino))
    except (OwnershipRefusal, OSError) as exc:
        print(f"GASLUX_SIX_GPT_EXPORT_REFUSED={exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
