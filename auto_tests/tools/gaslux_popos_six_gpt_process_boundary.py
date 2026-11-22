#!/usr/bin/env python3
"""Descriptor-bound, read-only measurement boundary for six-GPT evidence.

This is NOT a sandbox for third-party GPT/QCOW2/filesystem tools and grants
no writer, boot, rollback, or release authority. Same-UID in-place mutation
and ptrace cannot be excluded by FDs or permission bits alone.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from typing import TYPE_CHECKING

from gaslux_popos_reuse_snapshot_gate import Refusal, need

if TYPE_CHECKING:
    from gaslux_popos_six_gpt_ownership import SafeWorkspace

SHA = re.compile(r"[0-9a-f]{64}\Z")
# The scripts in lab.py, fsck.py and ownership.py still invoke these by
# mutable pathname. Their safety is NOT upgraded by this read-only adapter.
UNISOLATED_EXTERNAL_COMMANDS = (
    "sgdisk",
    "sfdisk",
    "blkid",
    "mcopy",
    "mmd",
    "mkfs.fat",
    "mkfs.ext4",
    "fsck.fat",
    "e2fsck",
    "qemu-img",
    "qemu-io",
    "python-child-prepare-preflight-recover-fsck",
)


def _pinned_sha256(fd: int) -> str:
    """Read the already-open inode through pread; never reopen its pathname."""
    h = hashlib.sha256()
    offset = 0
    while True:
        data = os.pread(fd, 1024 * 1024, offset)
        if not data:
            break
        h.update(data)
        offset += len(data)
    return h.hexdigest()


def measure_pinned_evidence(workspace: SafeWorkspace, name: str) -> dict:
    """Run pinned GNU sha256sum without exposing a mutable file pathname.

    This verifies temporal *identity* of one already-open file descriptor,
    not isolation of the entire lab or immunity to same-UID in-place writes.
    """
    need(
        name
        in (
            "pop-six-transaction.json",
            "recovery-proof.json",
            "filesystem-fsck-before.json",
            "filesystem-fsck-after.json",
        ),
        "REFUSE_SUBPROCESS_BOUNDARY: only bounded evidence may be measured",
    )
    workspace.inspect()
    need(name in workspace.open_files, "REFUSE_SUBPROCESS_BOUNDARY: evidence not pinned")
    fd = workspace.open_files[name]
    info = os.fstat(fd)
    need(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == os.geteuid()
        and info.st_size > 0
        and info.st_size <= 1024 * 1024,
        "REFUSE_SUBPROCESS_BOUNDARY: foreign or invalid pinned inode",
    )
    original = (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    initial_hash = _pinned_sha256(fd)
    exe = shutil.which("sha256sum")
    need(
        exe is not None and os.path.isabs(exe) and not os.path.islink(exe),
        "REFUSE_SUBPROCESS_BOUNDARY: sha256sum unavailable/untrusted executable path",
    )
    # Private FD transport: replacing the original filename cannot redirect
    # sha256sum to a different inode. No shell, output file or QCOW2 backing.
    fd_path = f"/proc/self/fd/{fd}"
    try:
        result = subprocess.run(
            [exe, "--", fd_path],
            pass_fds=(fd,),
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("REFUSE_SUBPROCESS_BOUNDARY: pinned tool failed") from exc
    workspace.inspect()
    final = os.fstat(fd)
    now = (
        final.st_dev,
        final.st_ino,
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
    )
    need(now == original, "REFUSE_SUBPROCESS_BOUNDARY: pinned inode mutated")
    expected_output = initial_hash + "  " + fd_path + "\n"
    need(
        result.returncode == 0
        and not result.stderr
        and result.stdout == expected_output
        and SHA.fullmatch(initial_hash) is not None
        and _pinned_sha256(fd) == initial_hash,
        "REFUSE_SUBPROCESS_BOUNDARY: unstable or unauthenticated pinned digest",
    )
    return {
        "name": name,
        "sha256": initial_hash,
        "descriptorBoundReadCompleted": True,
        "pathnameReopenUsedForEvidence": False,
        "allExternalToolsIsolated": False,
        "sameUidInPlaceWriteIsolationProven": False,
        "qcow2BackingResolutionAuthenticated": False,
        "observationComplete": False,
        "distinstExecutionAuthorized": False,
        "windowsWriterAuthorized": False,
        "productionInstallationAuthorized": False,
        "releaseEligible": False,
        "stable": False,
    }
