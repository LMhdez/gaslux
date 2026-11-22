#!/usr/bin/env python3
"""Fail-closed six-GPT lab resource monitor; NEVER delete files by pathname.

The private runner itself disposes of this entire ephemeral workspace. In
particular, no same-UID pathname race can make this monitor unlink a foreign
file: it performs NO unlink, rmdir, rename or recursive cleanup. This does
not protect unrelated subprocess writers from a hostile same-UID process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from gaslux_popos_reuse_snapshot_gate import Refusal, need
from gaslux_popos_six_gpt_contract import BOOLEANS, CONSENT

# Closed inventory of all files the six-GPT lab may create. Not a glob/delete
# authority. Temporary files are accounted for, including on incomplete runs.
NAMES = frozenset(
    {
        "prepared-six.raw",
        "owned-six-child.qcow2",
        "pop-six-transaction.json",
        "transaction.id",
        "ovmf-original-install.fd",
        "ovmf-original-firstboot.fd",
        "synthetic-esp-marker.tmp",
        "readback-protected-esp-canary.tmp",
        "fault-injected-child.qcow2",
        "fault-rebuilt-child.qcow2",
        "fault-injected-vars.fd",
        "fault-restored-vars.fd",
        "recovery-proof.json",
        "filesystem-fsck-before.json",
        "filesystem-fsck-after.json",
    }
    | {
        "fsck-" + phase + "-" + str(number) + ".img"
        for phase in ("before", "after")
        for number in (1, 5, 6)
    }
)
EVIDENCE = (
    "pop-six-transaction.json",
    "recovery-proof.json",
    "filesystem-fsck-before.json",
    "filesystem-fsck-after.json",
)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


class SafeWorkspace:
    """Pin runner parent, workspace and evidence directory by open descriptors."""

    def __init__(self, work: Path, evidence: Path):
        self.work = Path(work)
        self.evidence = Path(evidence)
        self.parent_fd = -1
        self.work_fd = -1
        self.evidence_fd = -1
        self.inventory: dict[str, tuple[int, int]] = {}
        try:
            need(
                self.work.is_absolute()
                and self.work.parent == Path(os.environ.get("RUNNER_TEMP", "/missing"))
                and self.work.name.startswith("gaslux-pop-six-gpt-")
                and self.evidence.is_absolute()
                and self.evidence.name == "pop-six-gpt-evidence"
                and self.evidence.parent == Path(os.environ.get("GITHUB_WORKSPACE", "/missing")),
                "REFUSE_IDENTITY_MISMATCH: foreign runner resource path",
            )
            self.parent_fd = os.open(self.work.parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            self.work_fd = os.open(
                self.work.name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=self.parent_fd
            )
            self.evidence_fd = os.open(
                self.evidence, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW
            )
            for fd in (self.work_fd, self.evidence_fd):
                item = os.fstat(fd)
                need(
                    stat.S_ISDIR(item.st_mode)
                    and item.st_uid == os.geteuid()
                    and stat.S_IMODE(item.st_mode) == 0o700,
                    "REFUSE_IDENTITY_MISMATCH: directory not private",
                )
            self.work_identity = identity(os.fstat(self.work_fd))
            self.evidence_identity = identity(os.fstat(self.evidence_fd))
            self.parent_identity = identity(os.fstat(self.parent_fd))
            self.inspect()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        for name in ("work_fd", "evidence_fd", "parent_fd"):
            fd = getattr(self, name, -1)
            if fd != -1:
                os.close(fd)
                setattr(self, name, -1)
        # Deliberately NO filesystem deletion, even on success.

    def __enter__(self) -> SafeWorkspace:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def check_directories(self) -> None:
        need(
            identity(os.fstat(self.parent_fd)) == self.parent_identity
            and identity(os.stat(self.work.parent, follow_symlinks=False)) == self.parent_identity
            and identity(os.fstat(self.work_fd)) == self.work_identity
            and identity(
                os.stat(self.work.name, dir_fd=self.parent_fd, follow_symlinks=False)
            )
            == self.work_identity
            and identity(os.fstat(self.evidence_fd)) == self.evidence_identity
            and identity(os.stat(self.evidence, follow_symlinks=False))
            == self.evidence_identity,
            "REFUSE_IDENTITY_MISMATCH: directory replaced",
        )

    def inspect(self) -> None:
        self.check_directories()
        observed = set(os.listdir(self.work_fd))
        need(
            all(
                name in NAMES
                or re.fullmatch(r"readback-protected-esp-canary-[0-9a-f]{32}\.tmp", name)
                for name in observed
            ),
            "REFUSE_IDENTITY_MISMATCH: foreign lab resource name",
        )
        for name in observed:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NONBLOCK | O_NOFOLLOW, dir_fd=self.work_fd
            )
            try:
                info = os.fstat(descriptor)
                path_info = os.stat(name, dir_fd=self.work_fd, follow_symlinks=False)
                need(
                    stat.S_ISREG(info.st_mode)
                    and info.st_uid == os.geteuid()
                    and info.st_nlink == 1
                    and identity(info) == identity(path_info),
                    "REFUSE_IDENTITY_MISMATCH: symlink/hardlink/replaced file",
                )
                prior = self.inventory.get(name)
                need(
                    prior is None or prior == identity(info),
                    "REFUSE_IDENTITY_MISMATCH: resource inode substituted",
                )
                self.inventory[name] = identity(info)
            finally:
                os.close(descriptor)
        need(
            all(name in observed for name in self.inventory),
            "REFUSE_IDENTITY_MISMATCH: previously owned resource missing",
        )
        self.check_directories()

    def evidence_bytes(self, name: str) -> bytes:
        need(name in EVIDENCE and name in self.inventory, "REFUSE_IDENTITY_MISMATCH: missing proof")
        self.inspect()
        fd = os.open(name, os.O_RDONLY | O_NOFOLLOW, dir_fd=self.work_fd)
        try:
            info = os.fstat(fd)
            need(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and identity(info) == self.inventory[name]
                and 0 < info.st_size < 1024 * 1024,
                "REFUSE_IDENTITY_MISMATCH: proof file swapped/oversized",
            )
            data = bytearray()
            while len(data) < info.st_size:
                block = os.read(fd, min(65536, info.st_size - len(data)))
                need(bool(block), "REFUSE_IDENTITY_MISMATCH: truncated proof")
                data.extend(block)
            need(os.fstat(fd).st_size == len(data), "REFUSE_IDENTITY_MISMATCH: proof mutated")
            self.check_directories()
            return bytes(data)
        finally:
            os.close(fd)

    def export(self) -> None:
        docs = {name: self.evidence_bytes(name) for name in EVIDENCE}
        self.inspect()
        for name, data in docs.items():
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
                0o600, dir_fd=self.evidence_fd,
            )
            try:
                with os.fdopen(fd, "wb", closefd=False) as out:
                    out.write(data)
                    out.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
        digest = "".join(
            hashlib.sha256(docs[name]).hexdigest() + "  " + name + "\n"
            for name in sorted(docs)
        ).encode("ascii")
        fd = os.open(
            "evidence.sha256", os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
            0o600, dir_fd=self.evidence_fd,
        )
        try:
            os.write(fd, digest)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.check_directories()


def run(work: Path, evidence: Path, template: Path) -> None:
    need(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("GASLUX_POP_SIX_GPT_CONSENT") == CONSENT,
        "REFUSE_IDENTITY_MISMATCH: no-writer hosted consent missing",
    )
    tools = Path(__file__).resolve().parent
    with SafeWorkspace(work, evidence) as workspace:
        base_args = ("--work", str(work), "--ovmf-template", str(template))
        tasks = (
            ("gaslux_popos_six_gpt_lab.py", ("prepare", *base_args)),
            ("gaslux_popos_six_gpt_lab.py", ("preflight", *base_args)),
            ("gaslux_popos_six_gpt_fsck.py", ("--work", str(work), "--phase", "before")),
            ("gaslux_popos_six_gpt_lab.py", ("recover", *base_args)),
            ("gaslux_popos_six_gpt_lab.py", ("preflight", *base_args)),
            ("gaslux_popos_six_gpt_fsck.py", ("--work", str(work), "--phase", "after")),
        )
        for tool, args in tasks:
            workspace.inspect()
            subprocess.run(
                [sys.executable, str(tools / tool), *args], check=True, timeout=2400
            )
            workspace.inspect()
        plan = json.loads(workspace.evidence_bytes("pop-six-transaction.json"))
        recovery = json.loads(workspace.evidence_bytes("recovery-proof.json"))
        need(
            plan["transactionId"] == recovery["transactionId"]
            and plan["manifestSha256"] == recovery["manifestSha256"]
            and len(plan["partitions"]) == 6
            and len(plan["canaries"]) == 7
            and recovery["ownedFaultChildReconstructedEmpty"] is True
            and all(
                plan[k] is recovery[k] is False for k in BOOLEANS
            ),
            "REFUSE_RECOVERY_UNPROVEN: inconsistent recovery plan",
        )
        for phase in ("before", "after"):
            result = json.loads(
                workspace.evidence_bytes("filesystem-fsck-" + phase + ".json")
            )
            need(
                result["readOnlyFsckAllPassed"] is True
                and len(result["filesystems"]) == 3
                and result["transactionId"] == plan["transactionId"]
                and result["manifestSha256"] == plan["manifestSha256"],
                "REFUSE_RECOVERY_UNPROVEN: incomplete synthetic fsck",
            )
        workspace.export()
    print("GASLUX_POP_SIX_GPT_NO_QEMU_PROOF=1", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run",))
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--ovmf-template", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args.work, args.evidence, args.ovmf_template)
    except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("GASLUX_POP_SIX_GPT_OWNERSHIP_REFUSED=" + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
