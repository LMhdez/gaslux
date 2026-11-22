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
from dataclasses import dataclass
from pathlib import Path

from gaslux_popos_reuse_snapshot_gate import Refusal, need
from gaslux_popos_six_gpt_contract import BOOLEANS, CONSENT
from gaslux_popos_six_gpt_process_boundary import measure_pinned_evidence

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




@dataclass(frozen=True, slots=True)
class EvidenceDocument:
    """One copy of exactly the bytes accepted by pinned FD measurement."""

    name: str
    payload: bytes
    sha256: str
    resource_identity: tuple[int, int]
    metadata: tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    """Closed, immutable evidence set; never represents a pathname re-read."""

    documents: tuple[EvidenceDocument, ...]
    owner_token: object

    def __getitem__(self, name: str) -> EvidenceDocument:
        for document in self.documents:
            if document.name == name:
                return document
        raise Refusal("REFUSE_SNAPSHOT_DIVERGED: unbound document requested")


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
        self._snapshot_token = object()
        self.inventory: dict[str, tuple[int, int]] = {}
        self.open_files: dict[str, int] = {}
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
            self.evidence_fd = os.open(self.evidence, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
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
        # Keeping the original file inode open prevents inode reuse between stages.
        for fd in self.open_files.values():
            os.close(fd)
        self.open_files.clear()
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
            and identity(os.stat(self.work.name, dir_fd=self.parent_fd, follow_symlinks=False))
            == self.work_identity
            and identity(os.fstat(self.evidence_fd)) == self.evidence_identity
            and identity(os.stat(self.evidence, follow_symlinks=False)) == self.evidence_identity,
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
                if prior is not None:
                    pinned = os.fstat(self.open_files[name])
                    need(
                        identity(pinned) == prior and pinned.st_nlink == 1,
                        "REFUSE_IDENTITY_MISMATCH: pinned inode detached",
                    )
                else:
                    self.open_files[name] = descriptor
                    descriptor = -1
                self.inventory[name] = identity(info)
            finally:
                if descriptor != -1:
                    os.close(descriptor)
        need(
            all(name in observed for name in self.inventory),
            "REFUSE_IDENTITY_MISMATCH: previously owned resource missing",
        )
        self.check_directories()

    def evidence_bytes(self, name: str) -> bytes:
        """Bounded content read exclusively through the original pinned inode."""
        need(name in EVIDENCE and name in self.inventory, "REFUSE_IDENTITY_MISMATCH: missing proof")
        self.inspect()
        fd = self.open_files[name]
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and identity(info) == self.inventory[name]
            and 0 < info.st_size < 1024 * 1024,
            "REFUSE_IDENTITY_MISMATCH: proof inode swapped/oversized",
        )
        before = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        chunks = []
        offset = 0
        while offset < info.st_size:
            block = os.pread(fd, min(65536, info.st_size - offset), offset)
            need(bool(block), "REFUSE_SNAPSHOT_DIVERGED: short pinned proof read")
            chunks.append(block)
            offset += len(block)
        current = os.fstat(fd)
        need(
            (current.st_size, current.st_mtime_ns, current.st_ctime_ns) == before
            and offset == before[0]
            and identity(current) == self.inventory[name],
            "REFUSE_SNAPSHOT_DIVERGED: source changed during pinned read",
        )
        self.inspect()
        return b"".join(chunks)

    def capture_evidence(self) -> EvidenceSnapshot:
        """Measure once, freeze bytes once, and reject intermediate mutations."""
        self.inspect()
        captured = []
        for name in EVIDENCE:
            measurement = measure_pinned_evidence(self, name)
            data = self.evidence_bytes(name)
            digest = hashlib.sha256(data).hexdigest()
            need(
                measurement["sha256"] == digest
                and measurement["descriptorBoundReadCompleted"] is True
                and measurement["distinstExecutionAuthorized"] is False
                and measurement["observationComplete"] is False,
                "REFUSE_SNAPSHOT_DIVERGED: measured bytes differ from captured bytes",
            )
            info = os.fstat(self.open_files[name])
            captured.append(
                EvidenceDocument(
                    name, data, digest, identity(info),
                    (info.st_size, info.st_mtime_ns, info.st_ctime_ns),
                )
            )
        snapshot = EvidenceSnapshot(tuple(captured), self._snapshot_token)
        self.verify_snapshot(snapshot)
        return snapshot

    def verify_snapshot(self, snapshot: EvidenceSnapshot) -> None:
        """Assert all source inodes and bytes still match the frozen transaction."""
        need(
            isinstance(snapshot, EvidenceSnapshot)
            and snapshot.owner_token is self._snapshot_token
            and tuple(doc.name for doc in snapshot.documents) == EVIDENCE,
            "REFUSE_SNAPSHOT_DIVERGED: foreign/incomplete evidence snapshot",
        )
        self.inspect()
        for doc in snapshot.documents:
            need(
                type(doc.payload) is bytes
                and type(doc.sha256) is str
                and hashlib.sha256(doc.payload).hexdigest() == doc.sha256
                and len(doc.payload) == doc.metadata[0],
                "REFUSE_SNAPSHOT_DIVERGED: invalid frozen evidence bytes",
            )
            info = os.fstat(self.open_files[doc.name])
            need(
                identity(info) == doc.resource_identity
                and info.st_nlink == 1
                and info.st_uid == os.geteuid()
                and (info.st_size, info.st_mtime_ns, info.st_ctime_ns) == doc.metadata
                and self.evidence_bytes(doc.name) == doc.payload,
                "REFUSE_SNAPSHOT_DIVERGED: source changed since measurement",
            )
        self.inspect()

    def _check_exported(self, name: str, fd: int, expected: bytes) -> None:
        """Verify bytes at the created inode, never a substituted output pathname."""
        original = os.fstat(fd)
        visible = os.stat(name, dir_fd=self.evidence_fd, follow_symlinks=False)
        need(
            stat.S_ISREG(original.st_mode)
            and original.st_uid == os.geteuid()
            and original.st_nlink == 1
            and identity(original) == identity(visible)
            and original.st_size == len(expected),
            "REFUSE_SNAPSHOT_DIVERGED: exported output replaced",
        )
        result = bytearray()
        while len(result) < len(expected):
            chunk = os.pread(fd, min(65536, len(expected) - len(result)), len(result))
            need(bool(chunk), "REFUSE_SNAPSHOT_DIVERGED: truncated exported bytes")
            result.extend(chunk)
        need(
            bytes(result) == expected
            and hashlib.sha256(result).digest() == hashlib.sha256(expected).digest(),
            "REFUSE_SNAPSHOT_DIVERGED: exported bytes not equal to frozen proof",
        )

    def export(self, snapshot: EvidenceSnapshot | None = None) -> None:
        """Export ONLY validated frozen bytes; no fallback to file re-reading."""
        need(snapshot is not None, "REFUSE_SNAPSHOT_DIVERGED: snapshot required for export")
        self.verify_snapshot(snapshot)
        opened: list[tuple[str, int, bytes]] = []
        try:
            for doc in snapshot.documents:
                self.verify_snapshot(snapshot)
                fd = os.open(
                    doc.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
                    0o600, dir_fd=self.evidence_fd,
                )
                opened.append((doc.name, fd, doc.payload))
                with os.fdopen(fd, "wb", closefd=False) as output:
                    need(
                        output.write(doc.payload) == len(doc.payload),
                        "REFUSE_SNAPSHOT_DIVERGED: short exported write",
                    )
                    output.flush()
                    os.fsync(fd)
                self._check_exported(doc.name, fd, doc.payload)
            self.verify_snapshot(snapshot)
            manifest = "".join(
                doc.sha256 + "  " + doc.name + "\n"
                for doc in sorted(snapshot.documents, key=lambda item: item.name)
            ).encode("ascii")
            fd = os.open(
                "evidence.sha256",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
                0o600, dir_fd=self.evidence_fd,
            )
            opened.append(("evidence.sha256", fd, manifest))
            index = 0
            while index < len(manifest):
                written = os.write(fd, manifest[index:])
                need(written > 0, "REFUSE_SNAPSHOT_DIVERGED: short manifest write")
                index += written
            os.fsync(fd)
            self._check_exported("evidence.sha256", fd, manifest)
            self.verify_snapshot(snapshot)
            for name, export_fd, payload in opened:
                self._check_exported(name, export_fd, payload)
            self.check_directories()
            os.fsync(self.evidence_fd)
        finally:
            # No pathname removal. A close failure refuses success, and files
            # remain available for runner teardown, never treated as rollback.
            failure = None
            for _, fd, _ in opened:
                try:
                    os.close(fd)
                except OSError as exc:
                    if failure is None:
                        failure = exc
            if failure is not None:
                raise Refusal(
                    "REFUSE_SNAPSHOT_DIVERGED: export descriptor close failed"
                ) from failure


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
            subprocess.run([sys.executable, str(tools / tool), *args], check=True, timeout=2400)
            workspace.inspect()
        # Resource-bound read-only subprocess stage: a swapped pathname cannot
        # make a foreign evidence file pass as a recovered artifact. Existing
        # tool calls in the lab remain UNISOLATED and DENY-ONLY.
        snapshot = workspace.capture_evidence()
        plan = json.loads(snapshot["pop-six-transaction.json"].payload)
        recovery = json.loads(snapshot["recovery-proof.json"].payload)
        need(
            plan["transactionId"] == recovery["transactionId"]
            and plan["manifestSha256"] == recovery["manifestSha256"]
            and len(plan["partitions"]) == 6
            and len(plan["canaries"]) == 7
            and recovery["ownedFaultChildReconstructedEmpty"] is True
            and all(plan[k] is recovery[k] is False for k in BOOLEANS),
            "REFUSE_RECOVERY_UNPROVEN: inconsistent recovery plan",
        )
        for phase in ("before", "after"):
            result = json.loads(snapshot["filesystem-fsck-" + phase + ".json"].payload)
            need(
                result["readOnlyFsckAllPassed"] is True
                and len(result["filesystems"]) == 3
                and result["transactionId"] == plan["transactionId"]
                and result["manifestSha256"] == plan["manifestSha256"],
                "REFUSE_RECOVERY_UNPROVEN: incomplete synthetic fsck",
            )
        workspace.export(snapshot)
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
