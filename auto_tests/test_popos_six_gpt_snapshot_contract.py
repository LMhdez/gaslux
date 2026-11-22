"""P-324-01: one pinned evidence snapshot must drive parsing and export.

Tests invoke real SafeWorkspace/sha256sum/export; only the heavy six-GPT
preparation subprocesses are inert in the end-to-end fault injection.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

import gaslux_popos_six_gpt_ownership as owner  # noqa: E402
from gaslux_popos_reuse_snapshot_gate import Refusal  # noqa: E402
from gaslux_popos_six_gpt_contract import BOOLEANS, CONSENT  # noqa: E402
from gaslux_popos_six_gpt_process_boundary import measure_pinned_evidence  # noqa: E402


def valid_documents() -> dict[str, bytes]:
    tx = "11111111-1111-4111-8111-111111111111"
    manifest = "a" * 64
    plan = {
        "transactionId": tx,
        "manifestSha256": manifest,
        "partitions": [{} for _ in range(6)],
        "canaries": [{} for _ in range(7)],
        **BOOLEANS,
    }
    recovery = {
        "transactionId": tx,
        "manifestSha256": manifest,
        "ownedFaultChildReconstructedEmpty": True,
        **BOOLEANS,
    }
    fsck = {
        "transactionId": tx,
        "manifestSha256": manifest,
        "readOnlyFsckAllPassed": True,
        "filesystems": [{} for _ in range(3)],
    }
    objects = {
        "pop-six-transaction.json": plan,
        "recovery-proof.json": recovery,
        "filesystem-fsck-before.json": fsck,
        "filesystem-fsck-after.json": fsck,
    }
    return {
        name: (json.dumps(value, sort_keys=True) + "\n").encode() for name, value in objects.items()
    }


def change_in_place(
    path: Path, *, old: bytes = b'"manifestSha256": "', replacement: bytes = b"b"
) -> None:
    with path.open("r+b", buffering=0) as resource:
        data = resource.read()
        pos = data.index(old) + len(old)
        resource.seek(pos)
        assert len(replacement) == 1
        assert resource.write(replacement) == 1
        resource.flush()
        os.fsync(resource.fileno())
    assert path.stat().st_size == len(data)


class SnapshotContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="gaslux-p324-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        runner = root / "runner"
        repo = root / "repo"
        runner.mkdir(mode=0o700)
        repo.mkdir(mode=0o700)
        self.work = runner / "gaslux-pop-six-gpt-snapshot"
        self.work.mkdir(mode=0o700)
        self.evidence = repo / "pop-six-gpt-evidence"
        self.evidence.mkdir(mode=0o700)
        self.documents = valid_documents()
        for name, raw in self.documents.items():
            (self.work / name).write_bytes(raw)
        env = patch.dict(
            os.environ,
            {
                "RUNNER_TEMP": str(runner),
                "GITHUB_WORKSPACE": str(repo),
            },
        )
        env.start()
        self.addCleanup(env.stop)

    def test_red_real_old_export_must_not_publish_changed_measurement(self) -> None:
        with owner.SafeWorkspace(self.work, self.evidence) as guard:
            measured = {
                name: measure_pinned_evidence(guard, name)["sha256"] for name in owner.EVIDENCE
            }
            path = self.work / "recovery-proof.json"
            before = path.stat()
            change_in_place(path)
            after = path.stat()
            self.assertEqual(
                (before.st_dev, before.st_ino, before.st_size),
                (after.st_dev, after.st_ino, after.st_size),
            )
            try:
                guard.export()
            except Refusal:
                pass
            else:
                # RED: original code exports a newly read, unmeasured version.
                self.assertEqual(
                    hashlib.sha256(
                        (self.evidence / "recovery-proof.json").read_bytes()
                    ).hexdigest(),
                    measured["recovery-proof.json"],
                )

    def test_snapshot_positive_byte_equality_and_manifest(self) -> None:
        with owner.SafeWorkspace(self.work, self.evidence) as guard:
            snapshot = guard.capture_evidence()
            for name in owner.EVIDENCE:
                self.assertEqual(snapshot[name].payload, self.documents[name])
                self.assertEqual(
                    snapshot[name].sha256,
                    measure_pinned_evidence(guard, name)["sha256"],
                )
            guard.export(snapshot)
            for name in owner.EVIDENCE:
                exported = (self.evidence / name).read_bytes()
                self.assertEqual(exported, snapshot[name].payload)
                self.assertEqual(hashlib.sha256(exported).hexdigest(), snapshot[name].sha256)
            self.assertEqual(
                (self.evidence / "evidence.sha256").read_bytes(),
                "".join(
                    snapshot[name].sha256 + "  " + name + "\n" for name in sorted(owner.EVIDENCE)
                ).encode("ascii"),
            )

    def test_changed_same_inode_after_capture_refuses(self) -> None:
        with owner.SafeWorkspace(self.work, self.evidence) as guard:
            snapshot = guard.capture_evidence()
            inode = (self.work / "recovery-proof.json").stat().st_ino
            change_in_place(self.work / "recovery-proof.json")
            self.assertEqual((self.work / "recovery-proof.json").stat().st_ino, inode)
            with self.assertRaises(Refusal):
                guard.export(snapshot)
        self.assertFalse((self.evidence / "evidence.sha256").exists())

    def test_no_unbound_export_or_cross_workspace_snapshot(self) -> None:
        with owner.SafeWorkspace(self.work, self.evidence) as guard:
            snapshot = guard.capture_evidence()
            with self.assertRaises(Refusal):
                guard.export()
        with (
            owner.SafeWorkspace(self.work, self.evidence) as different,
            self.assertRaises(Refusal),
        ):
            different.export(snapshot)

    def test_partial_failures_never_return_success(self) -> None:
        for problem in ("ENOSPC", "EIO", "FSYNC", "CLOSE", "COLLISION", "DIRECTORY"):
            with self.subTest(problem=problem):
                # Every subtest has a new evidence directory; no cleanup by
                # pathname, including for a foreign O_EXCL collision.
                repo = self.evidence.parent.parent / ("failure-" + problem.lower())
                repo.mkdir(mode=0o700)
                evidence = repo / "pop-six-gpt-evidence"
                evidence.mkdir(mode=0o700)
                with (
                    patch.dict(os.environ, {"GITHUB_WORKSPACE": str(repo)}),
                    owner.SafeWorkspace(self.work, evidence) as guard,
                ):
                    snapshot = guard.capture_evidence()
                    if problem == "COLLISION":
                        (evidence / "pop-six-transaction.json").write_bytes(b"FOREIGN")
                        with self.assertRaises((FileExistsError, Refusal)):
                            guard.export(snapshot)
                        self.assertEqual(
                            (evidence / "pop-six-transaction.json").read_bytes(),
                            b"FOREIGN",
                        )
                    elif problem == "DIRECTORY":
                        original = repo / "detached-evidence"
                        evidence.rename(original)
                        evidence.mkdir(mode=0o700)
                        with self.assertRaises((Refusal, OSError)):
                            guard.export(snapshot)
                        self.assertFalse((original / "evidence.sha256").exists())
                    elif problem in ("ENOSPC", "EIO"):
                        code = errno.ENOSPC if problem == "ENOSPC" else errno.EIO
                        with (
                            patch.object(owner.os, "write", side_effect=OSError(code, "synthetic")),
                            self.assertRaises(OSError),
                        ):
                            guard.export(snapshot)
                    elif problem == "FSYNC":
                        with (
                            patch.object(
                                owner.os, "fsync", side_effect=OSError(errno.EIO, "fsync")
                            ),
                            self.assertRaises(OSError),
                        ):
                            guard.export(snapshot)
                    else:
                        with (
                            patch.object(
                                owner.os, "close", side_effect=OSError(errno.EIO, "close")
                            ),
                            self.assertRaises(Refusal),
                        ):
                            guard.export(snapshot)
                # A partial output (including a partial/complete manifest
                # before a later close failure) is never a successful export.
                # The workflow must upload evidence only after job SUCCESS.

    def test_real_run_parses_snapshots_and_refuses_concurrent_mutation(self) -> None:
        originals = subprocess.run
        initial = self.documents["recovery-proof.json"]
        injected = {"count": 0}
        original_loads = owner.json.loads

        def stub_heavy(command, **kwargs):
            if command[0] == sys.executable and command[1].endswith(
                ("gaslux_popos_six_gpt_lab.py", "gaslux_popos_six_gpt_fsck.py")
            ):
                return subprocess.CompletedProcess(command, 0)
            return originals(command, **kwargs)

        def mutate_after_json(raw, *args, **kwargs):
            value = original_loads(raw, *args, **kwargs)
            if isinstance(value, dict) and value.get("ownedFaultChildReconstructedEmpty"):
                injected["count"] += 1
                change_in_place(self.work / "recovery-proof.json")
            return value

        with (
            patch.dict(
                os.environ,
                {
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_ENVIRONMENT": "github-hosted",
                    "RUNNER_OS": "Linux",
                    "GITHUB_REPOSITORY": "LMhdez/gaslux",
                    "GASLUX_POP_SIX_GPT_CONSENT": CONSENT,
                },
            ),
            patch.object(owner.subprocess, "run", side_effect=stub_heavy),
            patch.object(owner.json, "loads", side_effect=mutate_after_json),
            self.assertRaises((Refusal, OSError)),
        ):
            # Real run() measures/parses four JSONs; heavy preparation is inert.
            owner.run(self.work, self.evidence, Path("/missing"))
        self.assertGreater(injected["count"], 0)
        self.assertNotEqual(
            (self.work / "recovery-proof.json").read_bytes(),
            initial,
        )
        self.assertFalse((self.evidence / "evidence.sha256").exists())

    def test_real_run_success_uses_validated_snapshot_bytes(self) -> None:
        originals = subprocess.run

        def stub_heavy(command, **kwargs):
            if command[0] == sys.executable and command[1].endswith(
                ("gaslux_popos_six_gpt_lab.py", "gaslux_popos_six_gpt_fsck.py")
            ):
                return subprocess.CompletedProcess(command, 0)
            return originals(command, **kwargs)

        output = io.StringIO()
        with (
            patch.dict(
                os.environ,
                {
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_ENVIRONMENT": "github-hosted",
                    "RUNNER_OS": "Linux",
                    "GITHUB_REPOSITORY": "LMhdez/gaslux",
                    "GASLUX_POP_SIX_GPT_CONSENT": CONSENT,
                },
            ),
            patch.object(owner.subprocess, "run", side_effect=stub_heavy),
            contextlib.redirect_stdout(output),
        ):
            owner.run(self.work, self.evidence, Path("/missing"))
        self.assertIn("GASLUX_POP_SIX_GPT_NO_QEMU_PROOF=1", output.getvalue())
        for name, raw in self.documents.items():
            self.assertEqual((self.evidence / name).read_bytes(), raw)

    def test_real_run_failed_export_never_reports_success(self) -> None:
        originals = subprocess.run

        def stub_heavy(command, **kwargs):
            if command[0] == sys.executable and command[1].endswith(
                ("gaslux_popos_six_gpt_lab.py", "gaslux_popos_six_gpt_fsck.py")
            ):
                return subprocess.CompletedProcess(command, 0)
            return originals(command, **kwargs)

        output = io.StringIO()
        with (
            patch.dict(
                os.environ,
                {
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_ENVIRONMENT": "github-hosted",
                    "RUNNER_OS": "Linux",
                    "GITHUB_REPOSITORY": "LMhdez/gaslux",
                    "GASLUX_POP_SIX_GPT_CONSENT": CONSENT,
                },
            ),
            patch.object(owner.subprocess, "run", side_effect=stub_heavy),
            patch.object(owner.os, "fsync", side_effect=OSError(errno.EIO, "injected fsync")),
            contextlib.redirect_stdout(output),
            self.assertRaises(OSError),
        ):
            owner.run(self.work, self.evidence, Path("/missing"))
        self.assertNotIn("GASLUX_POP_SIX_GPT_NO_QEMU_PROOF=1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
