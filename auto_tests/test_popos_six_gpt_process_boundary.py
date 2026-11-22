"""Real same-UID substitutions against the read-only descriptor boundary."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
from gaslux_popos_reuse_snapshot_gate import Refusal  # noqa: E402
from gaslux_popos_six_gpt_ownership import SafeWorkspace  # noqa: E402
from gaslux_popos_six_gpt_process_boundary import (  # noqa: E402
    UNISOLATED_EXTERNAL_COMMANDS,
    measure_pinned_evidence,
)


class PinnedSubprocessBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pop-six-process-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = self.root / "runner"
        self.runner.mkdir(mode=0o700)
        github = self.root / "github"
        github.mkdir(mode=0o700)
        self.work = self.runner / "gaslux-pop-six-gpt-boundary"
        self.work.mkdir(mode=0o700)
        self.evidence = github / "pop-six-gpt-evidence"
        self.evidence.mkdir(mode=0o700)
        env = patch.dict(
            os.environ,
            {
                "RUNNER_TEMP": str(self.runner),
                "GITHUB_WORKSPACE": str(github),
            },
        )
        env.start()
        self.addCleanup(env.stop)
        self.name = "recovery-proof.json"
        (self.work / self.name).write_bytes(b'{"valid":false,"test":"pinned"}\n')

    def test_green_fd_read_never_grants_authority(self):
        with SafeWorkspace(self.work, self.evidence) as workspace:
            result = measure_pinned_evidence(workspace, self.name)
        self.assertEqual(
            result["sha256"],
            hashlib.sha256((self.work / self.name).read_bytes()).hexdigest(),
        )
        self.assertTrue(result["descriptorBoundReadCompleted"])
        for key in (
            "allExternalToolsIsolated",
            "sameUidInPlaceWriteIsolationProven",
            "qcow2BackingResolutionAuthenticated",
            "observationComplete",
            "distinstExecutionAuthorized",
            "windowsWriterAuthorized",
            "productionInstallationAuthorized",
            "releaseEligible",
            "stable",
        ):
            self.assertFalse(result[key])

    def test_same_uid_process_swaps_child_backing_vars_and_proof(self):
        for name in (
            "recovery-proof.json",
            "prepared-six.raw",
            "owned-six-child.qcow2",
            "ovmf-original-install.fd",
            "fault-injected-vars.fd",
            "fault-rebuilt-child.qcow2",
        ):
            with self.subTest(name=name):
                if name != self.name:
                    (self.work / name).write_bytes(b"OWNED\n")
                foreign = self.root / "foreign"
                foreign.write_bytes(b"FOREIGN\n")
                original_run = subprocess.run

                def attack(
                    command,
                    *,
                    target_name=name,
                    runner=original_run,
                    attacker_file=foreign,
                    **kwargs,
                ):
                    self.assertTrue(command[-1].startswith("/proc/self/fd/"))
                    self.assertNotIn(str(self.work / target_name), command)
                    code = (
                        "import os,sys;"
                        "os.rename(sys.argv[1],sys.argv[3]);"
                        "os.replace(sys.argv[2],sys.argv[1])"
                    )
                    runner(
                        [
                            sys.executable,
                            "-c",
                            code,
                            str(self.work / target_name),
                            str(attacker_file),
                            str(self.root / "detached"),
                        ],
                        check=True,
                        timeout=10,
                    )
                    return runner(command, **kwargs)

                with (
                    SafeWorkspace(self.work, self.evidence) as workspace,
                    patch(
                        "gaslux_popos_six_gpt_process_boundary.subprocess.run",
                        side_effect=attack,
                    ),
                    self.assertRaises((Refusal, OSError)),
                ):
                    measure_pinned_evidence(workspace, self.name)
                self.assertEqual((self.work / name).read_bytes(), b"FOREIGN\n")
                (self.work / name).unlink()
                if (self.root / "detached").exists():
                    (self.root / "detached").unlink()
                if name == self.name:
                    (self.work / name).write_bytes(b'{"valid":false,"test":"pinned"}\n')

    def test_same_uid_process_replaces_directory_during_child(self):
        original_run = subprocess.run

        def attack(command, **kwargs):
            code = "import os,sys;os.rename(sys.argv[1],sys.argv[2]);os.mkdir(sys.argv[1],0o700)"
            original_run(
                [sys.executable, "-c", code, str(self.work), str(self.root / "detached-work")],
                check=True,
                timeout=10,
            )
            return original_run(command, **kwargs)

        with (
            SafeWorkspace(self.work, self.evidence) as workspace,
            patch(
                "gaslux_popos_six_gpt_process_boundary.subprocess.run",
                side_effect=attack,
            ),
            self.assertRaises((Refusal, OSError)),
        ):
            measure_pinned_evidence(workspace, self.name)

    def test_in_place_change_and_tool_errors_refuse(self):
        original_run = subprocess.run

        def mutate(command, **kwargs):
            (self.work / self.name).write_bytes(b"MUTATED\n")
            return original_run(command, **kwargs)

        with (
            SafeWorkspace(self.work, self.evidence) as workspace,
            patch(
                "gaslux_popos_six_gpt_process_boundary.subprocess.run",
                side_effect=mutate,
            ),
            self.assertRaises(Refusal),
        ):
            measure_pinned_evidence(workspace, self.name)
        for error in (subprocess.TimeoutExpired("sha256sum", 1), OSError("missing")):
            with (
                self.subTest(error=repr(error)),
                SafeWorkspace(self.work, self.evidence) as workspace,
                patch(
                    "gaslux_popos_six_gpt_process_boundary.subprocess.run",
                    side_effect=error,
                ),
                self.assertRaises(Refusal),
            ):
                measure_pinned_evidence(workspace, self.name)

    def test_no_mutable_output_or_qcow2_backing_interface(self):
        self.assertIn("qemu-img", UNISOLATED_EXTERNAL_COMMANDS)
        self.assertIn("qemu-io", UNISOLATED_EXTERNAL_COMMANDS)
        self.assertIn("mkfs.ext4", UNISOLATED_EXTERNAL_COMMANDS)
        with SafeWorkspace(self.work, self.evidence) as workspace:
            for name in ("../../foreign", "owned-six-child.qcow2", "ovmf-original-install.fd"):
                with self.subTest(name=name), self.assertRaises(Refusal):
                    measure_pinned_evidence(workspace, name)


if __name__ == "__main__":
    unittest.main()
