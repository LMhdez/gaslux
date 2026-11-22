"""POP build-20 source/ELF audit: non-executable metadata and adversarial fixtures."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import gaslux_popos_build20_source_elf as audit  # noqa: E402

STATUS = (
    b"Package: unrelated\nVersion: 1\n\n"
    b"Package: distinst\nStatus: install ok installed\n"
    b"Architecture: amd64\nVersion: 0.3.2~1759348000~24.04~143114f\n"
    b"Source: distinst\nMaintainer: System76\n"
    b"Depends: libdistinst (= 0.3.2~1759348000~24.04~143114f), libc6\n\n"
)


class PackageStatusTests(unittest.TestCase):
    def test_valid_status_remains_unproven(self) -> None:
        info = audit.parse_dpkg_status(STATUS)
        self.assertEqual(info["versionGitSuffixCandidates"], ["143114f"])
        self.assertEqual(info["architecture"], "amd64")
        self.assertIn("libdistinst", info["depends"])
        self.assertFalse(info["aptOriginAuthenticated"])
        self.assertFalse(info["signedBuildinfoVerified"])
        self.assertFalse(info["sourceBuildEnvironmentReproduced"])

    def test_numeric_build_epoch_is_not_git_sha_candidate(self) -> None:
        status = STATUS.replace(b"~24.04~143114f", b"~24.04")
        info = audit.parse_dpkg_status(status)
        self.assertEqual(info["versionGitSuffixCandidates"], [])

    def test_new_source_commit_postdates_old_iso(self) -> None:
        self.assertGreater(audit.SOURCE_COMMITTED_UTC, audit.BUILD20_EARLIEST_PUBLIC_REFERENCE_UTC)

    def test_ambiguous_absent_wrong_or_corrupt_status_refuses(self) -> None:
        corrupt = (
            b"",
            b"Package: unrelated\nVersion: 1\n\n",
            STATUS + STATUS,
            STATUS.replace(b"Architecture: amd64", b"Architecture: i386"),
            STATUS.replace(b"Status: install ok installed", b"Status: deinstall ok config-files"),
            STATUS.replace(b"Version: 0.3.2", b"Version: ../0.3.2"),
            STATUS.replace(b"Version: 0.3.2", b"Version: 0.3.2\nVersion: 0.3.2"),
            STATUS.replace(b"Source: distinst", b"Source: " + b"a" * 200),
            b"\xff",
            b"Package: distinst\nBadField\n",
            b" Bad continuation\n",
        )
        for content in corrupt:
            with self.subTest(data=content[:30]), self.assertRaises(audit.Build20ProvenanceRefusal):
                audit.parse_dpkg_status(content)

    def test_missing_source_is_not_source_proof(self) -> None:
        info = audit.parse_dpkg_status(STATUS.replace(b"Source: distinst\n", b""))
        self.assertIsNone(info["sourceField"])
        self.assertFalse(info["aptOriginAuthenticated"])

    def test_reject_unbounded_input(self) -> None:
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            audit.parse_dpkg_status(b"x" * (audit.MAX_STATUS_BYTES + 1))


class TinyExtractedFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = tempfile.TemporaryDirectory(prefix="pop-b20-runner-")
        self.addCleanup(self.runner.cleanup)
        self.workspace = tempfile.TemporaryDirectory(
            prefix="gaslux-pop-build20-metadata-", dir=self.runner.name
        )
        self.addCleanup(self.workspace.cleanup)
        self.work = Path(self.workspace.name)
        self.iso = self.work / "build20.iso"
        self.elf = self.work / "distinst.elf"
        self.status = self.work / "dpkg.status"
        self.iso.write_bytes(b"SYNTHETIC-ISO-NOT-OFFICIAL")
        self.elf.write_bytes(b"SYNTHETIC-ELF-NOT-DISTINST")
        self.status.write_bytes(STATUS)
        env = patch.dict(
            os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "GITHUB_REPOSITORY": "LMhdez/gaslux",
                "RUNNER_TEMP": self.runner.name,
            },
        )
        env.start()
        self.addCleanup(env.stop)
        pins = patch.multiple(
            audit,
            PINNED_ISO_BYTES=len(self.iso.read_bytes()),
            PINNED_ISO_SHA256=hashlib.sha256(self.iso.read_bytes()).hexdigest(),
            ELF_SHA256=hashlib.sha256(self.elf.read_bytes()).hexdigest(),
        )
        pins.start()
        self.addCleanup(pins.stop)

    def inspect(self) -> dict:
        return audit.inspect_build20_extraction(self.iso, self.elf, self.status, self.work)

    def test_synthetic_positive_still_returns_unproven(self) -> None:
        report = self.inspect()
        self.assertEqual(report["result"], "SOURCE_TO_ELF_UNPROVEN")
        self.assertTrue(report["elfFullSha256Matched"])
        self.assertTrue(report["isoFullSha256Matched"])
        for field in (
            "sourceToElfCorrespondenceVerified",
            "signedBuildinfoVerified",
            "aptRepositorySnapshotVerified",
            "cargoLockOfActualBuildVerified",
            "elfBuildIdSourceBindingVerified",
            "isoGpgVerificationPerformedByWorkflow",
            "firstPersistentWriteProvenForPinnedElf",
            "firstStateChangeProvenForPinnedElf",
            "distinstExecuted",
            "distinstExecutionAuthorized",
            "productionInstallationAuthorized",
            "sameDiskDualBootVerified",
            "stable",
        ):
            self.assertIs(report[field], False, field)

    def test_wrong_elf_hash_refuses(self) -> None:
        self.elf.write_bytes(b"FOREIGN-ELF")
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            self.inspect()

    def test_wrong_iso_hash_or_size_refuses(self) -> None:
        original = self.iso.read_bytes()
        self.iso.write_bytes(b"X" + original[1:])
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            self.inspect()
        self.iso.write_bytes(original[:-1])
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            self.inspect()

    def test_duplicate_foreign_or_partial_package_refuses(self) -> None:
        self.status.write_bytes(STATUS + STATUS)
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            self.inspect()
        self.status.write_bytes(b"Package: distinst\nStatus: install ok installed\n")
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            self.inspect()

    def test_symlink_source_refuses(self) -> None:
        link = self.work / "fake.elf"
        link.symlink_to(self.elf)
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            audit.inspect_build20_extraction(self.iso, link, self.status, self.work)

    def test_non_hosted_or_foreign_workspace_refuses(self) -> None:
        with (
            patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}),
            self.assertRaises(audit.Build20ProvenanceRefusal),
        ):
            self.inspect()
        with (
            patch.dict(os.environ, {"RUNNER_TEMP": "/tmp/not-matching"}),
            self.assertRaises(audit.Build20ProvenanceRefusal),
        ):
            self.inspect()

    def test_workspace_permissions_and_filename_refuse(self) -> None:
        os.chmod(self.work, 0o755)
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            self.inspect()
        os.chmod(self.work, 0o700)
        with self.assertRaises(audit.Build20ProvenanceRefusal):
            audit.inspect_build20_extraction(
                self.iso, self.elf, self.status.parent / "missing.status", self.work
            )


if __name__ == "__main__":
    unittest.main()
