"""Only the original #264 authenticated artifact ZIP is a positive fixture.

No installer or ISO scripts are run. Negative cases mutate a PRIVATE copy
and must never be promoted into an authenticated call graph or write grant.
"""

from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

from zorin_ubiquity_source_coverage import (
    ARTIFACT_SHA256,
    CORE_SOURCES,
    MAP_SHA256,
    SourceCoverageDenied,
    enforce_no_operational_claims,
    exact_regular_bytes,
    open_pinned_archive,
    report_gap,
    source_index,
    static_python_calls,
)

ARCHIVE_ENV = "GASLUX_ZORIN_ORIGINAL_MAP_ZIP"


class ZorinSourceCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original = os.environ.get(ARCHIVE_ENV, "")
        if not original:
            raise RuntimeError("mandatory original #264 artifact ZIP is absent")
        cls.original = Path(original)
        cls.actual_map = open_pinned_archive(cls.original)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zorin-source-gap-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def rejects(self, code, method, *arguments):
        with self.assertRaises(SourceCoverageDenied) as caught:
            method(*arguments)
        self.assertEqual(caught.exception.code, code)

    def test_genuine_original_zip_matches_catalog_provenance(self):
        self.assertTrue(self.original.is_file())
        from zorin_ubiquity_source_coverage import sha

        self.assertEqual(sha(self.original.read_bytes()), ARTIFACT_SHA256)
        self.assertEqual(
            self.actual_map["isoSha256"],
            "44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5",
        )
        self.assertEqual(self.actual_map["authorization"], "DENY_NO_WRITER")

    def test_only_static_source_metadata_in_original_artifact(self):
        report = report_gap(self.actual_map)
        self.assertEqual(report["codeMapSha256"], MAP_SHA256)
        self.assertEqual(report["decision"], "ROUTE_B")
        self.assertEqual(report["classification"], "UBIQUITY_PRECOMMIT_PLAN_UNAVAILABLE")
        self.assertFalse(report["runtimeCallGraphAuthenticated"])
        self.assertFalse(report["firstPersistentMutationLocated"])
        self.assertFalse(report["nonMutatingPrecommitProven"])
        self.assertEqual(set(report["missingSourceBodies"]), set(CORE_SOURCES))
        self.assertFalse(report["productionStorageWritesAuthorized"])

    def test_old_zip_has_exact_unverified_partman_shell_references(self):
        indexed = source_index(self.actual_map)
        for script in ("lib/partman/lib/commit.sh", "lib/partman/lib/resize.sh"):
            with self.subTest(script=script):
                self.assertNotIn(script, indexed)
                self.assertIn(script, self.actual_map["unreadablePaths"])
                self.assertIsNone(report_gap(self.actual_map)["sources"][script]["knownSha256"])

    def test_historical_regular_source_hashes_are_available_but_no_bodies(self):
        indexed = source_index(self.actual_map)
        for path in CORE_SOURCES:
            if path in indexed:
                with self.subTest(path=path):
                    self.assertEqual(len(indexed[path]["sha256"]), 64)
                    self.assertGreater(indexed[path]["sizeBytes"], 0)
                    self.assertEqual(
                        report_gap(self.actual_map)["sources"][path]["status"], "BODY_NOT_AVAILABLE"
                    )

    def test_edited_archive_refused_by_full_zip_hash(self):
        edited = self.root / "tampered.zip"
        content = bytearray(self.original.read_bytes())
        content[-14] ^= 7
        edited.write_bytes(content)
        self.rejects("E_UNAUTHENTICATED_ARCHIVE", open_pinned_archive, edited)

    def test_invalid_short_fake_zip_refused(self):
        replacement = self.root / "forged.zip"
        replacement.write_bytes(b"PK\x03\x04not-a-mapping")
        self.rejects("E_UNAUTHENTICATED_ARCHIVE", open_pinned_archive, replacement)

    def test_archive_symlink_refused_without_following(self):
        original = self.root / "input.zip"
        original.write_bytes(self.original.read_bytes())
        link = self.root / "link.zip"
        link.symlink_to(original.name)
        self.rejects("E_UNTRUSTED_ARCHIVE_PATH", open_pinned_archive, link)

    def test_bad_source_blob_cannot_reproduce_pinned_hash(self):
        path = "usr/lib/ubiquity/ubiquity/components/partman_commit.py"
        spoof = {path: {"data": b"def run(): return None\n", "status": "REGULAR_HASH_MATCHED"}}
        with self.assertRaises(SourceCoverageDenied) as caught:
            report_gap(self.actual_map, source_bodies=spoof)
        self.assertEqual(caught.exception.code, "E_SOURCE_HASH_OR_SIZE_MISMATCH")

    def test_symlink_or_missing_member_never_treated_as_code(self):
        nonexistent = self.root / "not-a-squashfs.squashfs"
        content, status = exact_regular_bytes(
            nonexistent,
            "lib/partman/lib/commit.sh",
            None,
        )
        self.assertIsNone(content)
        self.assertEqual(status, "MISSING_OR_NONREGULAR")

    def test_attacker_cannot_add_source_outside_allowlist(self):
        malicious = {"../partman.sh": {"data": b"echo unsafe", "status": "REGULAR_NEWLY_ATTESTED"}}
        with self.assertRaises(SourceCoverageDenied) as caught:
            report_gap(self.actual_map, source_bodies=malicious)
        self.assertEqual(caught.exception.code, "E_SOURCE_PATH_NOT_ALLOWED")

    def test_historical_module_not_attested_as_regular_refused(self):
        changed = deepcopy(self.actual_map)
        entry = next(m for m in changed["modules"] if m["path"] == "usr/bin/ubiquity")
        entry["ownerVerified"] = False
        with self.assertRaises(SourceCoverageDenied) as caught:
            source_index(changed)
        self.assertEqual(caught.exception.code, "E_SOURCE_OWNER_UNVERIFIED")

    def test_missing_unverified_partman_script_is_explicit_blocker(self):
        changed = deepcopy(self.actual_map)
        changed["unreadablePaths"].remove("lib/partman/lib/commit.sh")
        with self.assertRaises(SourceCoverageDenied) as caught:
            source_index(changed)
        self.assertEqual(caught.exception.code, "E_UNACCOUNTED_SOURCE")

    def test_false_complete_action_graph_is_never_accepted(self):
        for field in (
            "completeActionGraph",
            "dryRunVerified",
            "firstWriteLocated",
            "writerFenceActive",
            "precommitFullyObserved",
        ):
            with self.subTest(field=field):
                self.rejects(
                    "E_FALSE_ACTION_GRAPH",
                    enforce_no_operational_claims,
                    {field: True},
                )

    def test_malicious_unobserved_operations_are_not_accepted(self):
        for field in ("proposedDiskWrites", "efiWrites", "grubWrites"):
            with self.subTest(field=field):
                self.rejects(
                    "E_UNTRUSTED_ACTION_GRAPH",
                    enforce_no_operational_claims,
                    {field: []},
                )

    def test_ast_is_static_not_proof_of_first_write(self):
        result = static_python_calls(
            b"def choose():\n    subprocess.run(['parted', '--script'])\n", "test.py"
        )
        self.assertEqual(result["parse"], "STATIC_AST_ONLY")
        self.assertEqual(len(result["callSites"]), 1)
        self.assertEqual(result["callSites"][0]["basis"], "STATIC_AST_CALLSITE_NOT_A_TRACE")
        self.assertFalse("firstWriteLocated" in result)

    def test_incomplete_source_set_does_not_grant_permission(self):
        partial = report_gap(self.actual_map)
        for name in (
            "productionStorageWritesAuthorized",
            "windowsEspWriteAuthorized",
            "sameDiskDualBootVerified",
            "windowsInPlaceRollbackProven",
            "stable",
        ):
            with self.subTest(field=name):
                self.assertIs(partial[name], False)


if __name__ == "__main__":
    unittest.main()
