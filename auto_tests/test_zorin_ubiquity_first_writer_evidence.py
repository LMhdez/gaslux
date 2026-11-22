"""Offline adversarial checks for first-writer evidence; never run ISO code."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

from zorin_ubiquity_first_writer_evidence import (
    SourceCoverageDenied,
    candidate_calls,
    lstat_member,
    parse_unsquashfs_lstat,
    reject_forged_effect_graph,
    static_shell_references,
)

COMMIT = "lib/partman/lib/commit.sh"
RESIZE = "lib/partman/lib/resize.sh"


class FirstWriterStaticEvidenceTests(unittest.TestCase):
    def test_static_calls_have_line_caller_args_but_no_runtime_proof(self):
        text = (
            "class PartedServer:\n"
            "    def select_disk(self, path):\n"
            "        self.write_line('select_disk ' + path)\n"
            "    def write_line(self, command):\n"
            "        self.pipe.write(command)\n"
        )
        report = candidate_calls(text.encode(), "parted_server.py")
        self.assertEqual(report["method"], "PYTHON_AST")
        self.assertFalse(report["runtimeReachabilityProven"])
        self.assertFalse(report["persistentWriteProven"])
        self.assertFalse(report["selectedCallsTruncated"])
        calls = report["selectedCalls"]
        self.assertTrue(
            any(
                c["caller"] == "PartedServer.select_disk" and c["callee"] == "self.write_line"
                for c in calls
            )
        )
        self.assertTrue(
            any(
                c["caller"] == "PartedServer.write_line" and c["callee"] == "self.pipe.write"
                for c in calls
            )
        )
        self.assertTrue(all(c["status"] == "STATIC_CALLSITE_NOT_EXECUTION" for c in calls))

    def test_conditional_mount_is_static_not_unconditional_disk_write(self):
        source = (
            "import subprocess\n"
            "def run(mode):\n"
            "    if mode == 'special':\n"
            "        subprocess.check_call(['mount', 'device', '/mnt/x'])\n"
        )
        result = candidate_calls(source.encode(), "ubi-partman.py")
        candidate = next(
            x for x in result["selectedCalls"] if x["callee"] == "subprocess.check_call"
        )
        self.assertEqual(candidate["enclosingIfBranches"][0]["expression"], "mode == 'special'")
        self.assertEqual(candidate["enclosingIfBranches"][0]["branch"], "if")
        self.assertFalse(result["persistentWriteProven"])

    def test_static_module_assignments_are_not_proven_disk_paths(self):
        source = b"devices = '/var/lib/partman/devices'\ndef use():\n    return devices\n"
        result = candidate_calls(source, "parted_server.py")
        self.assertEqual(result["moduleAssignments"][0]["symbol"], "devices")
        self.assertEqual(result["moduleAssignments"][0]["expression"], "'/var/lib/partman/devices'")
        self.assertFalse(result["runtimeReachabilityProven"])

    def test_parent_symlink_metadata_does_not_follow_scripts(self):
        meta = (
            "lrwxrwxrwx root/root 0 2026-11-22 14:30 "
            "squashfs-root/lib/partman/lib -> ../../usr/lib/partman/lib\n"
        )
        record = parse_unsquashfs_lstat(meta, "lib/partman/lib")
        self.assertEqual(record["type"], "SYMLINK_NOT_FOLLOWED")
        self.assertFalse(record["targetProvenanceAuthenticated"])

    def test_partman_preseed_does_not_imply_commit_or_safe_dryrun(self):
        code = b"class PartmanCommit:\n def run(self):\n  self.preseed('partman/confirm', 'true')\n"
        result = candidate_calls(code, "partman_commit.py")
        self.assertEqual(result["selectedCalls"][0]["callee"], "self.preseed")
        self.assertFalse(result["runtimeReachabilityProven"])

    def test_shell_source_is_only_static_token_evidence(self):
        source = (
            b"# mkfs.ext4 comment must be ignored\n"
            b". /lib/partman/lib/base.sh\n"
            b'mkfs.ext4 "$dev"\n'
            b'eval "$command"\n'
        )
        report = static_shell_references(source, "usr/lib/partman/lib/commit.sh")
        tokens = {x["token"] for x in report["effectCandidates"]}
        self.assertIn("mkfs.ext4", tokens)
        self.assertIn("eval", tokens)
        self.assertEqual(report["sourceReferences"][0]["expression"], "/lib/partman/lib/base.sh")
        self.assertFalse(report["sourceReferences"][0]["targetFileAuthenticated"])
        self.assertFalse(report["runtimeEffectsAuthenticated"])
        self.assertFalse(report["firstPersistentWriteVerified"])

    def test_untrusted_shell_encoding_is_not_accepted_as_code(self):
        with self.assertRaises(SourceCoverageDenied) as caught:
            static_shell_references(b"\\xff", "usr/lib/partman/lib/resize.sh")
        self.assertEqual(caught.exception.code, "E_PARTMAN_SHELL_ENCODING")

    def test_python_parse_error_fails_closed(self):
        with self.assertRaises(SourceCoverageDenied) as caught:
            candidate_calls(b"def broken(:\n", "ubi-partman.py")
        self.assertEqual(caught.exception.code, "E_UNPARSABLE_AUTHENTICATED_PYTHON")

    def test_symlink_target_is_text_only_never_resolved(self):
        output = (
            "lrwxrwxrwx root/root 0 2026-11-22 14:30 "
            "squashfs-root/lib/partman/lib/commit.sh -> ../../../share/partman/commit.sh\n"
        )
        record = parse_unsquashfs_lstat(output, COMMIT)
        self.assertEqual(record["type"], "SYMLINK_NOT_FOLLOWED")
        self.assertEqual(record["targetText"], "../../../share/partman/commit.sh")
        self.assertFalse(record["targetProvenanceAuthenticated"])

    def test_absolute_symlink_target_not_dereferenced(self):
        output = (
            "lrwxrwxrwx root/root 0 2026-11-22 14:30 "
            "squashfs-root/lib/partman/lib/resize.sh -> /usr/share/partman/resize.sh\n"
        )
        record = parse_unsquashfs_lstat(output, RESIZE)
        self.assertEqual(record["type"], "SYMLINK_NOT_FOLLOWED")
        self.assertEqual(record["targetLexicalPathUnverified"], "/usr/share/partman/resize.sh")

    def test_regular_metadata_does_not_authenticate_source(self):
        output = (
            "-rwxr-xr-x root/root 91 2026-11-22 14:30 squashfs-root/lib/partman/lib/commit.sh\n"
        )
        record = parse_unsquashfs_lstat(output, COMMIT)
        self.assertEqual(record["type"], "REGULAR_METADATA_ONLY")
        self.assertFalse(record["targetProvenanceAuthenticated"])

    def test_missing_and_ambiguous_metadata_fail_closed(self):
        self.assertEqual(parse_unsquashfs_lstat("", COMMIT)["type"], "UNRESOLVED")
        line = "lrwxrwxrwx root/root 0 2026-11-22 14:30 squashfs-root/" + COMMIT + " -> target"
        self.assertEqual(parse_unsquashfs_lstat(line + "\n" + line, COMMIT)["type"], "UNRESOLVED")

    def test_foreign_source_member_is_not_allowed(self):
        with self.assertRaises(SourceCoverageDenied) as caught:
            parse_unsquashfs_lstat("", "../commit.sh")
        self.assertEqual(caught.exception.code, "E_UNEXPECTED_PARTMAN_PATH")

    def test_lstat_uses_metadata_mode_only(self):
        line = "lrwxrwxrwx root/root 0 2026-11-22 14:30 squashfs-root/" + COMMIT + " -> fake"
        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=line.encode(), stderr=b"")
        with patch(
            "zorin_ubiquity_first_writer_evidence.subprocess.run",
            return_value=proc,
        ) as runner:
            result = lstat_member(Path("/readonly/iso/squashfs.img"), COMMIT)
        self.assertEqual(result["type"], "SYMLINK_NOT_FOLLOWED")
        call = runner.call_args.args[0]
        self.assertEqual(call[:4], ["unsquashfs", "-ll", "-processors", "2"])
        self.assertNotIn("-cat", call)

    def test_lstat_nonzero_has_no_auto_follow(self):
        proc = subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"not found")
        with patch(
            "zorin_ubiquity_first_writer_evidence.subprocess.run",
            return_value=proc,
        ):
            self.assertEqual(
                lstat_member(Path("/readonly/iso/squashfs.img"), RESIZE)["type"],
                "UNRESOLVED",
            )

    def test_lstat_overlong_output_refused(self):
        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"x" * 10000, stderr=b"")
        with patch(
            "zorin_ubiquity_first_writer_evidence.subprocess.run",
            return_value=proc,
        ):
            with self.assertRaises(SourceCoverageDenied) as caught:
                lstat_member(Path("/readonly/iso/squashfs.img"), COMMIT)
        self.assertEqual(caught.exception.code, "E_SQUASHFS_LSTAT_UNBOUNDED")

    def test_forged_runtime_effect_graph_always_rejected(self):
        for field in (
            "firstPersistentWriteVerified",
            "precommitNonMutatingVerified",
            "completeCallGraphVerified",
            "allEffectsAuthenticated",
            "runtimeCallPathVerified",
            "diskWritesAuthorized",
        ):
            with self.subTest(field=field):
                with self.assertRaises(SourceCoverageDenied) as caught:
                    reject_forged_effect_graph({field: True, "authorization": "DENY_NO_WRITER"})
                self.assertEqual(caught.exception.code, "E_FALSE_EFFECT_GRAPH")

    def test_forged_allow_is_denied_even_with_false_flags(self):
        with self.assertRaises(SourceCoverageDenied) as caught:
            reject_forged_effect_graph({"authorization": "ALLOW"})
        self.assertEqual(caught.exception.code, "E_EFFECT_GRAPH_AUTHORIZATION")

    def test_readonly_unproven_effect_graph_is_valid_as_negative_evidence(self):
        graph = {
            "authorization": "DENY_NO_WRITER",
            "firstPersistentWriteVerified": False,
            "completeCallGraphVerified": False,
            "diskWritesAuthorized": False,
        }
        reject_forged_effect_graph(deepcopy(graph))
        self.assertEqual(graph["authorization"], "DENY_NO_WRITER")


if __name__ == "__main__":
    unittest.main()
