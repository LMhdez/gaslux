"""Read-only archive manifest parser regressions."""
import importlib.util
from pathlib import Path
import unittest

p = Path(__file__).resolve().parent / "tools/gaslux_archive_history_verifier.py"
spec = importlib.util.spec_from_file_location("archive_dag_verifier", p)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ArchiveVerifierContracts(unittest.TestCase):
    def test_exact_source_identity_and_no_prod_merge(self):
        body = ("Source-ref: refs/heads/feature/legacy-lab\n"
                "Source-sha: " + "a" * 40 + "\n"
                "Archive-only: no experimental code included in working tree\n"
                "Production-merge: false\n")
        self.assertEqual(mod.source_message(body),
                         ("feature/legacy-lab", "a" * 40))

    def test_pr216_history_is_pinned(self):
        self.assertEqual(mod.EXPECTED_SOURCES, 114)
        body = (
            "Source-ref: refs/heads/" + mod.PR216_REF + "\\n"
            "Source-sha: " + mod.PR216_SHA + "\\n"
            "Archive-only: no experimental code included in working tree\\n"
            "Production-merge: false\\n"
        )
        self.assertEqual(mod.source_message(body),
                         (mod.PR216_REF, mod.PR216_SHA))
        self.assertEqual(mod.PR216_ARCHIVE_COMMIT,
                         "4c955ed329baf986e5e5a1d40258d7815c124dcd")

    def test_missing_no_production_claim_denied(self):
        with self.assertRaisesRegex(ValueError, "no-production"):
            mod.source_message("Source-ref: refs/heads/a\nSource-sha: " + "a" * 40)

    def test_archive_and_automation_refs_denied(self):
        for prefix in ("archive/", "automation/"):
            body = ("Source-ref: refs/heads/" + prefix + "internal\n"
                    "Source-sha: " + "b" * 40 + "\n"
                    "Archive-only: no experimental code included in working tree\n"
                    "Production-merge: false\n")
            with self.assertRaises(ValueError):
                mod.source_message(body)


if __name__ == "__main__":
    unittest.main()
