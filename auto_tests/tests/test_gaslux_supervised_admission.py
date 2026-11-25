"""Exact supervised append admission, separate from distro merge authority."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_supervised_admission as gate

A = gate.admission
F = gate.factory
BASE, HEAD = "a" * 40, "b" * 40
ROLE, SCOPE = "mint", F.SUPERVISED_TEST_SCOPE
SOURCE, TEST, _ = F.TASKS[ROLE]
SUITE = "auto_tests/tests/" + TEST
PR = {
    "number": 500, "state": "open", "draft": True, "commits": 1,
    "user": {"login": "gaslux-autonomous-publisher[bot]", "id": 360620437},
    "head": {"sha": HEAD, "ref": F.supervised_branch(ROLE, BASE, SCOPE),
             "repo": {"full_name": A.REPO}},
    "base": {"ref": "dev", "repo": {"full_name": A.REPO}},
}


class SupervisedAdmissionTests(unittest.TestCase):
    def test_canonical_scope_checks_full_bytes_and_never_executes_candidate(self):
        source = b"def assess_mint_lifecycle(evidence: dict) -> dict:\n    return {}\n"
        suite = b"def load_helper():\n    pass\n"
        addition = F.supervised_addition(ROLE, SCOPE).encode()
        expected = suite.rstrip(b"\n") + b"\n\n\n" + addition
        for scenario in ("valid", "malicious", "already_tested", "wrong_branch", "extra_commit"):
            pr = {**PR, "head": dict(PR["head"])}
            if scenario == "wrong_branch":
                pr["head"]["ref"] = "bot/gaslux-test-mint-" + "c" * 12
            if scenario == "extra_commit":
                pr["commits"] = 2
            def source_at(path, ref):
                if path == SOURCE:
                    return source
                if ref == BASE:
                    return suite + (b"# assess_mint_lifecycle\n" if scenario == "already_tested" else b"")
                return expected + (b"\nraise RuntimeError\n" if scenario == "malicious" else b"")
            with patch.object(A, "single_parent", return_value=BASE), \
                 patch.object(A, "one_path_commit") as one, \
                 patch.object(A, "source_at", side_effect=source_at), \
                 patch.object(F, "supervised_media_acceptance") as execute:
                if scenario == "valid":
                    self.assertEqual(gate.canonical_scope(pr, ROLE, SCOPE, HEAD), BASE)
                    one.assert_called_once_with(BASE, HEAD, SUITE)
                else:
                    with self.assertRaises(ValueError):
                        gate.canonical_scope(pr, ROLE, SCOPE, HEAD)
                execute.assert_not_called()

    def test_inspection_never_grants_merge_and_routes_missing_gates(self):
        for scenario in ("valid", "stale", "ci", "objection", "identity", "drift"):
            pr = {**PR}
            if scenario == "identity":
                pr["user"] = {"login": PR["user"]["login"], "id": 1}
            calls = 0
            def api(method, route):
                nonlocal calls
                self.assertEqual(method, "GET")
                if route == "/pulls/500":
                    return pr
                if route == "/git/ref/heads/dev":
                    calls += 1
                    return {"object": {"sha": "c" * 40 if scenario == "drift" and calls > 1 else BASE}}
                if route.startswith("/commits/"):
                    return {}
                if route.endswith("reviews?per_page=100"):
                    return [{"state": "CHANGES_REQUESTED"}] if scenario == "objection" else []
                if route.endswith("comments?per_page=100"):
                    return []
                self.fail(route)
            with patch.object(A, "api", side_effect=api), \
                 patch.object(gate, "canonical_scope", return_value="c" * 40 if scenario == "stale" else BASE), \
                 patch.object(A, "ci_workflow_provenance", return_value=scenario != "ci"), \
                 patch.object(A, "checks_ok", return_value=True):
                row = gate.inspect(500, ROLE, SCOPE, HEAD)
            wanted = {"valid": "INDEPENDENT_SAFETY_REVIEW", "stale": "REFRESH_SUPERVISED_SCOPE",
                      "ci": "WAIT_OR_REPAIR_SCOPE_CI", "objection": "RESOLVE_TECHNICAL_OBJECTION",
                      "identity": "VERIFY_SUPERVISED_SCOPE", "drift": "VERIFY_SUPERVISED_SCOPE"}
            self.assertEqual(row["next_action"], wanted[scenario])
            self.assertFalse(row["merge_authorized"])
            self.assertFalse(row["release_eligible"])

    def test_discovery_is_separate_from_legacy_and_inventory_is_bounded(self):
        with patch.object(A, "api", return_value=[PR]):
            self.assertEqual(gate.discover(), {500: (ROLE, SCOPE, HEAD)})
        with patch.object(A, "api", return_value=[PR] * 100):
            with self.assertRaises(ValueError):
                gate.discover()


if __name__ == "__main__":
    unittest.main()
