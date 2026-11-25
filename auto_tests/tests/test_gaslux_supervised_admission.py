"""Exact supervised append admission, separate from distro merge authority."""
import json
import os
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


class SupervisedIntegrationTests(unittest.TestCase):
    def receipt(self):
        return {"pr": 500, "role": ROLE, "scope": SCOPE, "head": HEAD, "base": BASE,
                "next_action": "TEST_ONLY_INTEGRATION_ELIGIBLE",
                "technical_objection": False, **{key: True for key in (
                    "exact_scope_verified", "current_base_verified",
                    "ci_workflow_provenance_verified", "ci_verified",
                    "safety_review_verified", "backend_owner_verified")}}

    def test_all_gates_and_only_test_scope(self):
        row = self.receipt()
        self.assertTrue(gate.eligible_test(row))
        for key, value in row.items():
            if value is True:
                self.assertFalse(gate.eligible_test({**row, key: False}), key)
        for delta in ({"scope": F.SUPERVISED_MEDIA_SCOPE}, {"technical_objection": True},
                      {"technical_objection": None}, {"head": "bad"}, {"base": "bad"},
                      {"next_action": "INDEPENDENT_SAFETY_REVIEW"}):
            self.assertFalse(gate.eligible_test({**row, **delta}))

    def test_strict_dev_policy_fail_closed(self):
        for scenario in ("valid", "no_rule", "loose", "no_checks", "admin_bypass",
                         "force_push", "delete", "pr_bypass", "force_bypass",
                         "effective_bypass", "wrong_base", "graphql_error", "unreadable"):
            checks = ["evidence-python"]
            rule = {"isAdminEnforced": True, "requiresStatusChecks": True,
                    "requiresStrictStatusChecks": True, "requiredStatusCheckContexts": checks,
                    "allowsForcePushes": False, "allowsDeletions": False,
                    "bypassPullRequestAllowances": {"totalCount": 0},
                    "bypassForcePushAllowances": {"totalCount": 0}}
            effective = {"requiredStatusCheckContexts": checks,
                         "allowsForcePushes": False, "allowsDeletions": False}
            if scenario == "loose":
                rule["requiresStrictStatusChecks"] = False
            if scenario == "no_checks":
                rule["requiredStatusCheckContexts"] = []
            if scenario == "admin_bypass":
                rule["isAdminEnforced"] = False
            if scenario == "force_push":
                rule["allowsForcePushes"] = True
            if scenario == "delete":
                rule["allowsDeletions"] = True
            if scenario == "pr_bypass":
                rule["bypassPullRequestAllowances"]["totalCount"] = 1
            if scenario == "force_bypass":
                rule["bypassForcePushAllowances"]["totalCount"] = 1
            if scenario == "effective_bypass":
                effective["requiredStatusCheckContexts"] = []
            ref = {"name": "dev", "prefix": "refs/heads/",
                   "target": {"oid": "c" * 40 if scenario == "wrong_base" else BASE},
                   "branchProtectionRule": None if scenario == "no_rule" else rule,
                   "refUpdateRule": effective}
            response = {"data": {"repository": {"nameWithOwner": A.REPO, "ref": ref}}}
            if scenario == "graphql_error":
                response["errors"] = [{"message": "denied"}]
            with patch.object(gate.subprocess, "run", return_value=gate.subprocess.CompletedProcess(
                    [], 0, json.dumps(response).encode(), b""),
                    side_effect=OSError("unreadable") if scenario == "unreadable" else None) as query:
                self.assertEqual(gate.strict_dev_protected(BASE), scenario == "valid", scenario)
                self.assertEqual(query.call_args.args[0][:3], ["gh", "api", "graphql"])
                self.assertIn("query {", query.call_args.args[0][-1])

    def test_trusted_merge_only_after_revalidation_and_github_ready(self):
        env = {"GITHUB_REPOSITORY": A.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_AUTONOMY_PAUSED": ""}
        for scenario in ("valid", "already_ready", "denied", "drift", "blocked",
                         "base_drift", "media", "paused", "untrusted", "no_policy",
                         "policy_drift", "server_base_race", "wrong_parent", "wrong_tree"):
            row = self.receipt()
            second = dict(row)
            if scenario == "denied":
                row["safety_review_verified"] = False
            if scenario == "drift":
                second["backend_owner_verified"] = False
            ready = scenario == "already_ready"
            writes = []

            def api(method, route, body=None):
                if method == "PUT":
                    writes.append((route, body))
                    if scenario == "server_base_race":
                        raise RuntimeError("GitHub rejected out-of-date head")
                    return {"merged": True, "sha": "d" * 40}
                self.assertEqual(method, "GET")
                if route == "/pulls/500":
                    return {"draft": not ready, "mergeable_state": "blocked" if scenario == "blocked" else "clean",
                            "head": {"sha": HEAD}, "base": {"sha": BASE}}
                if route == "/git/ref/heads/dev":
                    return {"object": {"sha": "c" * 40 if scenario == "base_drift" else BASE}}
                if route.startswith("/git/commits/"):
                    return {"tree": {"sha": "e" * 40 if route.endswith(HEAD)
                                    or scenario != "wrong_tree" else "f" * 40}}
                self.fail(route)

            def mark_ready(*args, **kwargs):
                nonlocal ready
                ready = True

            current = dict(env)
            if scenario == "paused":
                current["GASLUX_AUTONOMY_PAUSED"] = "true"
            if scenario == "untrusted":
                current["GITHUB_REF"] = "refs/heads/dev"
            scope = F.SUPERVISED_MEDIA_SCOPE if scenario == "media" else SCOPE
            with patch.dict(os.environ, current), \
                 patch.object(gate, "discover", return_value={500: (ROLE, scope, HEAD)}), \
                 patch.object(gate, "configured_reviewers", return_value=(1, {ROLE: 2})), \
                 patch.object(gate, "inspect", side_effect=[row, second]), \
                 patch.object(A, "api", side_effect=api), \
                 patch.object(gate, "strict_dev_protected",
                              side_effect=[scenario != "no_policy", scenario != "policy_drift"]), \
                 patch.object(A, "single_parent",
                              return_value="c" * 40 if scenario == "wrong_parent" else BASE), \
                 patch.object(gate.subprocess, "run", side_effect=mark_ready) as mark:
                if scenario in ("paused", "untrusted"):
                    with self.assertRaises(ValueError):
                        gate.integrate_one()
                    mark.assert_not_called()
                elif scenario in ("server_base_race", "wrong_parent", "wrong_tree"):
                    with self.assertRaises(RuntimeError):
                        gate.integrate_one()
                    self.assertEqual(len(writes), 1, "Never retry or roll back a merge")
                else:
                    result = gate.integrate_one()
                    if scenario in ("valid", "already_ready"):
                        self.assertEqual(result["status"], "merged")
                        self.assertEqual(writes, [("/pulls/500/merge", {"sha": HEAD, "merge_method": "squash"})])
                    else:
                        self.assertNotEqual(result["status"], "merged")
                    if scenario in ("already_ready", "denied", "media", "no_policy"):
                        mark.assert_not_called()
            if scenario not in ("valid", "already_ready", "server_base_race",
                                "wrong_parent", "wrong_tree"):
                self.assertEqual(writes, [], scenario)


if __name__ == "__main__":
    unittest.main()
