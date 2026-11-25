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
                         "policy_drift", "server_base_race", "wrong_parent", "wrong_tree",
                         "unclosed", "missing_dev_ancestry", "advanced_dev"):
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
                    if writes:
                        return {"state": "open" if scenario == "unclosed" else "closed",
                                "merged": True, "merge_commit_sha": "d" * 40,
                                "head": {"sha": HEAD}, "base": {"ref": "dev"}}
                    return {"draft": not ready, "mergeable_state": "blocked" if scenario == "blocked" else "clean",
                            "head": {"sha": HEAD}, "base": {"sha": BASE}}
                if route == "/git/ref/heads/dev":
                    if writes:
                        return {"object": {"sha": "c" * 40 if scenario in ("missing_dev_ancestry", "advanced_dev") else "d" * 40}}
                    return {"object": {"sha": "c" * 40 if scenario == "base_drift" else BASE}}
                if route.startswith("/compare/"):
                    return {"status": "ahead" if scenario == "advanced_dev" else "diverged",
                            "behind_by": 0 if scenario == "advanced_dev" else 1,
                            "merge_base_commit": {"sha": "d" * 40}}
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
                elif scenario in ("server_base_race", "wrong_parent", "wrong_tree", "unclosed", "missing_dev_ancestry"):
                    with self.assertRaises(RuntimeError):
                        gate.integrate_one()
                    self.assertEqual(len(writes), 1, "Never retry or roll back a merge")
                else:
                    result = gate.integrate_one()
                    if scenario in ("valid", "already_ready", "advanced_dev"):
                        self.assertEqual(result["status"], "merged")
                        self.assertTrue(result["pr_closure_verified"])
                        self.assertTrue(result["dev_ancestry_verified"])
                        self.assertEqual(writes, [("/pulls/500/merge", {"sha": HEAD, "merge_method": "squash"})])
                    else:
                        self.assertNotEqual(result["status"], "merged")
                    if scenario in ("already_ready", "denied", "media", "no_policy"):
                        mark.assert_not_called()
            if scenario not in ("valid", "already_ready", "advanced_dev", "server_base_race",
                                "wrong_parent", "wrong_tree", "unclosed", "missing_dev_ancestry"):
                self.assertEqual(writes, [], scenario)


class IndependentSafetyTests(unittest.TestCase):
    def test_separate_identity_and_exact_review(self):
        env = {"GITHUB_REPOSITORY": A.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_AUTONOMY_PAUSED": "",
               "GH_TOKEN": "fixture-only"}
        row = {"next_action": "INDEPENDENT_SAFETY_REVIEW", "technical_objection": False,
               "base": BASE, **{key: True for key in (
                   "exact_scope_verified", "current_base_verified",
                   "ci_workflow_provenance_verified", "ci_verified")}}
        for scenario in ("valid", "wrong_actor", "shared_owner", "missing_token", "bad_ci",
                         "product", "drift", "stale_review"):
            candidate = dict(row)
            if scenario == "bad_ci":
                candidate["ci_verified"] = False
            writes = []
            def api(method, route, body=None):
                if method == "POST":
                    writes.append((route, body))
                    return {"id": 10, "user": {"id": 123}, "commit_id": HEAD, "state": "APPROVED"}
                if route == "/pulls/500":
                    return {"user": {"id": 41898282}, "head": {"sha": HEAD},
                            "base": {"sha": BASE}, "state": "open"}
                if route.endswith("/reviews?per_page=100"):
                    return [{"user": {"id": 123}, "state": "DISMISSED"}] if scenario == "stale_review" else []
                if route == "/git/ref/heads/dev":
                    return {"object": {"sha": BASE}}
                self.fail(route)
            actor = type("Response", (), {"stdout": '{"id": %d}' % (999 if scenario == "wrong_actor" else 123)})()
            owners = {ROLE: 123 if scenario == "shared_owner" else 456}
            current = dict(env)
            if scenario == "missing_token":
                current["GH_TOKEN"] = ""
            scope = F.SUPERVISED_MEDIA_SCOPE if scenario == "product" else SCOPE
            with patch.dict(os.environ, current), patch.object(gate, "configured_reviewers", return_value=(123, owners)), patch.object(gate.subprocess, "run", return_value=actor), patch.object(gate, "discover", return_value={500: (ROLE, scope, HEAD)}), patch.object(gate, "inspect", side_effect=[candidate, {} if scenario == "drift" else candidate]), patch.object(A, "api", side_effect=api):
                if scenario == "wrong_actor":
                    with self.assertRaises(ValueError):
                        gate.independent_safety_review()
                else:
                    result = gate.independent_safety_review()
                    self.assertEqual(result["status"] == "reviewed", scenario == "valid")
            if scenario == "valid":
                self.assertEqual(len(writes), 1)
                self.assertEqual(writes[0][1]["commit_id"], HEAD)
                self.assertEqual(writes[0][1]["body"].splitlines()[0],
                                 f"GASLUX-SAFETY-V1 head={HEAD} base={BASE}")
            else:
                self.assertEqual(writes, [], scenario)


class FullVmAcceptanceTests(unittest.TestCase):
    def test_independent_complete_platform_evidence_only(self):
        env = {"GASLUX_VM_OBSERVER_ID": "789", "GASLUX_VM_ACCEPTANCE_WORKFLOW_ID": "1234"}
        digest = "e" * 64
        for scenario in ("valid", "missing_platform", "wrong_head", "shared_identity",
                         "wrong_workflow", "workflow_changed", "expired", "wrong_digest",
                         "live_only", "stale_review", "foreign_repo", "bad_job"):
            platforms = gate.VM_PLATFORMS
            if scenario == "missing_platform":
                platforms = platforms[:-1]
            marker = "\n".join(
                f"GASLUX-VM-V1 role=mint platform={platform} head={HEAD if scenario != 'wrong_head' else BASE} "
                f"base={BASE} run={10 + i} artifact={20 + i} sha256={digest}"
                for i, platform in enumerate(platforms))
            reviews = [{"user": {"id": 789}, "state": "DISMISSED" if scenario == "stale_review" else "APPROVED",
                        "commit_id": HEAD, "body": marker}]
            def api(method, route):
                self.assertEqual(method, "GET")
                if route == "/actions/workflows/1234":
                    return {"id": 1234, "state": "active",
                            "path": ".github/workflows/unrelated.yml" if scenario == "wrong_workflow"
                            else ".github/workflows/gaslux-agent-lifecycle-research.yml"}
                if route == "/git/ref/heads/main":
                    return {"object": {"sha": BASE}}
                run = int(route.split("/")[3])
                platform = gate.VM_PLATFORMS[run - 10]
                if "/jobs?" in route:
                    return {"total_count": 1, "jobs": [{
                        "name": "official_mint_live_guest" if scenario == "live_only" else f"full-installed-lifecycle (mint, {platform})",
                        "head_sha": HEAD, "run_id": run, "run_attempt": 1, "status": "completed",
                        "conclusion": "failure" if scenario == "bad_job" else "success"}]}
                if "/artifacts?" in route:
                    return {"total_count": 1, "artifacts": [{
                        "id": run + 10, "name": f"gaslux-full-vm-mint-{platform}",
                        "expired": scenario == "expired", "size_in_bytes": 100,
                        "digest": "sha256:" + ("d" * 64 if scenario == "wrong_digest" else digest)}]}
                return {"id": run, "workflow_id": 1234, "head_sha": HEAD,
                        "event": "pull_request", "repository": {"id": A.REPOSITORY_ID},
                        "head_repository": {"id": 1 if scenario == "foreign_repo" else A.REPOSITORY_ID},
                        "status": "completed", "conclusion": "success", "run_attempt": 1}
            with patch.dict(os.environ, env), patch.object(A, "api", side_effect=api), \
                 patch.object(A, "source_at", side_effect=lambda p, ref: b"changed" if scenario == "workflow_changed" and ref == HEAD else b"trusted"):
                self.assertEqual(gate.vm_acceptance_verified(reviews, "mint", HEAD, BASE, 41898282,
                                 789 if scenario == "shared_identity" else 123, 456),
                                 scenario == "valid", scenario)

    def test_product_merge_requires_every_gate_and_never_authorizes_other_scope(self):
        row = SupervisedIntegrationTests().receipt()
        row.update(scope=F.SUPERVISED_MEDIA_SCOPE, next_action="PRODUCT_INTEGRATION_ELIGIBLE",
                   full_vm_acceptance_verified=True)
        self.assertTrue(gate.eligible_product(row))
        self.assertFalse(gate.eligible_test(row))
        for key, value in row.items():
            if value is True:
                self.assertFalse(gate.eligible_product({**row, key: False}), key)
        self.assertFalse(gate.eligible_product({**row, "scope": "lifecycle"}))
        self.assertFalse(gate.eligible_product({**row, "technical_objection": True}))


class IndependentOwnerTests(unittest.TestCase):
    def test_independent_owner_exact_head_no_self_review(self):
        env = {"GITHUB_REPOSITORY": A.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_AUTONOMY_PAUSED": "",
               "GH_TOKEN": "fixture-only"}
        row = {"backend_owner_verified": False, "technical_objection": False,
               "base": BASE, **{key: True for key in (
                   "exact_scope_verified", "current_base_verified",
                   "ci_workflow_provenance_verified", "ci_verified")}}
        for scenario in ("valid", "same_safety", "wrong_role", "product_without_vm", "drift"):
            writes = []
            def api(method, route, body=None):
                if method == "POST":
                    writes.append(body)
                    return {"id": 10, "user": {"id": 456}, "commit_id": HEAD, "state": "APPROVED"}
                if route == "/pulls/500":
                    return {"user": {"id": 41898282}, "head": {"sha": HEAD},
                            "base": {"sha": BASE}, "state": "open"}
                if route.endswith("/reviews?per_page=100"):
                    return []
                if route == "/git/ref/heads/dev":
                    return {"object": {"sha": BASE}}
                self.fail(route)
            actor = type("Response", (), {"stdout": '{"id": 456}'})()
            owners = {ROLE: 999, "zorin": 456} if scenario == "wrong_role" else {ROLE: 456}
            scope = F.SUPERVISED_MEDIA_SCOPE if scenario == "product_without_vm" else SCOPE
            with patch.dict(os.environ, env), patch.object(gate, "configured_reviewers", return_value=(456 if scenario == "same_safety" else 123, owners)), \
                 patch.object(gate.subprocess, "run", return_value=actor), \
                 patch.object(gate, "discover", return_value={500: (ROLE, scope, HEAD)}), \
                 patch.object(gate, "inspect", side_effect=[row, {} if scenario == "drift" else row]), \
                 patch.object(gate, "vm_acceptance_verified", return_value=False), patch.object(A, "api", side_effect=api):
                if scenario == "same_safety":
                    with self.assertRaises(ValueError):
                        gate.independent_owner_review()
                else:
                    result = gate.independent_owner_review()
                    self.assertEqual(result["status"] == "owner_reviewed", scenario == "valid")
            self.assertEqual(len(writes), int(scenario == "valid"))
            if writes:
                self.assertEqual(writes[0]["body"].splitlines()[0],
                                 f"GASLUX-BACKEND-OWNER-V1 role={ROLE} head={HEAD} base={BASE}")


class DynamicAdmissionTests(unittest.TestCase):
    def test_dynamic_scope_reconstructed_without_pr_body(self):
        role = "zorin"
        source, suite, _ = F.TASKS[role]
        before = b"def present(x):\n    return x\n"
        generated = "def missing(x):\n    return x + 1\n"
        test = f"from {Path(source).stem} import missing\n\ndef test_required():\n    assert missing(1) == 2\n".encode()
        key = F.sha256(f"{source}:missing".encode())
        branch = f"bot/gaslux-dynamic-{role}-{key[:12]}-{BASE[:12]}"
        after = gate.dynamic.candidate_bytes(before, "missing", generated)
        for scenario in ("valid", "wrong_branch", "wrong_bytes", "no_witness", "two_commits"):
            pr = {"commits": 2 if scenario == "two_commits" else 1,
                  "head": {"ref": branch if scenario != "wrong_branch" else branch[:-1] + "c"}}
            def read(path, ref):
                if path == source:
                    return before if ref == BASE else after + (b"\nimport os\n" if scenario == "wrong_bytes" else b"")
                return b"def test_unrelated():\n    pass\n" if scenario == "no_witness" else test
            with patch.object(A, "single_parent", return_value=BASE), \
                 patch.object(A, "one_path_commit"), patch.object(A, "source_at", side_effect=read):
                if scenario == "valid":
                    self.assertEqual(gate.dynamic_scope(pr, role, HEAD), BASE)
                else:
                    with self.assertRaises(ValueError):
                        gate.dynamic_scope(pr, role, HEAD)

    def test_dynamic_requires_all_semantic_and_vm_gates(self):
        row = SupervisedIntegrationTests().receipt()
        row.update(scope=gate.DYNAMIC_SCOPE, next_action="PRODUCT_INTEGRATION_ELIGIBLE",
                   full_vm_acceptance_verified=True)
        self.assertTrue(gate.eligible_product(row))
        self.assertFalse(gate.eligible_test(row))
        for name in ("safety_review_verified", "backend_owner_verified", "full_vm_acceptance_verified",
                     "exact_scope_verified", "ci_verified", "current_base_verified"):
            self.assertFalse(gate.eligible_product({**row, name: False}))

    def test_dynamic_discovery_does_not_auto_approve_semantics(self):
        role = "zorin"
        ref = f"bot/gaslux-dynamic-{role}-{'b' * 12}-{'a' * 12}"
        repo = {"full_name": A.REPO}
        pr = {"number": 500, "head": {"ref": ref, "sha": HEAD, "repo": repo},
              "base": {"ref": "dev", "repo": repo}}
        with patch.object(A, "api", return_value=[pr]):
            self.assertEqual(gate.discover(), {500: (role, gate.DYNAMIC_SCOPE, HEAD)})
        env = {"GITHUB_REPOSITORY": A.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_AUTONOMY_PAUSED": "",
               "GH_TOKEN": "fixture"}
        with patch.dict(os.environ, env), \
             patch.object(gate, "configured_reviewers", return_value=(123, {role: 456})), \
             patch.object(gate.subprocess, "run", return_value=type("Response", (), {"stdout": '{"id": 123}'})()), \
             patch.object(gate, "discover", return_value={500: (role, gate.DYNAMIC_SCOPE, HEAD)}), \
             patch.object(gate, "inspect") as inspect:
            self.assertEqual(gate.independent_safety_review()["status"], "idle")
            inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
