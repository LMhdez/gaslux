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

    def test_ruleset_protection_requires_visible_non_bypassable_active_policy(self):
        for scenario in ("valid", "no_rules", "hidden_bypass", "bypass", "wrong_target",
                         "wrong_source", "inactive", "loose", "missing_check", "no_delete",
                         "no_force_block", "no_pr", "different_rules", "base_drift", "denied",
                         "no_review_count", "stale_reviews", "last_push", "unresolved_threads",
                         "wrong_check_app", "restrict_updates"):
            rules = [
                {"type": "deletion"}, {"type": "non_fast_forward"},
                {"type": "pull_request", "parameters": {
                    "required_approving_review_count": 0 if scenario == "no_review_count" else 2,
                    "dismiss_stale_reviews_on_push": scenario != "stale_reviews",
                    "require_last_push_approval": scenario != "last_push",
                    "required_review_thread_resolution": scenario != "unresolved_threads"}},
                {"type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": scenario != "loose",
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {"context": name, "integration_id": 1 if scenario == "wrong_check_app" else 15368}
                        for name in sorted(A.COMMON_CHECKS)
                        if scenario != "missing_check" or name != "evidence-python"]}},
            ]
            if scenario == "restrict_updates":
                rules.append({"type": "update"})
            missing = {"no_delete": "deletion", "no_force_block": "non_fast_forward",
                       "no_pr": "pull_request"}.get(scenario)
            rules = [r for r in rules if r["type"] != missing]
            active = [{**r, "ruleset_id": 42, "ruleset_source_type": "Repository",
                       "ruleset_source": A.REPO} for r in rules]
            if scenario == "no_rules":
                active = []
            detail = {"id": 42, "source_type": "Repository", "source": A.REPO,
                      "target": "branch", "enforcement": "active", "bypass_actors": [],
                      "conditions": {"ref_name": {"include": ["refs/heads/dev"], "exclude": []}},
                      "rules": rules}
            if scenario == "hidden_bypass":
                detail.pop("bypass_actors")
            if scenario == "bypass":
                detail["bypass_actors"] = [{"actor_type": "Integration"}]
            if scenario == "wrong_target":
                detail["conditions"]["ref_name"]["include"] = ["refs/heads/main"]
            if scenario == "wrong_source":
                detail["source"] = "other/repo"
            if scenario == "inactive":
                detail["enforcement"] = "evaluate"
            if scenario == "different_rules":
                detail["rules"] = rules[:-1]
            ref_reads = 0

            def api(method, route):
                nonlocal ref_reads
                self.assertEqual(method, "GET")
                if route == "/git/ref/heads/dev":
                    ref_reads += 1
                    return {"object": {"sha": "c" * 40 if scenario == "base_drift"
                                       and ref_reads > 1 else BASE}}
                if route == "/rules/branches/dev?per_page=100":
                    return active
                if route == "/rulesets/42?includes_parents=false":
                    if scenario == "denied":
                        raise RuntimeError("403")
                    return detail
                self.fail(route)

            with patch.object(A, "api", side_effect=api):
                self.assertEqual(gate.strict_ruleset_protected(BASE),
                                 scenario == "valid", scenario)

    def test_strict_dev_policy_fail_closed(self):
        for scenario in ("valid", "no_rule", "loose", "no_checks", "admin_bypass",
                         "force_push", "delete", "pr_bypass", "force_bypass",
                         "effective_bypass", "wrong_base", "graphql_error", "unreadable",
                         "no_review_count", "stale_reviews", "last_push", "unresolved_threads"):
            checks = sorted(A.COMMON_CHECKS)
            rule = {"isAdminEnforced": True, "requiresStatusChecks": True,
                    "requiresStrictStatusChecks": True, "requiredStatusCheckContexts": checks,
                    "requiredApprovingReviewCount": 0 if scenario == "no_review_count" else 2,
                    "dismissesStaleReviews": scenario != "stale_reviews",
                    "requireLastPushApproval": scenario != "last_push",
                    "requiresConversationResolution": scenario != "unresolved_threads",
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
                    side_effect=OSError("unreadable") if scenario == "unreadable" else None) as query, \
                 patch.object(gate, "strict_ruleset_protected", return_value=False) as ruleset:
                self.assertEqual(gate.strict_dev_protected(BASE), scenario == "valid", scenario)
                if scenario == "no_rule":
                    ruleset.assert_called_once_with(BASE)
                    ruleset.return_value = True
                    self.assertTrue(gate.strict_dev_protected(BASE))
                else:
                    ruleset.assert_not_called()
                self.assertEqual(query.call_args.args[0][:3], ["gh", "api", "graphql"])
                self.assertIn("query {", query.call_args.args[0][-1])

    def test_trusted_merge_only_after_revalidation_and_github_ready(self):
        env = {"GITHUB_REPOSITORY": A.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "schedule", "GASLUX_AUTONOMY_PAUSED": ""}
        for scenario in ("valid", "already_ready", "denied", "drift", "blocked",
                         "base_drift", "media", "paused", "untrusted", "no_policy",
                         "policy_drift", "no_confinement", "confinement_drift", "no_receipts", "receipt_drift", "role_policy_missing", "role_policy_drift", "server_base_race", "wrong_parent", "wrong_tree",
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
                 patch.object(gate, "production_merge_policy",
                              side_effect=[scenario != "no_confinement", scenario != "confinement_drift"]), \
                 patch.object(gate, "independent_status_receipts_verified",
                              side_effect=[scenario != "no_receipts", scenario != "receipt_drift"]), \
                 patch.object(gate, "strict_dev_protected",
                              side_effect=[scenario != "no_policy", scenario != "policy_drift"]), \
                 patch.object(gate, "role_review_protected",
                              side_effect=[scenario != "role_policy_missing", scenario != "role_policy_drift"]), \
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
                    if scenario in ("already_ready", "denied", "media", "no_policy", "no_confinement", "no_receipts", "role_policy_missing"):
                        mark.assert_not_called()
            if scenario not in ("valid", "already_ready", "advanced_dev", "server_base_race",
                                "wrong_parent", "wrong_tree", "unclosed", "missing_dev_ancestry"):
                self.assertEqual(writes, [], scenario)


class ProductionConfinementTests(unittest.TestCase):
    def test_server_policy_must_cover_all_non_dev_targets(self):
        for scenario in ("valid", "disabled", "paused", "no_main", "weak_main",
                         "missing_confinement", "wrong_pattern", "bypass", "missing_bypass",
                         "dev_covered", "missing_effective", "policy_drift", "main_drift",
                         "stale_checkout", "unknown", "wrong_source", "missing_ci", "fetch_merge_exception",
                         "parameterless", "fork", "unknown_fork", "foreign_repo", "unknown_update_parameters"):
            main = "c" * 40
            main_rules = [
                {"type": "deletion"}, {"type": "non_fast_forward"},
                {"type": "pull_request", "parameters": {
                    "required_approving_review_count": 0 if scenario == "weak_main" else 1,
                    "dismiss_stale_reviews_on_push": True, "require_last_push_approval": True,
                    "required_review_thread_resolution": True}},
                {"type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": True, "do_not_enforce_on_create": False,
                    "required_status_checks": [] if scenario == "missing_ci" else [
                        {"context": "adversarial_contracts", "integration_id": 15368}]}}]
            common = {"source": A.REPO, "source_type": "Repository", "target": "branch",
                      "enforcement": "active", "current_user_can_bypass": "never"}
            details = {
                10: {**common, "id": 10, "bypass_actors": [],
                     "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                     "rules": main_rules},
                20: {**common, "id": 20,
                     "conditions": {"ref_name": {"include": ["~ALL"], "exclude": ["refs/heads/dev"]}},
                     "rules": [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}]},
            }
            if scenario == "no_main":
                details.pop(10)
            if scenario == "missing_confinement":
                details.pop(20)
            if scenario == "parameterless":
                details[20]["rules"][0].pop("parameters")
            if scenario == "fetch_merge_exception":
                details[20]["rules"][0]["parameters"]["update_allows_fetch_and_merge"] = True
            if scenario == "unknown_update_parameters":
                details[20]["rules"][0]["parameters"]["other_exception"] = True
            if scenario == "wrong_pattern":
                details[20]["conditions"]["ref_name"]["include"] = ["refs/heads/main"]
            if scenario == "bypass":
                details[20]["current_user_can_bypass"] = "pull_requests_only"
            if scenario == "missing_bypass":
                details[20].pop("current_user_can_bypass")
            if scenario == "wrong_source":
                details[20]["source"] = "other/repo"
            rows = [{**rule, "ruleset_id": rid, "ruleset_source": A.REPO,
                     "ruleset_source_type": "Repository"}
                    for rid, detail in details.items() for rule in detail["rules"]]
            reads = {}
            def api(method, route):
                self.assertEqual(method, "GET")
                reads[route] = reads.get(route, 0) + 1
                if route == "":
                    repo = {"id": A.REPOSITORY_ID if scenario != "foreign_repo" else 1,
                            "full_name": A.REPO, "fork": scenario == "fork", "default_branch": "main"}
                    if scenario == "unknown_fork":
                        repo.pop("fork")
                    return repo
                if route == "/git/ref/heads/dev":
                    return {"object": {"sha": BASE}}
                if route == "/git/ref/heads/main":
                    return {"object": {"sha": HEAD if scenario == "main_drift" and reads[route] > 1 else main}}
                if route == "/rulesets?includes_parents=false&per_page=100":
                    if scenario == "unknown":
                        raise RuntimeError("403")
                    return list(details.values())
                if route == "/rules/branches/main?per_page=100":
                    return [row for row in rows if scenario != "missing_effective" or row["ruleset_id"] != 20]
                if route == "/rules/branches/dev?per_page=100":
                    return [row for row in rows if row["ruleset_id"] == 20] if scenario == "dev_covered" else []
                if route.startswith("/rulesets/"):
                    rid = int(route.split("/")[2].split("?")[0])
                    detail = details[rid]
                    return {**detail, "enforcement": "disabled"} if scenario == "policy_drift" and reads[route] > 1 else detail
                self.fail(route)
            env = {"GASLUX_PRODUCTION_MERGE_ENABLED": "" if scenario == "disabled" else "true",
                   "GASLUX_AUTONOMY_PAUSED": "true" if scenario == "paused" else "false",
                   "GITHUB_SHA": HEAD if scenario == "stale_checkout" else main}
            with patch.dict(os.environ, env, clear=True), patch.object(A, "api", side_effect=api), \
                 patch.object(gate, "strict_ruleset_protected", return_value=True):
                os.environ["GASLUX_APP_STATUS_GATES_ENABLED"] = "true"
                self.assertEqual(gate.production_merge_policy(BASE), scenario in ("valid", "parameterless"), scenario)
                if scenario == "valid":
                    os.environ["GASLUX_APP_STATUS_GATES_ENABLED"] = "false"
                    self.assertFalse(gate.production_merge_policy(BASE))


    def test_exact_source_pinned_required_statuses(self):
        baseline = [{"context": n, "integration_id": 15368} for n in sorted(A.COMMON_CHECKS)]
        app = [{"context": gate.APP_STATUS_CONTEXTS[k], "integration_id": i}
               for k, i in (("safety", 7000001), ("owner", 7000002))]
        with patch.dict(os.environ, {"GASLUX_SAFETY_APP_ID": "7000001",
                                    "GASLUX_OWNER_APP_ID": "7000002"}, clear=True):
            self.assertTrue(gate.exact_required_checks(baseline))
            self.assertFalse(gate.exact_required_checks(baseline, require_app_statuses=True))
            self.assertTrue(gate.exact_required_checks(baseline + app, require_app_statuses=True))
            for bad in (baseline + app[:1], baseline + app + app[:1],
                        baseline + [{**app[0], "integration_id": 15368}, app[1]],
                        baseline + [app[0], {**app[1], "integration_id": 361556198}],
                        baseline + app + [{"context": "unrecognized", "integration_id": 5938492}],
                        baseline[1:] + app):
                self.assertFalse(gate.exact_required_checks(bad, require_app_statuses=True))
        for ids in ({}, {"GASLUX_SAFETY_APP_ID": "5938492", "GASLUX_OWNER_APP_ID": "5938509"},
                    {"GASLUX_SAFETY_APP_ID": "7000001", "GASLUX_OWNER_APP_ID": "7000001"}):
            with patch.dict(os.environ, ids, clear=True):
                self.assertFalse(gate.exact_required_checks(baseline + app, require_app_statuses=True))



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
            actor = 999 if scenario == "wrong_actor" else 123
            owners = {ROLE: 123 if scenario == "shared_owner" else 456}
            current = dict(env)
            if scenario == "missing_token":
                current["GH_TOKEN"] = ""
            scope = F.SUPERVISED_MEDIA_SCOPE if scenario == "product" else SCOPE
            with patch.dict(os.environ, current), patch.object(gate, "configured_reviewers", return_value=(123, owners)), patch.object(gate, "review_app_actor", return_value=actor), patch.object(gate, "discover", return_value={500: (ROLE, scope, HEAD)}), patch.object(gate, "inspect", side_effect=[candidate, {} if scenario == "drift" else candidate]), patch.object(A, "api", side_effect=api):
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
            actor = 456
            owners = {ROLE: 999, "zorin": 456} if scenario == "wrong_role" else {ROLE: 456}
            scope = F.SUPERVISED_MEDIA_SCOPE if scenario == "product_without_vm" else SCOPE
            with patch.dict(os.environ, env), patch.object(gate, "configured_reviewers", return_value=(456 if scenario == "same_safety" else 123, owners)), \
                 patch.object(gate, "review_app_actor", return_value=actor), \
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
             patch.object(gate, "review_app_actor", return_value=123), \
             patch.object(gate, "discover", return_value={500: (role, gate.DYNAMIC_SCOPE, HEAD)}), \
             patch.object(gate, "inspect", return_value={"technical_objection": True}) as inspect:
            self.assertEqual(gate.independent_safety_review()["status"], "idle")
            inspect.assert_called_once()


    def test_dynamic_assessment_never_approves_and_revalidates(self):
        role = "zorin"
        row = {"technical_objection": False, "safety_review_verified": False,
               "base": BASE, **{k: True for k in ("exact_scope_verified",
                   "current_base_verified", "ci_workflow_provenance_verified", "ci_verified")}}
        for scenario in ("valid", "hold", "drift", "duplicate", "self_review"):
            writes = []
            initial = dict(row, technical_objection=scenario == "hold")
            def api(method, route, body=None):
                if method == "POST":
                    writes.append(body)
                    return {"id": 10, "user": {"id": 123}, "commit_id": HEAD,
                            "state": "COMMENTED"}
                if route == "/pulls/500":
                    return {"user": {"id": 123 if scenario == "self_review" else 41898282}}
                if route.endswith("/reviews?per_page=100"):
                    return [{"user": {"id": 123}, "state": "COMMENTED",
                             "body": f"GASLUX-DYNAMIC-SAFETY-V1 head={HEAD} base={BASE}"}] if scenario == "duplicate" else []
                self.fail(route)
            with patch.object(gate, "discover", return_value={500: (role, gate.DYNAMIC_SCOPE, HEAD)}), \
                 patch.object(gate, "inspect", side_effect=[initial, {} if scenario == "drift" else initial]), \
                 patch.object(gate, "dynamic_safety_findings", return_value={"base": BASE, "semantic_approval": False}), \
                 patch.object(A, "api", side_effect=api):
                result = gate.independent_dynamic_assessment(123, {role: 456})
                self.assertEqual(result["status"] == "dynamic_assessed", scenario == "valid")
            self.assertEqual(len(writes), int(scenario == "valid"))
            if writes:
                self.assertEqual(writes[0]["event"], "COMMENT")
                self.assertEqual(writes[0]["commit_id"], HEAD)


class CompletedIntegrationAuditTests(unittest.TestCase):
    def test_audit_only_counts_actual_verified_merges(self):
        role = "zorin"
        merged, live, tree = "c" * 40, "d" * 40, "e" * 40
        repo = {"full_name": A.REPO}
        publisher = {"login": "github-actions[bot]", "id": 41898282}
        pr = {"number": 500, "state": "closed", "merged": True,
              "merge_commit_sha": merged, "user": publisher,
              "head": {"ref": f"bot/gaslux-test-{role}-{BASE[:12]}", "sha": HEAD, "repo": repo},
              "base": {"ref": "dev", "repo": repo}}
        for scenario in ("valid", "not_merged", "wrong_parent", "wrong_tree", "not_in_dev",
                         "missing_approval", "bad_ci", "hold", "drift"):
            calls = []
            def api(method, route):
                self.assertEqual(method, "GET")
                if route == "/git/ref/heads/dev":
                    calls.append(route)
                    return {"object": {"sha": BASE if scenario == "drift" and len(calls) > 1 else live}}
                if route.startswith("/pulls?"):
                    return [pr]
                if route == "/pulls/500":
                    return dict(pr, merged=scenario != "not_merged")
                if route.startswith("/git/commits/"):
                    return {"tree": {"sha": BASE if scenario == "wrong_tree" and route.endswith(merged) else tree}}
                if route.startswith("/compare/"):
                    return {"status": "diverged" if scenario == "not_in_dev" else "ahead",
                            "behind_by": 0, "merge_base_commit": {"sha": merged}}
                if route.endswith("/reviews?per_page=100"):
                    return []
                if route.endswith("/check-runs?per_page=100"):
                    return {}
                if route.endswith("/comments?per_page=100"):
                    return [{"body": "SAFETY HOLD"}] if scenario == "hold" else []
                self.fail(route)
            with patch.object(A, "api", side_effect=api), \
                 patch.object(gate, "configured_reviewers", return_value=(123, {role: 456})), \
                 patch.object(gate, "canonical_scope", return_value=BASE), \
                 patch.object(A, "single_parent", return_value=HEAD if scenario == "wrong_parent" else BASE), \
                 patch.object(A, "review_ok", return_value=scenario != "missing_approval"), \
                 patch.object(A, "owner_review_ok", return_value=True), \
                 patch.object(A, "ci_workflow_provenance", return_value=True), \
                 patch.object(A, "checks_ok", return_value=scenario != "bad_ci"):
                if scenario == "drift":
                    with self.assertRaises(ValueError):
                        gate.audit_completed_integrations()
                    continue
                result = gate.audit_completed_integrations()
            self.assertEqual(result["verified_integrations"], int(scenario == "valid"), scenario)
            self.assertFalse(result["release_eligible"])


class RulesetVisibilityTests(unittest.TestCase):
    def test_hidden_rest_actors_require_explicit_graphql_connection(self):
        detail = {"id": 28107915, "node_id": "RRS_example",
                  "updated_at": "2026-11-25T21:35:57.851+00:00"}
        for scenario in ("empty", "nonempty", "null", "wrong_id", "wrong_repo",
                         "inactive", "errors", "denied", "drift", "partial", "bad_count"):
            node = {"__typename": "RepositoryRuleset", "id": detail["node_id"],
                    "databaseId": detail["id"], "enforcement": "ACTIVE",
                    "source": {"nameWithOwner": A.REPO},
                    "bypassActors": {"totalCount": 0, "nodes": [],
                                     "pageInfo": {"hasNextPage": False, "hasPreviousPage": False}}}
            actors = node["bypassActors"]
            if scenario == "nonempty":
                actors.update(totalCount=1, nodes=[{"id": "actor"}])
            elif scenario == "null":
                node["bypassActors"] = None
            elif scenario == "wrong_id":
                node["databaseId"] += 1
            elif scenario == "wrong_repo":
                node["source"]["nameWithOwner"] = "other/repo"
            elif scenario == "inactive":
                node["enforcement"] = "DISABLED"
            elif scenario == "partial":
                actors["pageInfo"]["hasNextPage"] = True
            elif scenario == "bad_count":
                actors["totalCount"] = False
            response = {"data": {"node": node}}
            if scenario == "errors":
                response["errors"] = [{"message": "permission denied"}]
            fresh = dict(detail, updated_at="later") if scenario == "drift" else detail
            with patch.object(gate.subprocess, "run",
                              return_value=gate.subprocess.CompletedProcess([], 0, json.dumps(response).encode()),
                              side_effect=OSError("denied") if scenario == "denied" else None), \
                 patch.object(A, "api", return_value=fresh):
                expected = {"empty": "graphql_empty", "nonempty": "nonempty"}.get(scenario, "unknown")
                self.assertEqual(gate.ruleset_bypass_evidence(detail), expected, scenario)

    def test_visible_actor_list_and_current_identity(self):
        with patch.object(gate.subprocess, "run") as query:
            self.assertEqual(gate.ruleset_bypass_evidence({"bypass_actors": []}), "rest_empty")
            self.assertEqual(gate.ruleset_bypass_evidence({"bypass_actors": [{"actor_id": 1}]}), "nonempty")
            self.assertEqual(gate.ruleset_bypass_evidence(
                {"bypass_actors": [], "current_user_can_bypass": "always"}), "nonempty")
            self.assertEqual(gate.ruleset_bypass_evidence(
                {"current_user_can_bypass": "never"}), "unknown")
            query.assert_not_called()


class MultifileAdmissionTests(unittest.TestCase):
    def test_reconstruct_multiple_files_and_original_test_witness(self):
        import tempfile
        role = "zorin"
        suite = "auto_tests/tests/" + F.TASKS[role][1]
        paths = [gate.multi.module_path(x) for x in ("gaslux_alpha", "gaslux_beta")]
        test = b"from gaslux_alpha import one\nfrom gaslux_beta import two\n\ndef test_contract():\n    assert one(1) == two(2)\n"
        original = b"def present(x):\n    return x\n"
        changes = {name: gate.dynamic.candidate_bytes(original, symbol, f"def {symbol}(x):\n    return x\n")
                   for name, symbol in zip(paths, ("one", "two"))}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, raw in [(suite, test)] + [(name, original) for name in paths]:
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(raw)
            key = gate.multi.discover(root)[0]["key"]
        branch = f"bot/gaslux-multi-{role}-{key[6:18]}-{BASE[:12]}"
        for scenario in ("valid", "off_scope", "changed_test", "bad_source", "wrong_branch"):
            files = [{"filename": name, "status": "modified"} for name in paths]
            if scenario == "off_scope":
                files.append({"filename": ".github/workflows/evil.yml", "status": "modified"})
            if scenario == "changed_test":
                files.append({"filename": suite, "status": "modified"})
            comparison = {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                          "total_commits": 1, "merge_base_commit": {"sha": BASE}, "files": files}
            def source_at(name, ref):
                if name == suite:
                    return test
                if ref == BASE:
                    return original
                return changes[name] + (b"\nimport os\n" if scenario == "bad_source" else b"")
            pr = {"commits": 1, "head": {"ref": branch if scenario != "wrong_branch" else branch + "x"}}
            with patch.object(A, "single_parent", return_value=BASE), \
                 patch.object(A, "api", return_value=comparison), \
                 patch.object(A, "source_at", side_effect=source_at):
                if scenario == "valid":
                    self.assertEqual(gate.multifile_scope(pr, role, HEAD), BASE)
                else:
                    with self.assertRaises(ValueError):
                        gate.multifile_scope(pr, role, HEAD)

    def test_multifile_requires_same_product_gates(self):
        row = SupervisedIntegrationTests().receipt()
        row.update(scope=gate.MULTIFILE_SCOPE, next_action="PRODUCT_INTEGRATION_ELIGIBLE",
                   full_vm_acceptance_verified=True)
        self.assertTrue(gate.eligible_product(row))
        self.assertFalse(gate.eligible_test(row))
        for name in ("safety_review_verified", "backend_owner_verified", "full_vm_acceptance_verified"):
            self.assertFalse(gate.eligible_product({**row, name: False}))


class ActivationGateTests(unittest.TestCase):
    def test_exact_server_role_teams_not_generic_count(self):
        row = lambda tid: {"file_patterns": ["**"], "minimum_approvals": 1,
                           "reviewer": {"type": "Team", "id": tid}}
        policy = {"required_reviewers": [row(10), row(20)]}
        for second in ([{"id": 202}], [{"id": 101}], [{"id": 202}, {"id": 303}], []):
            with patch.object(gate, "readonly_gh_json", side_effect=[[{"id": 101}], second]):
                self.assertEqual(gate.required_role_teams_verified(policy, (101, 202)),
                                 second == [{"id": 202}])
        self.assertFalse(gate.required_role_teams_verified({"required_approving_review_count": 2}, (101, 202)))
        self.assertFalse(gate.required_role_teams_verified(policy, (101, 101)))
        with patch.object(gate, "strict_ruleset_protected", return_value=False) as strict:
            self.assertFalse(gate.role_review_protected(BASE, 101, 202))
            strict.assert_called_once_with(BASE, role_ids=(101, 202), candidate_head=None)

    def test_personal_repo_requires_two_distinct_codeowners_and_immutable_manifest(self):
        one, two = "assets/live/gaslux_alpha.py", "assets/live/gaslux_beta.py"
        rows = [{"filename": name, "status": "modified"} for name in (one, two)]
        manifest = (f"/.github/CODEOWNERS @safety\n/{one} @safety\n/{two} @owner\n").encode()
        for scenario in ("valid", "one_file", "same_owner", "wildcard", "changed_policy",
                         "no_codeowner_rule", "invalid_owner", "codeowner_errors", "wrong_identity"):
            diff = {"status": "ahead", "ahead_by": 1, "behind_by": 0, "total_commits": 1,
                    "merge_base_commit": {"sha": BASE},
                    "files": rows[:1] if scenario == "one_file" else rows}
            raw = manifest
            if scenario == "same_owner":
                raw = raw.replace(b"@owner", b"@safety")
            if scenario == "wildcard":
                raw += b"* @owner\n"
            def source(path, ref):
                self.assertEqual(path, ".github/CODEOWNERS")
                return raw + (b"# drift\n" if scenario == "changed_policy" and ref == HEAD else b"")
            def read(endpoint):
                if endpoint == "user/101":
                    return {"id": 999 if scenario == "wrong_identity" else 101, "login": "safety", "type": "User"}
                if endpoint == "user/202":
                    return {"id": 202, "login": "owner", "type": "User"}
                if endpoint.endswith("/safety/permission"):
                    return {"user": {"id": 101}, "permission": "write"}
                if endpoint.endswith("/owner/permission"):
                    return {"user": {"id": 202}, "permission": "read" if scenario == "invalid_owner" else "write"}
                if "/codeowners/errors?" in endpoint:
                    return {"errors": [{"kind": "invalid"}] if scenario == "codeowner_errors" else []}
                self.fail(endpoint)
            with patch.object(A, "api", return_value=diff), patch.object(A, "source_at", side_effect=source), \
                    patch.object(gate, "readonly_gh_json", side_effect=read):
                result = gate.required_role_codeowners_verified(
                    BASE, HEAD, {"require_code_owner_review": scenario != "no_codeowner_rule"}, (101, 202))
                self.assertEqual(result, scenario == "valid", scenario)

    def test_app_mint_identity_and_scope_fail_closed(self):
        env = {"GH_TOKEN": "fixture-only",
               "GASLUX_SAFETY_APP_CLIENT_ID": "Iv1.safety123",
               "GASLUX_OWNER_APP_CLIENT_ID": "Iv1.owner123",
               "GASLUX_PUBLISH_APP_CLIENT_ID": "Iv1.publisher123",
               "GASLUX_MINTED_APP_SLUG": "gaslux-safety",
               "GASLUX_MINTED_INSTALLATION_ID": "12345"}
        for scenario in ("valid", "same_client", "publisher_slug", "wrong_client",
                         "write_contents", "admin_permission", "wrong_repo", "extra_repo",
                         "wrong_bot", "publisher_id", "missing_installation"):
            current = dict(env)
            if scenario == "same_client":
                current["GASLUX_OWNER_APP_CLIENT_ID"] = current["GASLUX_SAFETY_APP_CLIENT_ID"]
            if scenario == "publisher_slug":
                current["GASLUX_MINTED_APP_SLUG"] = "gaslux-autonomous-publisher"
            if scenario == "missing_installation":
                current["GASLUX_MINTED_INSTALLATION_ID"] = ""
            permissions = dict(gate.REVIEW_APP_PERMISSIONS)
            if scenario == "write_contents":
                permissions["contents"] = "write"
            if scenario == "admin_permission":
                permissions["administration"] = "write"
            def read(path):
                if path == "apps/gaslux-safety":
                    return {"id": 70, "slug": "gaslux-safety", "permissions": permissions,
                            "client_id": "wrong" if scenario == "wrong_client" else env["GASLUX_SAFETY_APP_CLIENT_ID"]}
                if path == "installation/repositories?per_page=100":
                    return {"total_count": 2 if scenario == "extra_repo" else 1,
                            "repositories": [{"full_name": "other/repo" if scenario == "wrong_repo" else A.REPO}]}
                if path == "users/gaslux-safety%5Bbot%5D":
                    return {"type": "User" if scenario == "wrong_bot" else "Bot",
                            "login": "gaslux-safety[bot]", "id": 41898282 if scenario == "publisher_id" else 101}
                self.fail(path)
            with patch.dict(os.environ, current), patch.object(gate, "readonly_gh_json", side_effect=read):
                if scenario == "valid":
                    self.assertEqual(gate.review_app_actor("safety"), 101)
                else:
                    with self.assertRaises(ValueError):
                        gate.review_app_actor("safety")

    def test_paused_probe_validates_actual_identity_without_writes(self):
        env = {"GITHUB_REPOSITORY": A.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GASLUX_AUTONOMY_PAUSED": "true",
               "GH_TOKEN": "fixture-only"}
        for actor, kind, expected in ((101, "safety", True), (202, "owner", True),
                                       (202, "safety", False), (101, "owner", False)):
            with patch.dict(os.environ, env), patch.object(gate, "configured_reviewers",
                    return_value=(101, {"mint": 202})), patch.object(gate, "review_app_actor",
                    return_value=actor), patch.object(A, "api") as api:
                out = gate.credential_probe(kind)
                self.assertEqual(out["credential_verified"], expected)
                self.assertFalse(out["merge_authorized"])
                self.assertFalse(out["review_capability_verified"])
                self.assertFalse(out["server_role_enforcement_verified"])
                api.assert_not_called()
        with patch.dict(os.environ, {**env, "GASLUX_AUTONOMY_PAUSED": "false"}), \
                patch.object(gate, "readonly_gh_json") as read:
            with self.assertRaises(ValueError):
                gate.credential_probe("safety")
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
