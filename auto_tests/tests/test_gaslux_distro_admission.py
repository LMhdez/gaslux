"""Adversarial tests of the distro admission stage; no GitHub network."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_distro_admission as gate

HEAD = "a" * 40
BASE = "b" * 40


class AdmissionTests(unittest.TestCase):
    def review(self, **updates):
        return {"user": {"id": 2}, "state": "APPROVED", "commit_id": HEAD,
                "body": f"GASLUX-SAFETY-V1 head={HEAD} base={BASE}", **updates}

    def test_exact_review(self):
        self.assertTrue(gate.review_ok([self.review()], 2, 1, HEAD, BASE))

    def test_review_absent_self_or_unconfigured(self):
        for rows, reviewer in [([], 2), ([self.review()], None), ([self.review()], 1)]:
            self.assertFalse(gate.review_ok(rows, reviewer, 1, HEAD, BASE))

    def test_stale_dismissed_wrong_actor_or_comment(self):
        for changes in [{"commit_id": BASE}, {"body": "SAFETY_APPROVED"},
                        {"state": "DISMISSED"}, {"state": "COMMENTED"},
                        {"user": {"id": 3}}]:
            self.assertFalse(gate.review_ok([self.review(**changes)], 2, 1, HEAD, BASE))

    def test_objection(self):
        self.assertFalse(gate.review_ok(
            [self.review(), self.review(state="CHANGES_REQUESTED")], 2, 1, HEAD, BASE))

    def test_page_truncation(self):
        with self.assertRaises(ValueError):
            gate.complete_page([{}] * 100)

    def test_required_ci(self):
        rows = [{"name": name, "head_sha": HEAD, "status": "completed",
                 "conclusion": "success", "app": {"slug": "github-actions"}}
                for name in gate.COMMON_CHECKS | {"read-only-contracts"}]
        data = {"total_count": len(rows), "check_runs": rows}
        self.assertTrue(gate.checks_ok(data, HEAD, "zorin"))
        self.assertFalse(gate.checks_ok(data, HEAD, "cachyos"))
        self.assertFalse(gate.checks_ok({"total_count": 0, "check_runs": []}, HEAD, "zorin"))
        self.assertFalse(gate.checks_ok({**data, "total_count": 101}, HEAD, "zorin"))
        for field, value in [("head_sha", BASE), ("conclusion", "skipped"),
                             ("status", "in_progress"), ("app", {"slug": "other"})]:
            modified = [{**rows[0], field: value}, *rows[1:]]
            self.assertFalse(gate.checks_ok({**data, "check_runs": modified}, HEAD, "zorin"))

    def test_append_no_execution(self):
        before = b"# original\n"
        after = before + b"\ndef assess_zorin_lifecycle(evidence: dict) -> dict:\n    return {}\n"
        with patch.object(gate, "validate_addition") as validator:
            gate.exact_append(before, after, "zorin")
            self.assertEqual(validator.call_args.kwargs, {"execute": False})
        with self.assertRaises(ValueError):
            gate.exact_append(before, b"# replaced\n" + after, "zorin")

    def test_formatted_append_requires_exact_separator(self):
        before = b"# original\n"
        after = before + b"\n\ndef assess_zorin_lifecycle(evidence: dict) -> dict:\n    return {}\n"
        with patch.object(gate, "validate_addition"):
            gate.exact_append(before, after, "zorin", formatted=True)
            with self.assertRaises(ValueError):
                gate.exact_append(before, after, "zorin")

    def test_repaired_candidate_and_semantic_change(self):
        generated = "c" * 40
        path = "assets/live/example.py"
        pr = {"commits": 2, "head": {"ref": f"bot/gaslux-feature-zorin-{BASE[:12]}"}}
        before = b"# original\n"
        original = before + (
            b"\ndef assess_zorin_lifecycle(evidence: dict) -> dict:\n"
            b"    return {'safe': False}\n"
        )
        formatted = before + (
            b'\n\ndef assess_zorin_lifecycle(evidence: dict) -> dict:\n'
            b'    return {"safe": False}\n'
        )
        for final in (formatted, formatted.replace(b"False", b"True")):
            with (
                patch.object(gate, "single_parent", side_effect=[generated, BASE]),
                patch.object(gate, "one_path_commit") as scope,
                patch.object(gate, "source_at", side_effect=[before, original, final]),
                patch.object(gate, "validate_addition") as validator,
                patch.object(gate, "require_fixed_lifecycle"),
                patch.object(gate, "api", return_value={"author": {"id": 9}}),
            ):
                if final == formatted:
                    self.assertEqual(gate.candidate_append(pr, "zorin", HEAD, path), (BASE, 9))
                    self.assertEqual(scope.call_count, 2)
                    self.assertEqual(validator.call_count, 2)
                else:
                    with self.assertRaises(ValueError):
                        gate.candidate_append(pr, "zorin", HEAD, path)

    def test_fixed_semantics_for_all_queued_roles(self):
        for role in gate.QUEUE.values():
            for local in ("missing", "missingGates"):
                with self.subTest(role=role, local=local):
                    source = (
                        f"def assess_{role}_lifecycle(evidence: dict) -> dict:\n"
                        f"    gates = {gate.LIFECYCLE_GATES!r}\n"
                        f"    {local} = sorted([name for name in gates if evidence.get(name) is not True])\n"
                        f"    return {{'backend': {role!r}, 'missingGates': {local}, "
                        "'installationAuthorized': False, 'releaseEligible': False}\n"
                    )
                    gate.require_fixed_lifecycle(role, source)
                    for changed in (
                        source.replace("'installationAuthorized': False", "'installationAuthorized': True"),
                        source.replace("'releaseEligible': False", "'releaseEligible': bool(evidence)"),
                        source.replace("is not True", "!= True"),
                        source.replace("'windows-return', ", ""),
                        source.replace("evidence.get(name)", "evidence.get('install')"),
                        source.replace(f"'missingGates': {local}", "'missingGates': []"),
                        source.replace("'releaseEligible': False", "'releaseEligible': False, 'releaseEligible': True"),
                        source.replace("    return", "    if evidence:\n        return {}\n    return"),
                    ):
                        self.assertNotEqual(changed, source)
                        with self.assertRaises(ValueError):
                            gate.require_fixed_lifecycle(role, changed)

    def test_intermediate_offscope_commit_rejected(self):
        good = {"status": "ahead", "ahead_by": 1, "behind_by": 0, "total_commits": 1,
                "merge_base_commit": {"sha": BASE},
                "files": [{"filename": "allowed.py", "status": "modified"}]}
        with patch.object(gate, "api", return_value=good):
            gate.one_path_commit(BASE, HEAD, "allowed.py")
        for changed in ({**good, "files": good["files"] + [{"filename": "other.py"}]},
                        {**good, "ahead_by": 2}, {**good, "behind_by": 1}):
            with patch.object(gate, "api", return_value=changed):
                with self.assertRaises(ValueError):
                    gate.one_path_commit(BASE, HEAD, "allowed.py")

    def test_unsupported_history_rejected(self):
        for count in (0, 3, True, "2"):
            with self.assertRaises(ValueError):
                gate.candidate_append({"commits": count}, "zorin", HEAD, "allowed.py")

    def test_full_read_only_admission_for_repaired_history(self):
        generated = "c" * 40
        drift = "d" * 40
        path = gate.TASKS["zorin"][0]
        before = b"# existing source\n"
        gates = (
            "source-authenticity", "windows-preflight", "install",
            "linux-first-boot", "windows-return", "linux-update-reboot",
            "uninstall-windows-integrity", "fault-injection-rollback",
        )
        function = (
            "def assess_zorin_lifecycle(evidence: dict) -> dict:\n"
            f"    gates = {gates!r}\n"
            "    missing = sorted([name for name in gates if evidence.get(name) is not True])\n"
            "    return {'backend': 'zorin', 'missingGates': missing, "
            "'installationAuthorized': False, 'releaseEligible': False}\n"
        ).encode()
        initial = before + b"\n" + function
        repaired = before + b"\n\n" + function.replace(b"'", b'"')
        pr = {
            "number": 395, "state": "open", "draft": True, "commits": 2,
            "user": {"login": "gaslux-autonomous-publisher[bot]", "id": 1},
            "head": {"sha": HEAD, "repo": {"full_name": gate.REPO},
                     "ref": f"bot/gaslux-feature-zorin-{BASE[:12]}"},
            "base": {"ref": "dev", "repo": {"full_name": gate.REPO}},
        }
        file_row = {"filename": path, "status": "modified",
                    "additions": 20, "deletions": 0}
        checks = [{"name": name, "head_sha": HEAD, "status": "completed",
                   "conclusion": "success", "app": {"slug": "github-actions"}}
                  for name in gate.COMMON_CHECKS | {"read-only-contracts"}]

        for scenario in ("valid", "self_repair_review", "no_review",
                         "stale_base", "head_drift", "offscope_intermediate",
                         "owner_approved", "owner_wrong_role", "owner_self_review",
                         "owner_stale_base", "owner_objection"):
            with self.subTest(scenario=scenario):
                live_dev = drift if scenario in ("stale_base", "owner_stale_base") else BASE
                reviewer = 9 if scenario == "self_repair_review" else 2
                reviews = [] if scenario == "no_review" else [{
                    "user": {"id": reviewer}, "state": "APPROVED", "commit_id": HEAD,
                    "body": f"GASLUX-SAFETY-V1 head={HEAD} base={live_dev}",
                }]
                owner_id = None
                if scenario.startswith("owner_"):
                    owner_id = 9 if scenario == "owner_self_review" else 3
                    owner_role = "bazzite" if scenario == "owner_wrong_role" else "zorin"
                    reviews.append({
                        "user": {"id": owner_id}, "state": "APPROVED", "commit_id": HEAD,
                        "body": f"GASLUX-BACKEND-OWNER-V1 role={owner_role} head={HEAD} base={live_dev}",
                    })
                    if scenario == "owner_objection":
                        reviews.append({"user": {"id": 5}, "state": "CHANGES_REQUESTED"})
                pr_reads = 0

                def api(method, route):
                    nonlocal pr_reads
                    self.assertEqual(method, "GET")
                    if route == "/pulls/395":
                        pr_reads += 1
                        if scenario == "head_drift" and pr_reads > 1:
                            return {**pr, "head": {**pr["head"], "sha": drift}}
                        return pr
                    if route == "/git/ref/heads/dev":
                        return {"object": {"sha": live_dev}}
                    if route == "/pulls/395/files?per_page=100":
                        return [file_row]
                    if route == f"/git/commits/{HEAD}":
                        return {"parents": [{"sha": generated}]}
                    if route == f"/git/commits/{generated}":
                        return {"parents": [{"sha": BASE}]}
                    for parent, child in ((BASE, generated), (generated, HEAD)):
                        if route == f"/compare/{parent}...{child}":
                            files = [file_row]
                            if scenario == "offscope_intermediate" and child == generated:
                                files.append({"filename": "other.py", "status": "modified"})
                            return {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                                    "total_commits": 1, "merge_base_commit": {"sha": parent},
                                    "files": files}
                    for ref, raw in ((BASE, before), (generated, initial), (HEAD, repaired)):
                        if route == f"/contents/{path}?ref={ref}":
                            return {"type": "file", "encoding": "base64",
                                    "content": gate.base64.b64encode(raw).decode()}
                    if route == f"/commits/{HEAD}":
                        return {"author": {"id": 9}}
                    if route == f"/commits/{HEAD}/check-runs?per_page=100":
                        return {"total_count": len(checks), "check_runs": checks}
                    if route == "/pulls/395/reviews?per_page=100":
                        return reviews
                    if route == "/issues/395/comments?per_page=100":
                        return []
                    self.fail(f"Unexpected API route: {route}")

                # Only the API transport is mocked; real source checks and AST
                # validation run without executing the proposed helper.
                with patch.object(gate, "api", side_effect=api):
                    row = gate.inspect(395, "zorin", reviewer, owner_id)
                self.assertEqual(row["status"], "blocked")
                for key in ("merge_authorized", "release_eligible",
                            "full_vm_acceptance_verified"):
                    self.assertFalse(row[key])
                self.assertEqual(row["backend_owner_verified"], scenario == "owner_approved")
                if scenario in ("head_drift", "offscope_intermediate"):
                    self.assertFalse(row["exact_scope_verified"])
                    self.assertFalse(row["safety_review_verified"])
                else:
                    self.assertTrue(row["exact_scope_verified"])
                    self.assertTrue(row["ci_verified"])
                    self.assertEqual(row["current_base_verified"], scenario not in ("stale_base", "owner_stale_base"))
                    self.assertEqual(row["safety_review_verified"],
                                     scenario not in ("self_repair_review", "no_review", "owner_objection"))

    def test_owner_config_is_strict(self):
        self.assertEqual(gate.parse_owner_ids('{"zorin":3,"cachyos":4}'),
                         {"zorin": 3, "cachyos": 4})
        for raw in ('', '[]', 'null', '{"zorin":true}', '{"zorin":"3"}',
                    '{"zorin":0}', '{"zorin":-1}', '{"mint":3}',
                    '{"zorin":3,"zorin":4}', '{"zorin":10000000000000000000}',
                    ' ' * 1025):
            with self.subTest(raw=raw):
                self.assertEqual(gate.parse_owner_ids(raw), {})

    def test_owner_review_is_separate_and_exact(self):
        marker = f"GASLUX-BACKEND-OWNER-V1 role=zorin head={HEAD} base={BASE}"
        owner = {"user": {"id": 3}, "state": "APPROVED",
                 "commit_id": HEAD, "body": marker}
        self.assertTrue(gate.owner_review_ok([owner], 3, 2, 1, 9, "zorin", HEAD, BASE))
        for owner_id, safety_id, author_id, repair_id in (
            (None, 2, 1, 9), (True, 2, 1, 9), (3, None, 1, 9),
            (3, 3, 1, 9), (3, 2, 3, 9), (3, 2, 1, 3), (3, 2, 1, 2),
        ):
            self.assertFalse(gate.owner_review_ok(
                [owner], owner_id, safety_id, author_id, repair_id, "zorin", HEAD, BASE))
        for reviews in (
            [], [{**owner, "state": "COMMENTED"}],
            [{**owner, "state": "DISMISSED"}],
            [{**owner, "body": marker.replace("role=zorin", "role=bazzite")}],
            [{**owner, "commit_id": BASE}],
            [{**owner, "body": marker.replace(f"base={BASE}", f"base={HEAD}")}],
            [owner, {**owner, "state": "DISMISSED"}],
            [owner, {"user": {"id": 5}, "state": "CHANGES_REQUESTED"}],
        ):
            self.assertFalse(gate.owner_review_ok(reviews, 3, 2, 1, 9, "zorin", HEAD, BASE))

    def test_api_failure_is_blocked(self):
        with patch.object(gate, "api", side_effect=RuntimeError("offline")):
            row = gate.inspect(395, "zorin", 2)
        self.assertEqual(row["status"], "blocked")
        self.assertFalse(row["merge_authorized"])
        self.assertFalse(row["release_eligible"])
        self.assertFalse(row["safety_review_verified"])


if __name__ == "__main__":
    unittest.main()
