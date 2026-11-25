"""Offline adversarial tests of bounded AI proposals, never a disk writer."""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gaslux_agent_feature_factory.py"
SPEC = importlib.util.spec_from_file_location("gaslux_agent_feature_factory", SCRIPT)
assert SPEC and SPEC.loader
factory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(factory)


def valid(role: str) -> str:
    gates = repr(factory.GATES)
    return (
        f"def assess_{role}_lifecycle(evidence: dict) -> dict:\n"
        f"    gates = {gates}\n"
        "    missing = sorted([name for name in gates if evidence.get(name) is not True])\n"
        f"    return {{'backend': '{role}', 'missingGates': missing, "
        "'installationAuthorized': False, 'releaseEligible': False}\n"
    )


class FeatureFactoryTests(unittest.TestCase):
    def test_all_six_roles_have_scoped_real_product_source_and_test(self):
        self.assertEqual(
            set(factory.TASKS),
            {"mint", "zorin", "cachyos", "popos", "q4os", "bazzite"},
        )
        for role, (source, test, _) in factory.TASKS.items():
            self.assertTrue(source.startswith("assets/live/"))
            self.assertTrue(source.endswith(".py"))
            self.assertTrue(test.startswith("test_"))
            self.assertNotIn("..", Path(source).parts)
            self.assertNotIn("..", Path(test).parts)
            factory.validate_addition(role, valid(role), execute=True)

    def test_goal_discovery_is_bounded_read_only_and_uses_real_dev_matrix(self):
        """A claimed six-role catalog is blocked work, not completion."""
        platforms = [
            "windows10-bios-mbr", "windows10-uefi-gpt", "windows11-uefi-gpt",
        ]
        goal = {
            "schema_version": 1, "platforms": platforms,
            "gates": list(factory.GATES),
            "automatic_safe_gates": list(factory.GATES[:2]),
            "protected_gates": list(factory.GATES[2:]),
            "backends": [
                {
                    "id": role, "priority": i, "issue_numbers": [],
                    "platforms": platforms[1:] if role == "bazzite" else platforms,
                }
                for i, role in enumerate(factory.TASKS)
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs/autonomy"
            docs.mkdir(parents=True)
            evidence = {"schema_version": 1, "records": []}
            def store():
                (docs / "goal.json").write_text(json.dumps(goal))
                (docs / "evidence.json").write_text(json.dumps(evidence))
            store()
            result = factory.discover_goal_backlog(root)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["required_gate_slots"], 136)
            self.assertEqual(result["independently_verified_slots"], 0)
            self.assertEqual({x["role"] for x in result["next_gates"]},
                             set(factory.TASKS))
            self.assertTrue(all(
                not x["code_authorized"] and not x["release_eligible"]
                for x in result["next_gates"]
            ))
            self.assertEqual(result["next_gates"][-1]["platform"],
                             "windows10-uefi-gpt")
            self.assertEqual(result["next_gates"][0]["state"], "missing_evidence")

            evidence["records"] = [{
                "backend": "mint", "platform": platforms[0],
                "gate": factory.GATES[0], "claimed_pass": True,
            }]
            store()
            result = factory.discover_goal_backlog(root)
            self.assertEqual(result["next_gates"][0]["state"],
                             "declared_unverified")
            self.assertEqual(result["independently_verified_slots"], 0)
            evidence["records"] *= 2
            store()
            with self.assertRaises(ValueError):
                factory.discover_goal_backlog(root)
            evidence["records"] = []
            goal["backends"][-1]["platforms"] = platforms
            store()
            with self.assertRaises(ValueError):
                factory.discover_goal_backlog(root)
            goal["backends"][-1]["platforms"] = platforms[1:]
            goal["gates"][0] = "synthetic-success"
            store()
            with self.assertRaises(ValueError):
                factory.discover_goal_backlog(root)

    def test_full_six_distro_gate_inventory_is_blocked_without_real_evidence(self):
        """Enumerate 136 exact slots; dev JSON cannot grant product authority."""
        platforms = [
            "windows10-bios-mbr", "windows10-uefi-gpt",
            "windows11-uefi-gpt",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs/autonomy"
            docs.mkdir(parents=True)
            goal = {
                "schema_version": 1,
                "gates": list(factory.GATES),
                "platforms": platforms,
                "automatic_safe_gates": list(factory.GATES[:2]),
                "protected_gates": list(factory.GATES[2:]),
                "backends": [
                    {
                        "id": role, "priority": i,
                        "platforms": platforms[1:] if role == "bazzite"
                                     else platforms,
                        "issue_numbers": [],
                    }
                    for i, role in enumerate(factory.TASKS)
                ],
            }
            (docs / "goal.json").write_text(json.dumps(goal))
            evidence = {"schema_version": 1, "records": []}
            (docs / "evidence.json").write_text(json.dumps(evidence))
            result = factory.discover_goal_backlog(root)
            items = result["work_items"]
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(len(items), 136)
            self.assertEqual(result["required_gate_slots"], 136)
            self.assertEqual(result["scope_review_slots"], 34)
            self.assertEqual(result["protected_vm_slots"], 102)
            self.assertEqual(result["declared_unverified_slots"], 0)
            self.assertEqual(result["independently_verified_slots"], 0)
            self.assertEqual(len(result["next_gates"]), 6)
            self.assertEqual(
                len(set((x["role"], x["platform"], x["gate"]) for x in items)),
                136,
            )
            self.assertFalse(any(
                x["role"] == "bazzite" and
                x["platform"] == "windows10-bios-mbr" for x in items
            ))
            for item in items:
                with self.subTest(key=(item["role"], item["platform"],
                                       item["gate"])):
                    self.assertIs(item["code_authorized"], False)
                    self.assertIs(item["installation_authorized"], False)
                    self.assertIs(item["release_eligible"], False)
                    self.assertEqual(
                        item["prerequisite_gates"],
                        list(factory.GATES[:factory.GATES.index(item["gate"])]),
                    )
                    self.assertEqual(
                        item["scope_status"],
                        "needs_scope_review" if item["gate"] in factory.GATES[:2]
                        else "blocked_external_vm_evidence",
                    )
                    self.assertEqual(
                        item["source_target"], factory.TASKS[item["role"]][0]
                    )
                    self.assertEqual(
                        item["test_target"],
                        "auto_tests/tests/" + factory.TASKS[item["role"]][1],
                    )
            # Even attacker-controlled records claiming full installation
            # verification cannot become independently verified.
            evidence["records"] = [
                {"backend": "mint", "platform": "windows10-bios-mbr",
                 "gate": "source-authenticity", "claimed_pass": True},
                {"backend": "bazzite", "platform": "windows11-uefi-gpt",
                 "gate": "fault-injection-rollback", "verified": True,
                 "release_eligible": True},
            ]
            (docs / "evidence.json").write_text(json.dumps(evidence))
            later = factory.discover_goal_backlog(root)
            self.assertEqual(later["declared_unverified_slots"], 2)
            self.assertEqual(later["independently_verified_slots"], 0)
            self.assertEqual(later["scope_review_slots"], 34)
            self.assertEqual(later["protected_vm_slots"], 102)
            claimed = [
                x for x in later["work_items"]
                if x["state"] == "declared_unverified"
            ]
            self.assertEqual(len(claimed), 2)
            self.assertTrue(all(
                x["code_authorized"] is False and
                x["installation_authorized"] is False and
                x["release_eligible"] is False for x in claimed
            ))

    def test_six_backend_backlog_artifact_does_not_expand_model_permissions(self):
        workflow = (
            SCRIPT.parents[2] /
            ".github/workflows/gaslux-agent-feature-factory.yml"
        ).read_text()
        before_model, after_model = workflow.split("  model:\n", 1)
        self.assertIn(
            "if: steps.plan.outputs.blocked == 'true'", before_model
        )
        self.assertIn(
            "name: gaslux-six-backend-gate-backlog", before_model
        )
        self.assertIn(
            "path: /tmp/gaslux-feature-plan.json", before_model
        )
        self.assertIn(
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            before_model,
        )
        self.assertNotIn("issues: write", before_model)
        self.assertNotIn("GASLUX_PUBLISH_APP_PRIVATE_KEY", before_model)
        self.assertIn("if: needs.select.outputs.active == 'true'", after_model)
        self.assertIn("No new Qwen code scope authorized", before_model)
        self.assertIn("protected_vm_slots", before_model)

    def test_plan_reports_real_blocked_gates_when_all_six_roles_claimed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            platforms = [
                "windows10-bios-mbr", "windows10-uefi-gpt",
                "windows11-uefi-gpt",
            ]
            docs = root / "docs/autonomy"
            docs.mkdir(parents=True)
            (docs / "goal.json").write_text(json.dumps({
                "schema_version": 1,
                "platforms": platforms,
                "gates": list(factory.GATES),
                "automatic_safe_gates": list(factory.GATES[:2]),
                "protected_gates": list(factory.GATES[2:]),
                "backends": [
                    {
                        "id": role, "priority": i, "issue_numbers": [],
                        "platforms": platforms[1:] if role == "bazzite"
                                     else platforms,
                    }
                    for i, role in enumerate(factory.TASKS)
                ],
            }))
            (docs / "evidence.json").write_text(
                json.dumps({"schema_version": 1, "records": []})
            )
            for role, (path, _, _) in factory.TASKS.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("a", encoding="utf-8") as output:
                    output.write(f"def assess_{role}_lifecycle(evidence: dict) -> dict:\n")
            with patch.object(factory, "git", return_value="a" * 40), \
                 patch.object(factory.subprocess, "run") as run:
                result = factory.plan(root)
                run.assert_not_called()
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["base"], "a" * 40)
            self.assertEqual(len(result["next_gates"]), 6)

    def role_pr(self, role: str, *, suffix="a" * 12,
                author="github-actions[bot]", repo=None, base="dev"):
        return {
            "state": "open", "draft": True,
            "head": {
                "ref": f"bot/gaslux-feature-{role}-{suffix}",
                "repo": {"full_name": repo or factory.REPO},
            },
            "base": {"ref": base, "repo": {"full_name": factory.REPO}},
            "user": {"login": author, "type": "Bot"},
        }

    def test_existing_role_prs_dedupe_across_dev_sha_changes(self):
        drafts = [
            self.role_pr("zorin", suffix="5c34b16651f1"),
            self.role_pr("cachyos", suffix="5c34b16651f1"),
            self.role_pr("popos", suffix="d89f1547c507",
                         author="gaslux-autonomous-publisher[bot]"),
            self.role_pr("q4os", suffix="5c34b16651f1"),
            self.role_pr("bazzite", suffix="5c34b16651f1"),
        ]
        done = subprocess.CompletedProcess([], 0, json.dumps(drafts), "")
        with patch.object(factory.subprocess, "run", return_value=done) as run:
            claims = factory.open_role_drafts()
        self.assertEqual(
            claims, {"zorin", "cachyos", "popos", "q4os", "bazzite"}
        )
        run.assert_called_once()
        self.assertIn("pulls?state=open&per_page=100", run.call_args.args[0][-1])

    def test_role_dedup_ignores_foreign_forks_but_denies_unknown_actor(self):
        rows = [
            self.role_pr("zorin", repo="outsider/gaslux"),
            self.role_pr("popos", base="main"),
        ]
        with patch.object(factory.subprocess, "run", return_value=(
            subprocess.CompletedProcess([], 0, json.dumps(rows), "")
        )):
            self.assertEqual(factory.open_role_drafts(), set())
        rows.append(self.role_pr("cachyos", author="untrusted-app[bot]"))
        with patch.object(factory.subprocess, "run", return_value=(
            subprocess.CompletedProcess([], 0, json.dumps(rows), "")
        )):
            with self.assertRaisesRegex(RuntimeError, "Unknown"):
                factory.open_role_drafts()
        rows[-1]["user"]["type"] = "User"
        with patch.object(factory.subprocess, "run", return_value=(
            subprocess.CompletedProcess([], 0, json.dumps(rows), "")
        )):
            with self.assertRaisesRegex(RuntimeError, "Unknown"):
                factory.open_role_drafts()

    def test_role_dedup_fails_closed_on_api_error_or_unbounded_pr_list(self):
        bad = [
            subprocess.CompletedProcess([], 1, "", "API rejected"),
            subprocess.CompletedProcess(
                [], 0, json.dumps([self.role_pr("zorin")] * 100), ""
            ),
            subprocess.CompletedProcess([], 0, '{"bad":"shape"}', ""),
        ]
        with patch.object(factory.subprocess, "run") as run:
            for result in bad:
                with self.subTest(result=result.stdout[:24]):
                    run.return_value = result
                    with self.assertRaises((RuntimeError, ValueError)):
                        factory.open_role_drafts()

    def test_live_plan_blocks_duplicate_roles_even_when_dev_moved(self):
        platforms = [
            "windows10-bios-mbr", "windows10-uefi-gpt",
            "windows11-uefi-gpt",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs/autonomy"
            docs.mkdir(parents=True)
            goal = {
                "schema_version": 1, "platforms": platforms,
                "gates": list(factory.GATES),
                "automatic_safe_gates": list(factory.GATES[:2]),
                "protected_gates": list(factory.GATES[2:]),
                "backends": [
                    {
                        "id": role, "priority": i, "issue_numbers": [],
                        "platforms": platforms[1:] if role == "bazzite"
                                     else platforms,
                    }
                    for i, role in enumerate(factory.TASKS)
                ],
            }
            (docs / "goal.json").write_text(json.dumps(goal))
            (docs / "evidence.json").write_text(
                json.dumps({"schema_version": 1, "records": []})
            )
            for role, (source, _, _) in factory.TASKS.items():
                target = root / source
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    "def assess_mint_lifecycle(evidence: dict) -> dict:\n"
                    if role == "mint" else "# product source\n"
                )
            # Mint and CachyOS intentionally share one module: the loop
            # above replaces the same fixture path for the CachyOS role.
            mint_target = root / factory.TASKS["mint"][0]
            mint_target.write_text(
                mint_target.read_text() +
                "def assess_mint_lifecycle(evidence: dict) -> dict:\n"
            )
            old_sha_drafts = [
                self.role_pr(role, suffix="5c34b16651f1")
                for role in ("zorin", "cachyos", "popos", "q4os", "bazzite")
            ]
            with patch.object(factory, "git", return_value="d" * 40), \
                 patch.object(factory.subprocess, "run", return_value=(
                     subprocess.CompletedProcess(
                         [], 0, json.dumps(old_sha_drafts), ""
                     )
                 )) as run:
                result = factory.plan(root)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["base"], "d" * 40)
            self.assertEqual(result["required_gate_slots"], 136)
            self.assertEqual(result["scope_review_slots"], 34)
            self.assertEqual(result["protected_vm_slots"], 102)
            self.assertEqual(result["independently_verified_slots"], 0)
            run.assert_called_once()

    def test_factory_style_enforcement_retries_before_artifact_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / factory.TASKS["popos"][0]
            src.parent.mkdir(parents=True)
            src.write_text("# previous product\n")
            artifact = root / "evidence"
            with patch.dict(
                "os.environ", {"GASLUX_FACTORY_RUFF_ENFORCE": "true"}
            ), patch.object(
                factory, "git", return_value="a" * 40
            ), patch.object(
                factory, "call_model", return_value=valid("popos")
            ) as model:
                with self.assertRaisesRegex(RuntimeError, "Ruff E501"):
                    factory.generate(root, artifact, "popos", "a" * 40)
            self.assertEqual(model.call_count, 2)
            self.assertFalse((artifact / "addition.py").exists())
            self.assertFalse((artifact / "report.json").exists())

    def test_factory_pinned_ruff_precedes_publication_and_safety(self):
        workflow = (
            SCRIPT.parents[2] /
            ".github/workflows/gaslux-agent-feature-factory.yml"
        ).read_text()
        model, rest = workflow.split("  safety:\n", 1)
        self.assertIn("GASLUX_FACTORY_RUFF_ENFORCE: 'true'", model)
        self.assertIn("'ruff==0.17.6'", model)
        self.assertIn(
            "python3 -m ruff check --config trusted/auto_tests/pyproject.toml",
            model,
        )
        self.assertIn(
            "python3 -m ruff format --check --config trusted/auto_tests/pyproject.toml",
            model,
        )
        self.assertNotIn("issues: write", model)
        self.assertNotIn("GASLUX_PUBLISH_APP_PRIVATE_KEY", model)
        self.assertIn("  publish_draft:", rest)

    def test_no_remote_writer_or_insecure_backend_authority(self):
        for role in factory.TASKS:
            src = valid(role)
            self.assertRaises(ValueError, factory.validate_addition, role,
                              src + "open('/tmp/owned', 'w')\n", execute=True)
            self.assertRaises(ValueError, factory.validate_addition, role,
                              src.replace("'releaseEligible': False", "'releaseEligible': True"),
                              execute=True)
            self.assertRaises(ValueError, factory.validate_addition, role,
                              src.replace("is not True", "is True"), execute=True)

    def test_import_i_o_globals_and_other_code_rejected(self):
        source = valid("mint")
        for extra in ("import os\n", "exec('1')\n",
                      "class Danger:\n    pass\n", "def bypass():\n    pass\n"):
            with self.assertRaises(ValueError):
                factory.validate_addition("mint", source + extra, execute=True)
        with self.assertRaises(ValueError):
            factory.validate_addition("mint", source.replace(
                "evidence.get(name)", "evidence.__class__"), execute=True)
        with self.assertRaises(ValueError):
            factory.validate_addition("mint", source.replace(
                "return {", "while True:\n        pass\n    return {"), execute=True)

    def test_reports_bound_to_exact_base_source_and_artifact_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / factory.TASKS["popos"][0]
            source.parent.mkdir(parents=True)
            source.write_text("# original\n")
            evidence = root / "evidence"
            evidence.mkdir()
            code = valid("popos")
            (evidence / "addition.py").write_text(code)
            before, after = factory.expected_source(root, "popos", code)
            report = {
                "role": "popos", "base": "a" * 40,
                "target": factory.TASKS["popos"][0],
                "task": factory.TASKS["popos"][2],
                "model": factory.MODEL, "model_digest": factory.MODEL_DIGEST,
                "source_sha256": factory.sha256(before),
                "candidate_sha256": factory.sha256(after),
                "addition_sha256": factory.sha256(code.encode()),
            }
            (evidence / "report.json").write_text(json.dumps(report))
            with patch.object(factory, "git", return_value="a" * 40):
                self.assertEqual(factory.verify(root, evidence, "popos", "a" * 40,
                                                execute=True)["role"], "popos")
                (evidence / "addition.py").write_text(code + "# tampered\n")
                with self.assertRaises(ValueError):
                    factory.verify(root, evidence, "popos", "a" * 40, execute=False)

    def test_publish_denies_wrong_branch_before_git_and_model_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"GITHUB_REPOSITORY": factory.REPO,
                                            "GITHUB_REF": "refs/heads/dev"}):
                with patch.object(factory, "git") as mock:
                    with self.assertRaises(ValueError):
                        factory.publish(Path(tmp), Path(tmp), "mint", "a" * 40)
                    mock.assert_not_called()

    def test_only_forward_and_byte_identical_product_and_tests_survive_dev_drift(self):
        root = Path("/tmp/not-used")
        old, new = "a" * 40, "b" * 40
        self.assertTrue(factory.safe_forward_draft_base(root, "mint", old, old))
        with patch.object(factory.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0)), \
             patch.object(factory.subprocess, "check_output",
                          side_effect=[b"source", b"source", b"tests", b"tests"]) as read:
            self.assertTrue(factory.safe_forward_draft_base(root, "mint", old, new))
            self.assertEqual(read.call_count, 4)
        with patch.object(factory.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0)), \
             patch.object(factory.subprocess, "check_output",
                          side_effect=[b"source", b"tampered"]):
            self.assertFalse(factory.safe_forward_draft_base(root, "mint", old, new))
        with patch.object(factory.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 1)), \
             patch.object(factory.subprocess, "check_output") as read:
            self.assertFalse(factory.safe_forward_draft_base(root, "mint", old, new))
            read.assert_not_called()

    def test_qwen_generation_has_strict_schema_and_rejects_extra_keys(self):
        good = json.dumps({"response": json.dumps({"addition": valid("mint")})}).encode()
        bad = json.dumps({"response": json.dumps({
            "addition": valid("mint"), "explanation": "unreviewed"})}).encode()
        with patch.object(factory.urllib.request, "urlopen") as url:
            url.return_value.__enter__.return_value = io.BytesIO(good)
            self.assertIn("def assess_mint", factory.call_model("test"))
            req = url.call_args.args[0]
            data = json.loads(req.data)
            self.assertEqual(data["format"]["required"], ["addition"])
            self.assertIs(data["format"]["additionalProperties"], False)
            url.return_value.__enter__.return_value = io.BytesIO(bad)
            with self.assertRaisesRegex(ValueError, "schema"):
                factory.call_model("test")

    def test_branch_names_are_exactly_scoped_and_no_untrusted_role(self):
        name = factory.origin_branch("bazzite", "a" * 40)
        self.assertEqual(name, "bot/gaslux-feature-bazzite-aaaaaaaaaaaa")
        for role in ("../main", "integrator", "mint; rm"):
            with self.assertRaises(ValueError):
                factory.origin_branch(role, "a" * 40)


    def test_statement_loops_forbidden_but_list_comprehension_accepted(self):
        good = valid("mint")
        self.assertIn("ListComp", {type(n).__name__ for n in factory.ast.walk(
            factory.ast.parse(good))})
        factory.validate_addition("mint", good, execute=True)
        for statement, category in (
            ("for item in ():\\n        pass", "For"),
            ("while False:\\n        pass", "While"),
        ):
            bad = good.replace("    missing = sorted", "    " + statement.replace(
                "\\n", "\n    ") + "\n    missing = sorted")
            self.assertIn(category, factory.rejection_category(
                bad, ValueError("Code includes a prohibited operation")))
            with self.assertRaisesRegex(ValueError, "prohibited operation"):
                factory.validate_addition("mint", bad, execute=True)

    def test_adversarial_rejections_keep_validator_fail_closed(self):
        source = valid("mint")
        variants = {
            "import": source.replace("    gates =", "    import os\n    gates ="),
            "I/O": source.replace("    gates =", "    open('/tmp/a', 'w')\n    gates ="),
            "exec": source.replace("    gates =", "    exec('1')\n    gates ="),
            "eval": source.replace("    gates =", "    eval('1')\n    gates ="),
            "system": source.replace("    gates =", "    __import__('os').system('id')\n    gates ="),
            "foreign_backend": source.replace("'backend': 'mint'", "'backend': 'zorin'"),
            "wrong_signature": source.replace("evidence: dict", "data: dict"),
            "second_function": source + "\ndef bypass():\n    return True\n",
            "installation_true": source.replace("'installationAuthorized': False",
                                                 "'installationAuthorized': True"),
            "release_true": source.replace("'releaseEligible': False",
                                            "'releaseEligible': True"),
            "oversize": source + ("#" * 5500),
        }
        for name, addition in variants.items():
            with self.subTest(name=name), self.assertRaises(
                (ValueError, SyntaxError)
            ):
                factory.validate_addition("mint", addition, execute=True)
        with self.assertRaises(ValueError):
            factory.validate_addition("mint", valid("zorin"), execute=True)

    def test_valid_helper_non_boolean_and_missing_evidence_never_satisfies_gates(self):
        ns = {}
        exec(compile(valid("mint"), "<test-only-canonical-fixture>", "exec"), ns)
        fn = ns["assess_mint_lifecycle"]
        self.assertEqual(fn({})["missingGates"], sorted(factory.GATES))
        for value in ("True", 1, [True], {}, None, False, 0):
            with self.subTest(value=repr(value)):
                evidence = {gate: True for gate in factory.GATES}
                evidence[factory.GATES[0]] = value
                result = fn(evidence)
                self.assertEqual(result["missingGates"], [factory.GATES[0]])
                self.assertIs(result["installationAuthorized"], False)
                self.assertIs(result["releaseEligible"], False)

    def test_f39101_nested_callback_is_rejected_without_execution(self):
        """Never accept an inner FunctionDef passed as sorted(key=...)."""
        src = valid("mint").replace(
            "    gates =",
            "    def helper(item):\n"
            "        evidence['injected'] = True\n"
            "        return item\n"
            "    sorted([0], key=helper)\n"
            "    gates =",
        )
        self.assertIn("FunctionDef", {
            type(n).__name__ for n in factory.ast.walk(factory.ast.parse(src))
        })
        with patch.dict(factory.SAFE_BUILTINS, {
            "sorted": unittest.mock.Mock(side_effect=AssertionError(
                "untrusted source was executed"))
        }):
            with self.assertRaisesRegex(ValueError, "Nested function"):
                factory.validate_addition("mint", src, execute=True)

    def test_f39101_direct_and_aliased_evidence_mutation_rejected(self):
        """Store into evidence or aliases/subscripts must fail before execution."""
        template = valid("mint")
        variants = {
            "direct_subscript": "    evidence['new-authority-flag'] = True\n",
            "augmented_subscript": "    evidence['new-authority-flag'] += 1\n",
            "in_place_union": "    evidence |= {\'new-authority-flag\': True}\n",
            "indirect_alias": "    same = evidence\n    same['new-authority-flag'] = True\n",
            "nested_dict": ("    nested = evidence.get('source-authenticity')\n"
                            "    nested['new-authority-flag'] = True\n"),
            "subscript_store_in_comprehension": (
                "    [item for evidence['new-authority-flag'] in [True]]\n"),
            "delete_subscript": "    del evidence['source-authenticity']\n",
        }
        for category, insert in variants.items():
            with self.subTest(category=category):
                src = template.replace("    gates =", insert + "    gates =")
                with patch.dict(factory.SAFE_BUILTINS, {
                    "sorted": unittest.mock.Mock(side_effect=AssertionError(
                        "untrusted source was executed"))
                }):
                    with self.assertRaises((ValueError, SyntaxError)):
                        factory.validate_addition("mint", src, execute=True)

    def test_f39101_input_evidence_remains_unchanged_for_valid_helpers(self):
        """Canonical proposals preserve read-only fixtures across all six roles."""
        for role in factory.TASKS:
            with self.subTest(role=role):
                env = {"__builtins__": factory.SAFE_BUILTINS}
                scope = {}
                exec(compile(valid(role), "<trusted-test-fixture>", "exec"),
                     env, scope)
                fn = scope[f"assess_{role}_lifecycle"]
                for value in (True, False, 1, "True", None):
                    evidence = {gate: value for gate in factory.GATES}
                    evidence["extra"] = {"nested": [1, 2, 3]}
                    before = json.dumps(evidence, sort_keys=True)
                    result = fn(evidence)
                    self.assertEqual(json.dumps(evidence, sort_keys=True), before)
                    self.assertIs(result["installationAuthorized"], False)
                    self.assertIs(result["releaseEligible"], False)
                factory.validate_addition(role, valid(role), execute=True)

    def test_mocked_qwen_retries_with_ast_specific_feedback_and_real_bytes(self):
        bad = valid("mint").replace(
            "    missing = sorted",
            "    for item in ():\n        pass\n    missing = sorted",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / factory.TASKS["mint"][0]
            path.parent.mkdir(parents=True)
            path.write_text("# offline source\n", encoding="utf-8")
            evidence = root / "evidence"
            with patch.object(factory, "git", return_value="a" * 40), \
                 patch.object(factory, "call_model", side_effect=[bad, valid("mint")]) as mocked:
                factory.generate(root, evidence, "mint", "a" * 40)
                self.assertEqual(mocked.call_count, 2)
                retry_prompt = mocked.call_args_list[1].args[0]
                self.assertIn("Forbidden AST nodes: For", retry_prompt)
                self.assertIn("list comprehension", retry_prompt)
                self.assertIn("AST For", mocked.call_args_list[0].args[0])
                self.assertEqual((evidence / "addition.py").read_text(), valid("mint"))
                report = json.loads((evidence / "report.json").read_text())
                self.assertEqual(report["addition_sha256"],
                                 factory.sha256(valid("mint").encode()))
                self.assertEqual(report["model"], factory.MODEL)

    def test_mocked_qwen_bounded_rejection_writes_no_candidate(self):
        bad = valid("mint").replace(
            "    missing = sorted",
            "    while False:\n        pass\n    missing = sorted",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / factory.TASKS["mint"][0]
            target.parent.mkdir(parents=True)
            target.write_text("# source\n")
            evidence = root / "evidence"
            with patch.object(factory, "git", return_value="a" * 40), \
                 patch.object(factory, "call_model", return_value=bad) as mocked:
                with self.assertRaisesRegex(RuntimeError, "AST nodes: While"):
                    factory.generate(root, evidence, "mint", "a" * 40)
                self.assertEqual(mocked.call_count, 2)
                self.assertFalse(evidence.exists())


    def test_generated_pr_ci_identity_is_main_scoped_and_minimal(self):
        workflows = (
            (".github/workflows/gaslux-agent-feature-factory.yml", "publish_draft"),
            (".github/workflows/gaslux-agent-clock.yml", "integrator_publisher"),
        )
        for path, job in workflows:
            workflow = (SCRIPT.parents[2] / path).read_text(encoding="utf-8")
            before, publisher = workflow.split(f"  {job}:\n", 1)
            self.assertNotIn("GASLUX_PUBLISH_APP_PRIVATE_KEY", before)
            self.assertNotIn("pull_request_target:", workflow)
            self.assertIn("github.repository == 'LMhdez/gaslux'", publisher)
            self.assertIn("github.ref == 'refs/heads/main'", publisher)
            self.assertIn("    environment: gaslux-main-publisher", publisher)
            self.assertIn("id: publish_identity", publisher)
            self.assertIn("vars.GASLUX_PUBLISH_APP_CLIENT_ID != ''", publisher)
            self.assertIn("secrets.GASLUX_PUBLISH_APP_PRIVATE_KEY", publisher)
            self.assertIn("repositories: gaslux", publisher)
            self.assertIn("permission-contents: write", publisher)
            self.assertIn("permission-pull-requests: write", publisher)
            self.assertIn("GH_TOKEN: ${{ steps.publish_identity.outputs.token || secrets.GITHUB_TOKEN }}", publisher)
            self.assertLess(
                publisher.index("id: publish_identity"),
                publisher.index("GH_TOKEN: ${{ steps.publish_identity.outputs.token"),
            )

class DeterministicRepairTests(unittest.TestCase):
    HEAD, BASE = "a" * 40, "b" * 40

    def test_repair_artifact_bound_to_identity_bytes_and_non_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / factory.TASKS["zorin"][0]
            path.parent.mkdir(parents=True)
            path.write_text("# existing source\n")
            evidence = root / "evidence"
            with patch.object(factory, "git", return_value=self.BASE):
                factory.generate_repair(root, evidence, "zorin", self.BASE, 395, self.HEAD)
                result = factory.verify(root, evidence, "zorin", self.BASE, execute=True,
                                        repair_pr=395, repair_head=self.HEAD)
                self.assertEqual(result["producer"], "trusted-fixed-lifecycle-repair-v1")
                self.assertNotIn("model", result)
                for args in ({}, {"repair_pr": 396, "repair_head": self.HEAD},
                             {"repair_pr": 395, "repair_head": self.BASE}):
                    with self.assertRaises(ValueError):
                        factory.verify(root, evidence, "zorin", self.BASE, execute=False, **args)
                raw = (evidence / "addition.py").read_bytes()
                (evidence / "addition.py").write_bytes(raw.replace(b"False", b"True"))
                with self.assertRaises(ValueError):
                    factory.verify(root, evidence, "zorin", self.BASE, execute=False,
                                   repair_pr=395, repair_head=self.HEAD)

    def test_repair_role_and_identity_fail_closed(self):
        for number, head in ((True, self.HEAD), (0, self.HEAD), (395, None),
                             (None, self.HEAD), (395, "bad")):
            with self.assertRaises(ValueError):
                factory.repair_identity(number, head)
        with self.assertRaises(ValueError):
            factory.repair_addition("mint")
        for role in ("zorin", "cachyos", "popos", "q4os", "bazzite"):
            factory.validate_addition(role, factory.repair_addition(role), execute=True)

    def test_repair_publisher_denies_changed_eligibility_before_git_or_push(self):
        env = {"GITHUB_REPOSITORY": factory.REPO, "GITHUB_REF": "refs/heads/main",
               "GH_TOKEN": "fixture-publisher", "GASLUX_REPAIR_READ_TOKEN": "fixture-reader"}
        with patch.dict("os.environ", env, clear=True), \
             patch.object(factory, "verify"), \
             patch.object(factory, "repair_plan", return_value=None) as plan, \
             patch.object(factory, "git") as git:
            with self.assertRaisesRegex(RuntimeError, "no longer eligible"):
                factory.publish(Path("."), Path("."), "zorin", self.BASE,
                                repair_pr=395, repair_head=self.HEAD)
            plan.assert_called_once()
            git.assert_not_called()
            self.assertEqual(__import__("os").environ["GH_TOKEN"], "fixture-publisher")

    def test_workflow_reuses_existing_isolated_jobs(self):
        workflow = (SCRIPT.parents[2] /
                    ".github/workflows/gaslux-agent-feature-factory.yml").read_text()
        model = workflow.split("  model:\n", 1)[1].split("  safety:\n", 1)[0]
        safety = workflow.split("  safety:\n", 1)[1].split("  publish_draft:\n", 1)[0]
        publisher = workflow.split("  publish_draft:\n", 1)[1].split("  triage_missing_gates:\n", 1)[0]
        self.assertIn("if: needs.select.outputs.repair_pr == ''", model)
        for part in (model, safety, publisher):
            self.assertIn('--repair-pr "$REPAIR_PR" --repair-head "$REPAIR_HEAD"', part)
        self.assertNotIn("GASLUX_REPAIR_READ_TOKEN", model)
        self.assertNotIn("GASLUX_REPAIR_READ_TOKEN", safety)
        self.assertIn("needs.safety.result == 'success'", publisher)


if __name__ == "__main__":
    unittest.main()
