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


if __name__ == "__main__":
    unittest.main()
