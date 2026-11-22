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


if __name__ == "__main__":
    unittest.main()
