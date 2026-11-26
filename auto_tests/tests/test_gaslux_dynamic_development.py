"""Dynamic shadow scope never imports model-produced code in the controller."""
import sys
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_dynamic_development as dynamic


class DynamicDevelopmentTests(unittest.TestCase):
    def test_only_bounded_pure_function(self):
        valid = "def missing(value):\n    if value is None:\n        return False\n    return len(value) > 0\n"
        dynamic.validate_function("missing", valid)
        for source in (
            "import os\ndef missing(x):\n    return x\n",
            "def missing(x):\n    return x.__class__\n",
            "def missing(x):\n    return open(x)\n",
            "def missing(x):\n    return SECRET\n",
            "def missing(x):\n    x[0] = 1\n    return x\n",
            "def missing(x=open('f')):\n    return x\n",
            "@evil\ndef missing(x):\n    return x\n",
            "def missing(x):\n    while True:\n        pass\n",
            "def missing(x):\n    len = x\n    return len\n",
            "def missing(x):\n    return x\nprint('side effect')\n",
            "def another(x):\n    return x\n",
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                dynamic.validate_function("missing", source)

    def test_exact_append_never_replaces_existing_function(self):
        raw = b"def existing(x):\n    return x\n"
        generated = "def missing(x):\n    return x + 1\n"
        result = dynamic.candidate_bytes(raw, "missing", generated)
        self.assertEqual(result, raw.rstrip(b"\n") + b"\n\n\n" + generated.encode())
        with self.assertRaises(ValueError):
            dynamic.candidate_bytes(raw, "existing", "def existing(x):\n    return False\n")

    def test_real_test_witness_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, suite, _ = dynamic.factory.TASKS["zorin"]
            path = root / source
            path.parent.mkdir(parents=True)
            path.write_text("def present(x):\n    return x\n")
            test = root / "auto_tests/tests" / suite
            test.parent.mkdir(parents=True)
            test.write_text(f"from {path.stem} import missing\n\ndef test_required():\n    assert missing(1) == 2\n")
            row = dynamic.triage.discover_missing_implementations(root)[0]
            self.assertEqual(dynamic.select_task(root, row["key"]), row)
            with self.assertRaises(ValueError):
                dynamic.select_task(root, "0" * 64)
            path.write_text("def missing(x):\n    return x + 1\n")
            with self.assertRaises(ValueError):
                dynamic.select_task(root, row["key"])

    def test_no_green_baseline_no_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            role = "zorin"
            source, suite, _ = dynamic.factory.TASKS[role]
            raw = b"def existing(x):\n    return x\n"
            def archive(repo, base, tree):
                target = tree / source
                target.parent.mkdir(parents=True)
                target.write_bytes(raw)
                test = tree / "auto_tests/tests" / suite
                test.parent.mkdir(parents=True)
                test.write_text(f"from {target.stem} import missing\n\ndef test_required():\n    assert missing(1) == 2\n")
            key = dynamic.triage.hashlib.sha256(f"{source}:missing".encode()).hexdigest()
            sha = "a" * 40
            with patch.object(dynamic.factory, "git", return_value=sha), \
                 patch.object(dynamic.shadow, "read_tree", side_effect=archive), \
                 patch.object(dynamic.shadow, "regression", return_value={"accepted": True, "exit_code": 0, "failed": 0, "errors": 0}), \
                 patch.object(dynamic.factory, "call_model") as model:
                report = dynamic.evaluate(root, sha, key, root, evidence)
            self.assertEqual(report["status"], "NO_REPRODUCIBLE_RED")
            self.assertFalse(report["publish_authorized"])
            self.assertFalse(evidence.exists())
            model.assert_not_called()


    def test_replay_reconstructs_bytes_and_rejects_modified_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            role = "zorin"
            source, suite, _ = dynamic.factory.TASKS[role]
            raw = b"def existing(x):\n    return x\n"
            generated = "def missing(x):\n    return x + 1\n"
            sha = "a" * 40
            key = dynamic.triage.hashlib.sha256(f"{source}:missing".encode()).hexdigest()
            def archive(repo, base, tree):
                target = tree / source
                target.parent.mkdir(parents=True)
                target.write_bytes(raw)
                test = tree / "auto_tests/tests" / suite
                test.parent.mkdir(parents=True)
                test.write_text(f"from {target.stem} import missing\n\ndef test_required():\n    assert missing(1) == 2\n")
            tree = root / "fixture"
            tree.mkdir()
            archive(root, sha, tree)
            task = dynamic.select_task(tree, key)
            candidate = dynamic.candidate_bytes(raw, "missing", generated)
            report = {"schema": "gaslux-dynamic-shadow-v1", "base": sha, "role": role,
                      "key": key, "symbol": "missing", "task": task,
                      "status": "RED_GREEN_REVIEW_ARTIFACT", "accepted": True,
                      "addition_sha256": dynamic.factory.sha256(generated.encode()),
                      "candidate_sha256": dynamic.factory.sha256(candidate),
                      "publish_authorized": False, "merge_authorized": False, "release_eligible": False}
            (evidence / "addition.py").write_text(generated)
            (evidence / "report.json").write_text(json.dumps(report))
            red = {"accepted": False, "exit_code": 2, "failed": 0, "errors": 1}
            green = {"accepted": True, "exit_code": 0, "failed": 0, "errors": 0}
            with patch.object(dynamic.factory, "git", return_value=sha), \
                 patch.object(dynamic.shadow, "read_tree", side_effect=archive), \
                 patch.object(dynamic.shadow, "regression", side_effect=[red, green]), \
                 patch.object(dynamic.shadow, "style_check", return_value={"accepted": True}):
                _, observed, receipt = dynamic.verify_artifact(root, sha, key, evidence, dependencies=root)
                self.assertEqual(observed, candidate)
                self.assertTrue(receipt["replayed"])
                self.assertFalse(receipt["merge_authorized"])
                (evidence / "addition.py").write_text("def missing(x):\n    return 0\n")
                with self.assertRaisesRegex(ValueError, "DYNAMIC_ARTIFACT_MISMATCH"):
                    dynamic.verify_artifact(root, sha, key, evidence)

    def test_publisher_rejects_untrusted_event_and_unreplayed_candidate(self):
        env = {"GITHUB_REPOSITORY": dynamic.factory.REPO,
               "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "schedule",
               "GASLUX_AUTONOMY_PAUSED": "false"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay = root / "replay.json"
            replay.write_text(json.dumps({"replayed": False}))
            with patch.dict(os.environ, {**env, "GITHUB_EVENT_NAME": "pull_request"}, clear=True), \
                 patch.object(dynamic, "verify_artifact") as verify:
                with self.assertRaises(ValueError):
                    dynamic.publish_draft(root, "a" * 40, "b" * 64, root, replay)
                verify.assert_not_called()
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(dynamic, "verify_artifact", return_value=({}, b"", {"draft_only": True})), \
                 patch.object(dynamic.subprocess, "run") as write:
                with self.assertRaisesRegex(ValueError, "DYNAMIC_INDEPENDENT_REPLAY_REQUIRED"):
                    dynamic.publish_draft(root, "a" * 40, "b" * 64, root, replay)
                write.assert_not_called()


    def test_rejects_nested_function_and_module_shadowing(self):
        for code in (
            "def missing(x):\n    def inner():\n        return 1\n    return 2\n",
            "def missing(x):\n    def inner(y=abs(x)):\n        return y\n    return x\n",
        ):
            with self.assertRaisesRegex(ValueError, "DYNAMIC_NESTED_FUNCTION"):
                dynamic.validate_function("missing", code)
        generated = "def missing(x):\n    return len(x)\n"
        for before in (b"len = dangerous\n", b"from other import dangerous as len\n",
                       b"from other import *\n", b"def len(x):\n    return x\n"):
            with self.assertRaisesRegex(ValueError, "DYNAMIC_SHADOWED_BUILTIN"):
                dynamic.candidate_bytes(before, "missing", generated)


if __name__ == "__main__":
    unittest.main()
