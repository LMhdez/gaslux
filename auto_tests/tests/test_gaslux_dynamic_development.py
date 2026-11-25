"""Dynamic shadow scope never imports model-produced code in the controller."""
import sys
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


if __name__ == "__main__":
    unittest.main()
