"""Bounded multi-file discovery and independent exact-byte candidate replay."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_multifile_development as multi


class MultiFileTests(unittest.TestCase):
    def fixture(self, root):
        suite = "auto_tests/tests/" + multi.factory.TASKS["zorin"][1]
        test = root / suite
        test.parent.mkdir(parents=True)
        test.write_text("from gaslux_alpha import one\nfrom gaslux_beta import two\n"
                        "def test_contract():\n    assert one(1) == two(2)\n")
        for name in ("gaslux_alpha", "gaslux_beta"):
            path = root / multi.module_path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("def present(x):\n    return x\n")
        return suite

    def test_discovery_without_fixed_product_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suite = self.fixture(root)
            rows = multi.discover(root)
            self.assertEqual(len(rows), 1)
            task = rows[0]
            self.assertEqual(task["suite"], suite)
            self.assertEqual(task["role"], "zorin")
            self.assertEqual([e["symbol"] for e in task["entries"]], ["one", "two"])
            self.assertEqual(multi.select(root, task["key"]), task)
            (root / suite).write_text("from gaslux_alpha import one\nfrom gaslux_beta import two\n"
                                      "def test_contract():\n    assert one(1)\n")
            self.assertEqual(multi.discover(root), [])

    def test_reconstruct_exact_paths_and_no_test_edits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            task = multi.discover(root)[0]
            proposal = {e["path"]: f"def {e['symbol']}(x):\n    return x\n"
                        for e in task["entries"]}
            candidate = multi.reconstruct(root, task, proposal)
            self.assertEqual(set(candidate), set(proposal))
            for name, raw in candidate.items():
                self.assertTrue(raw.startswith((root / name).read_bytes().rstrip(b"\n") + b"\n\n\n"))
            for bad in ({**proposal, task["suite"]: "pass"},
                        {**proposal, next(iter(proposal)): "def one(x):\n    return open(x)\n"},
                        {**proposal, next(iter(proposal)): "def one(x):\n    return x.__class__\n"},
                        dict(list(proposal.items())[:1])):
                with self.assertRaises(ValueError):
                    multi.reconstruct(root, task, bad)

    def test_replay_rejects_substitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "fixture"
            fixture.mkdir()
            self.fixture(fixture)
            task = multi.discover(fixture)[0]
            proposal = {e["path"]: f"def {e['symbol']}(x):\n    return x\n"
                        for e in task["entries"]}
            sha = "a" * 40
            expected = multi.receipt(sha, task, multi.reconstruct(fixture, task, proposal))
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "bundle.json").write_text(json.dumps(proposal))
            (evidence / "report.json").write_text(json.dumps(expected))
            red = {"accepted": False, "exit_code": 2, "failed": 0, "errors": 1}
            green = {"accepted": True, "exit_code": 0, "failed": 0, "errors": 0}
            def archive(repo, base, tree):
                self.fixture(tree)
            with patch.object(multi.factory, "git", return_value=sha), \
                 patch.object(multi.shadow, "read_tree", side_effect=archive), \
                 patch.object(multi.shadow, "regression", side_effect=[red, green, red]), \
                 patch.object(multi, "style", return_value=True):
                result = multi.run(root, sha, task["key"], root, evidence, replay=True)
                self.assertTrue(result["replayed"])
                self.assertFalse(result["merge_authorized"])
                proposal[next(iter(proposal))] = "def one(x):\n    return 0\n"
                (evidence / "bundle.json").write_text(json.dumps(proposal))
                with self.assertRaisesRegex(ValueError, "substitution"):
                    multi.run(root, sha, task["key"], root, evidence, replay=True)

    def test_ambiguous_or_dynamic_exports_are_not_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suite = self.fixture(root)
            (root / suite).write_text("from gaslux_alpha import one, another, third\n"
                                     "from gaslux_beta import two\n"
                                     "def test_contract():\n    one(1); another(1); third(1); two(2)\n")
            self.assertEqual(multi.discover(root), [])
            self.fixture(root / "second")
            (root / "second" / multi.module_path("gaslux_alpha")).write_text(
                "def __getattr__(name):\n    return None\n")
            self.assertEqual(multi.discover(root / "second"), [])


if __name__ == "__main__":
    unittest.main()
