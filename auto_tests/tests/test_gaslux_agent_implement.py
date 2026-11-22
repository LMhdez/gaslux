"""Offline adversarial acceptance for role-based local product implementation."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gaslux_agent_implement", ROOT / "auto_tests/tools/gaslux_agent_implement.py")
assert SPEC and SPEC.loader
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class AgentImplementationTests(unittest.TestCase):
    def setUp(self):
        self.original_path = ROOT / "Installation/WindowsKeyboardLayout.cs"
        self.live_source = self.original_path.read_text()
        # Candidate tests always start from a reusable missing-feature fixture,
        # including after earlier autonomous product PRs have been merged.
        import re
        self.source = re.sub(
            r'^[ \t]*\{ "00000816", Mapping\("pt"\) \},\n',
            '', self.live_source, flags=re.MULTILINE)
        self.source = re.sub(
            r'^[ \t]*\{ "00000416", Mapping\("br"\) \},\n',
            '', self.source, flags=re.MULTILINE)
        self.missions = json.loads((ROOT / "docs/autonomy/agent_missions.json").read_text())
        self.pt = next(x for x in self.missions["tasks"] if x["role"] == "mint")
        self.br = next(x for x in self.missions["tasks"] if x["role"] == "zorin")

    def test_real_missing_product_feature(self):
        # The live repository evolves; a previously merged mapping must not
        # cause the autonomous Supervisor's own tests to fail forever.
        p = agent.plan()
        if '"00000816"' not in self.live_source:
            self.assertEqual(p["task"]["id"], "MINT-PT-KEYBOARD-01")
        elif '"00000416"' not in self.live_source:
            self.assertEqual(p["task"]["id"], "ZORIN-BR-KEYBOARD-01")
        else:
            self.assertEqual(p["status"], "idle")

    def test_mint_candidate_accepted_only_one_line(self):
        updated = agent.propose(self.source, self.pt, '{ "00000816", Mapping("pt") },')
        agent.acceptance(self.source, updated, self.pt)
        self.assertEqual(len(updated.splitlines()), len(self.source.splitlines()) + 1)

    def test_zorin_candidate_is_distinct_real_feature(self):
        updated = agent.propose(self.source, self.br, '{ "00000416", Mapping("br") },')
        agent.acceptance(self.source, updated, self.br)

    def test_model_cannot_replace_path_or_invoke_code(self):
        for entry in (
            '{ "00000816", System.IO.File.Delete("C:\\\\foo") },',
            '{ "00000816", Mapping("br") },',
            '{ "00000816", Mapping("pt") };',
            'using System;',
            '{ "00000416", Mapping("br") },',
        ):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                agent.propose(self.source, self.pt, entry)

    def test_existing_feature_is_not_selected_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "src.cs"
            target.write_text(agent.propose(self.source, self.pt, '{ "00000816", Mapping("pt") },'))
            with patch.object(agent, "SOURCE", target):
                picked = agent.plan()
            self.assertEqual(picked["task"]["id"], "ZORIN-BR-KEYBOARD-01")

    def test_zero_tasks_after_completion(self):
        text = agent.propose(self.source, self.pt, '{ "00000816", Mapping("pt") },')
        text = agent.propose(text, self.br, '{ "00000416", Mapping("br") },')
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "src.cs"
            target.write_text(text)
            with patch.object(agent, "SOURCE", target):
                self.assertEqual(agent.plan()["status"], "idle")

    def test_unsupported_metadata_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "missions.json"
            bad = dict(self.missions)
            bad["tasks"] = [dict(x) for x in self.missions["tasks"]]
            bad["tasks"][0]["source"] = "/dev/sda"
            file.write_text(json.dumps(bad))
            with patch.object(agent, "MISSION_PATH", file):
                with self.assertRaises(ValueError):
                    agent.tasks()

    def test_new_mapping_must_not_change_existing_source(self):
        updated = agent.propose(self.source, self.pt, '{ "00000816", Mapping("pt") },')
        with self.assertRaises(ValueError):
            agent.acceptance(self.source, updated + "\n", self.pt)


if __name__ == "__main__":
    unittest.main()
