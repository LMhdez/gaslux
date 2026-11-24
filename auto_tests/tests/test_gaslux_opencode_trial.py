"""Offline, synthetic tests; no model/network or publishing."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_opencode_trial as trial


def event_rows(tool="skill", name=trial.SKILL):
    return [
        {"type": "tool_use", "part": {"tool": tool, "state": {"status": "completed",
            "input": {"name": name}, "output": '<skill_content name="' + name + '">\nexample'}}},
        {"type": "text", "part": {"text": json.dumps({"addition": "synthetic"})}},
    ]


def encode(rows):
    return ("\n".join(json.dumps(row) for row in rows)).encode()


class OpenCodeTrialTests(unittest.TestCase):
    def test_native_skill_layout_and_deny_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            config = trial.prepare(work)
            self.assertEqual(config["enabled_providers"], ["ollama"])
            self.assertEqual(config["permission"]["*"], "deny")
            self.assertEqual(config["permission"]["skill"]["*"], "deny")
            self.assertEqual(config["agent"]["gaslux-lab"]["permission"], config["permission"])
            self.assertEqual(config["mcp"], {})
            self.assertEqual(config["plugin"], [])
            skills = list((work / ".opencode/skills").glob("*/SKILL.md"))
            self.assertEqual(len(skills), 8)
            self.assertTrue(all(p.read_text().startswith("---\nname: " + p.parent.name + "\n")
                                for p in skills))

    def test_native_skill_event_required(self):
        self.assertEqual(trial.parse_events(encode(event_rows())), ("synthetic", [trial.SKILL]))
        with self.assertRaises(ValueError):
            trial.parse_events(encode(event_rows()[1:]))

    def test_unexpected_tool_and_failed_skill_rejected(self):
        for rows in (event_rows("bash"), event_rows(name="untrusted")):
            with self.assertRaises(ValueError):
                trial.parse_events(encode(rows))
        rows = event_rows()
        rows[0]["part"]["state"]["status"] = "error"
        with self.assertRaises(ValueError):
            trial.parse_events(encode(rows))

    def test_forged_text_and_oversize_denied(self):
        rows = event_rows()
        rows[0]["part"]["state"]["output"] = "claimed skill"
        with self.assertRaises(ValueError):
            trial.parse_events(encode(rows))
        with self.assertRaises(ValueError):
            trial.parse_events(b"x" * (trial.MAX_EVENTS + 1))

    def test_existing_ast_guard_rejects_writer(self):
        row = trial.assess(lambda: ("def assess_mint_lifecycle(evidence: dict) -> dict:\n"
                                   "    import os\n    return {}\n", [trial.SKILL]))
        self.assertIs(row["accepted"], False)

    def test_actual_scope_guard_accepts_valid_synthetic_helper(self):
        addition = ("def assess_mint_lifecycle(evidence: dict) -> dict:\n"
                    "    gates = " + repr(trial.factory.GATES) + "\n"
                    "    missing = sorted([name for name in gates if evidence.get(name) is not True])\n"
                    "    return {'backend': 'mint', 'missingGates': missing, "
                    "'installationAuthorized': False, 'releaseEligible': False}\n")
        self.assertIs(trial.assess(lambda: (addition, [trial.SKILL]))["accepted"], True)


if __name__ == "__main__":
    unittest.main()
