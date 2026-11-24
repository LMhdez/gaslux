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
            self.assertEqual(config["skills"], {"paths": [str(work / ".opencode/skills")], "urls": []})
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

    def test_failure_categories_and_native_witness_preserved(self):
        rows = event_rows()
        rows[-1]["part"]["text"] = "not json; SECRET_SENTINEL"
        row = trial.assess(lambda: trial.parse_events(encode(rows)))
        self.assertEqual(row["failure"], "CANDIDATE_JSON_INVALID")
        self.assertEqual(row["native_skills"], [trial.SKILL])
        self.assertEqual(row["event_counts"], {"tool_use": 1, "text": 1})
        self.assertNotIn("SECRET_SENTINEL", json.dumps(row))
        self.assertIs(row["accepted"], False)

    def test_error_event_allowlist(self):
        for name, expected in (("APIError", "APIError"), ("SECRET_SENTINEL", "OTHER")):
            row = trial.assess(lambda: trial.parse_events(encode([
                {"type": "error", "error": {"name": name, "data": "SECRET_SENTINEL"}}
            ])))
            self.assertEqual(row["failure"], "OPENCODE_ERROR_EVENT")
            self.assertEqual(row["failure_detail"], expected)
            self.assertNotIn("SECRET_SENTINEL", json.dumps(row))

    def test_cli_failure_categories(self):
        error = trial.cli_failure(1, b"", b"invalid configuration SECRET_SENTINEL")
        self.assertEqual(error.category, "CLI_NONZERO")
        self.assertEqual(error.detail, "CONFIG_INVALID")
        self.assertEqual(trial.cli_failure(-25, b"", b"").detail, "FILE_SIZE_LIMIT")
        self.assertNotIn("SECRET_SENTINEL", str(error))

    def test_native_tool_denial_and_missing_tool_differ(self):
        rows = event_rows()
        rows[0]["part"]["state"].update({"status": "error", "error": "permission denied"})
        row = trial.assess(lambda: trial.parse_events(encode(rows)))
        self.assertEqual(row["failure"], "SKILL_TOOL_FAILED")
        self.assertEqual(row["failure_detail"], "PERMISSION_DENIED")
        row = trial.assess(lambda: trial.parse_events(encode(rows[1:])))
        self.assertEqual(row["failure"], "NO_NATIVE_SKILL_EVENT")


if __name__ == "__main__":
    unittest.main()
