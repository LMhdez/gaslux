"""Offline, synthetic tests; no model/network or publishing."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

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

    def test_safety1_419_01_event_types_and_tool_disguises_fail_closed(self):
        malformed = [
            {"type": "unknown", "part": {"tool": "bash"}},
            {"type": "unknown", "part": {}},
            {"type": "tool_result", "part": {"tool": "bash"}},
            {"type": "reasoning", "part": {"text": "", "state": {"status": "completed"}}},
            {"type": "text", "part": {"text": "", "callID": "forbidden"}},
            {"type": "step_start", "part": None},
            {"type": "reasoning", "part": {"type": "reasoning", "text": []}},
            {"part": {"tool": "bash"}},
            {"type": None, "part": {}},
            {"type": [], "part": {}},
            {"type": "reasoning", "part": {"tool": "bash"}},
            {"type": "step_start", "part": {"type": "tool", "tool": "bash"}},
            {"type": "step_finish", "part": {"type": "tool"}},
            {"type": "text", "part": {"type": "tool", "text": "", "tool": "bash"}},
            {"type": "text", "tool": "bash", "part": {"text": ""}},
            {"type": "tool_use", "part": {"type": "text", "tool": "skill",
                "state": event_rows()[0]["part"]["state"]}},
        ]
        for event in malformed:
            with self.subTest(event=event):
                with self.assertRaises(trial.TrialFailure):
                    trial.parse_events(encode(event_rows() + [event]))
        # Duplicate keys must not mask a forbidden event or a tool identity.
        good = encode(event_rows())
        for raw in (
            b'{"type":"unknown","type":"reasoning","part":{}}',
            b'{"type":"reasoning","part":{"tool":"bash","tool":"skill"}}',
            b'{"type":"step_finish","part":{"tokens":{"input":NaN}}}',
            b'{"type":"step_finish","part":{"type":"step-finish","type":"tool"}}',
        ):
            with self.assertRaises(trial.TrialFailure):
                trial.parse_events(good + b"\n" + raw)
        # Recognized non-tool events and free text are still legitimate.
        rows = event_rows()
        rows.insert(1, {"type": "reasoning", "part": {"type": "reasoning",
            "text": "the word bash is not a tool invocation"}})
        rows.insert(1, {"type": "step_start", "part": {"type": "step-start"}})
        rows.append({"type": "step_finish", "part": {"type": "step-finish"}})
        self.assertEqual(trial.parse_events(encode(rows)), ("synthetic", [trial.SKILL]))

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
        self.assertEqual(row["failure"], "CANDIDATE_FORMAT_INVALID")
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

    def test_internal_files_can_exceed_stream_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            with patch.object(trial, "MIN_FREE", 0):
                code, out, err = trial.bounded_process(
                    [sys.executable, "-c",
                     "open('cache.bin','wb').write(b'x' * (3 * 1024 * 1024)); print('ok')"],
                    work, {}, timeout=10)
            self.assertEqual((code, out, err), (0, b"ok\n", b""))
            self.assertGreater((work / "cache.bin").stat().st_size, trial.MAX_EVENTS)

    def test_output_stream_limits_independent_of_internal_limit(self):
        for fd, expected in ((1, "EVENT_STREAM_OVERSIZE"), (2, "STDERR_STREAM_OVERSIZE")):
            with tempfile.TemporaryDirectory() as tmp, patch.object(trial, "MIN_FREE", 0):
                with self.assertRaises(trial.TrialFailure) as caught:
                    trial.bounded_process(
                        [sys.executable, "-c", f"import os; os.write({fd}, b'x' * 3000000)"],
                        Path(tmp), {}, timeout=10)
                self.assertEqual(caught.exception.category, expected)

    def test_scratch_budget_and_disk_reserve(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "cache").write_bytes(b"x" * 4096)
            with patch.object(trial, "MAX_SCRATCH", 1):
                with self.assertRaisesRegex(trial.TrialFailure, "SCRATCH_SIZE_LIMIT"):
                    trial.check_scratch(work)
            with patch.object(trial, "MIN_FREE", 10**20):
                with self.assertRaisesRegex(trial.TrialFailure, "DISK_RESERVE_LIMIT"):
                    trial.check_scratch(work)

    def test_timeout_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(trial, "MIN_FREE", 0):
            with self.assertRaisesRegex(trial.TrialFailure, "CLI_TIMEOUT"):
                trial.bounded_process([sys.executable, "-c", "import time; time.sleep(10)"],
                                      Path(tmp), {}, timeout=0.2)


    def test_native_agent_source_contract(self):
        source = ("def assess_mint_lifecycle(evidence: dict) -> dict:\n"
                  "    gates = " + repr(trial.factory.GATES) + "\n"
                  "    missing = sorted([name for name in gates if evidence.get(name) is not True])\n"
                  "    return {'backend': 'mint', 'missingGates': missing, "
                  "'installationAuthorized': False, 'releaseEligible': False}\n")
        for answer in (source, "```python\n" + source + "```",
                       "```json\n" + json.dumps({"addition": source}) + "\n```",
                       json.dumps({"addition": source})):
            rows = event_rows()
            rows[-1]["part"]["text"] = answer
            row = trial.assess(lambda: trial.parse_events(encode(rows)))
            self.assertIs(row["accepted"], True)
            self.assertEqual(row["native_skills"], [trial.SKILL])

    def test_source_decoding_never_extracts_from_prose_or_multiple_blocks(self):
        source = trial.SIGNATURE + "\n    return {}"
        for answer in ("Here is the function:\n```python\n" + source + "\n```",
                       "```python\n" + source + "\n```\nmore",
                       "```python\n" + source + "\n```\n```python\n" + source + "\n```",
                       '{"addition":"a","addition":"b"}',
                       '{"addition":"a","permission":true}',
                       "```json\n" + source + "\n```",
                       "x" * (trial.MAX_ADDITION_BYTES + 1)):
            with self.assertRaises(trial.TrialFailure):
                trial.decode_candidate(answer)

    def test_raw_python_is_still_checked_by_unchanged_ast(self):
        rows = event_rows()
        rows[-1]["part"]["text"] = trial.SIGNATURE + "\n    import os\n    return {}"
        row = trial.assess(lambda: trial.parse_events(encode(rows)))
        self.assertIs(row["accepted"], False)
        self.assertEqual(row["failure_stage"], "ast_functional_guard")
        self.assertEqual(row["native_skills"], [trial.SKILL])

    def test_compact_profile_is_explicit_and_keeps_tool_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = trial.prepare(Path(tmp), context=trial.COMPACT_CONTEXT)
            model = config["provider"]["ollama"]["models"][trial.factory.MODEL]
            self.assertEqual(model["limit"]["context"], 16384)
            self.assertEqual(model["options"]["reasoningEffort"], "none")
            self.assertEqual(config["permission"]["*"], "deny")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                trial.prepare(Path(tmp), context=1)

    def test_metrics_and_native_skill_are_bounded(self):
        rows = event_rows()
        rows.insert(0, {"type": "step_finish", "part": {"tokens": {
            "input": 123, "output": 45, "reasoning": 4, "cache": {"read": 10, "write": 0}}}})
        metrics = {}
        trial.parse_events(encode(rows), metrics)
        self.assertEqual(metrics["event_counts"]["tool_use"], 1)
        self.assertEqual(metrics["reported_tokens"]["input"], 123)
        self.assertEqual(metrics["reported_tokens"]["cache_read"], 10)
        self.assertEqual(metrics["token_steps"], 1)

    def test_repair_retries_only_known_model_rejections(self):
        calls = []
        def attempt(reason):
            calls.append(reason)
            return {"accepted": bool(reason), "native_skills": [trial.SKILL],
                    "failure": "CANDIDATE_FORMAT_INVALID", "failure_stage": "opencode_events"}
        final, rows = trial.bounded_repair(attempt)
        self.assertEqual(calls, [None, "CANDIDATE_FORMAT_INVALID"])
        self.assertEqual(len(rows), 2)
        self.assertTrue(final["accepted"])
        for category, skills in (("CLI_TIMEOUT", [trial.SKILL]), ("CANDIDATE_FORMAT_INVALID", [])):
            final, rows = trial.bounded_repair(lambda _: {"accepted": False, "native_skills": skills,
                "failure": category, "failure_stage": "opencode_events"})
            self.assertEqual(len(rows), 1)

    def test_scratch_materialization_does_not_write_rejected_ast(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            row = trial.assess(lambda: (trial.SIGNATURE + "\n    import os\n    return {}", [trial.SKILL]),
                               workspace=work)
            self.assertFalse(row["accepted"])
            self.assertFalse((work / "candidate.py").exists())

    def test_agent_prompt_does_not_require_double_json(self):
        self.assertIn("Return only the Python function source", trial.AGENT_PROMPT)
        self.assertNotIn("Return exactly one JSON object", trial.AGENT_PROMPT)
        self.assertIn("Return exactly one JSON object", trial.PROMPT)


if __name__ == "__main__":
    unittest.main()
