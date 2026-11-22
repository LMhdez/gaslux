#!/usr/bin/env python3
"""Adversarial acceptance tests for the read-only full-project goal supervisor."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "auto_tests/tools/goal_supervisor.py"
SPEC = importlib.util.spec_from_file_location("goal_supervisor", MODULE)
assert SPEC and SPEC.loader
supervisor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supervisor)


class GoalSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.goal = json.loads((ROOT / "docs/autonomy/goal.json").read_text())
        self.evidence = {"schema_version": 1, "records": []}

    def test_full_release_matrix_and_no_silent_completions(self) -> None:
        result = supervisor.evaluate(self.goal, self.evidence)
        self.assertEqual(result["total_required_gates"], 136)
        self.assertEqual(result["remaining_gates"], 136)
        self.assertEqual(result["recorded_reviewed_gates"], 0)
        self.assertFalse(result["complete"])
        self.assertFalse(result["release_eligible"])
        self.assertTrue(result["blocked_for_automerge"])

    def test_first_mission_is_noncritical_baseline_proof(self) -> None:
        result = supervisor.evaluate(self.goal, self.evidence)
        self.assertEqual(
            (result["next_auto_research"]["backend"], result["next_auto_research"]["gate"]),
            ("mint", "source-authenticity"),
        )

    def test_bazzite_legacy_bios_is_not_acceptance_target(self) -> None:
        tasks, _ = supervisor.validate(self.goal, self.evidence)
        self.assertNotIn(
            ("bazzite", "windows10-bios-mbr"),
            {(x["backend"], x["platform"]) for x in tasks},
        )

    def test_bazzite_legacy_bios_cannot_be_enabled(self) -> None:
        self.goal["backends"][-1]["platforms"].append("windows10-bios-mbr")
        with self.assertRaisesRegex(ValueError, "Bazzite BIOS"):
            supervisor.evaluate(self.goal, self.evidence)

    def test_unsupported_evidence_cannot_complete_a_gate(self) -> None:
        self.evidence["records"] = [{
            "backend": "bazzite", "platform": "windows10-bios-mbr",
            "gate": "install", "status": "independently_reviewed",
            "head_sha": "f" * 40,
            "ci_url": "https://github.com/LMhdez/gaslux/actions/runs/123",
            "review_url": "https://github.com/LMhdez/gaslux/pull/123",
        }]
        with self.assertRaisesRegex(ValueError, "unsupported"):
            supervisor.evaluate(self.goal, self.evidence)

    def test_fake_success_without_review_is_rejected(self) -> None:
        self.evidence["records"] = [{
            "backend": "mint", "platform": "windows10-bios-mbr",
            "gate": "install", "status": "success", "head_sha": "f" * 40,
            "ci_url": "https://github.com/LMhdez/gaslux/actions/runs/123",
            "review_url": "https://github.com/LMhdez/gaslux/pull/123",
        }]
        with self.assertRaisesRegex(ValueError, "Unreviewed"):
            supervisor.evaluate(self.goal, self.evidence)

    def test_duplicate_reviewed_gate_is_rejected(self) -> None:
        record = {
            "backend": "mint", "platform": "windows10-bios-mbr",
            "gate": "install", "status": "independently_reviewed",
            "head_sha": "f" * 40,
            "ci_url": "https://github.com/LMhdez/gaslux/actions/runs/123",
            "review_url": "https://github.com/LMhdez/gaslux/pull/123",
        }
        self.evidence["records"] = [record, dict(record)]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            supervisor.evaluate(self.goal, self.evidence)

    def test_invalid_sha_is_rejected(self) -> None:
        self.evidence["records"] = [{
            "backend": "mint", "platform": "windows10-bios-mbr",
            "gate": "install", "status": "independently_reviewed",
            "head_sha": "fake", "ci_url": "https://github.com/LMhdez/gaslux/actions/runs/123",
            "review_url": "https://github.com/LMhdez/gaslux/pull/123",
        }]
        with self.assertRaisesRegex(ValueError, "SHA"):
            supervisor.evaluate(self.goal, self.evidence)

    def test_reviewed_record_is_counted_as_unverified_claim_not_release(self) -> None:
        self.evidence["records"] = [{
            "backend": "mint", "platform": "windows10-bios-mbr",
            "gate": "source-authenticity", "status": "independently_reviewed",
            "head_sha": "f" * 40,
            "ci_url": "https://github.com/LMhdez/gaslux/actions/runs/123",
            "review_url": "https://github.com/LMhdez/gaslux/pull/123",
        }]
        result = supervisor.evaluate(self.goal, self.evidence)
        self.assertEqual(result["recorded_reviewed_gates"], 1)
        self.assertEqual(result["remaining_gates"], 135)
        self.assertFalse(result["release_eligible"])
        self.assertIn("NOT fetched", result["evidence_assurance"])

    def test_gate_classification_cannot_be_weakened_silently(self) -> None:
        self.goal["protected_gates"].remove("fault-injection-rollback")
        with self.assertRaisesRegex(ValueError, "safety class"):
            supervisor.evaluate(self.goal, self.evidence)


if __name__ == "__main__":
    unittest.main()
