"""Offline tests for checkpoint counting, scope and fail-closed reporting."""
import importlib.util
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gaslux_agent_progress.py"
SPEC = importlib.util.spec_from_file_location("gaslux_agent_progress", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
SHA = "a" * 40


def run(conclusion="success", status="completed", event="schedule"):
    return {"id": 17, "head_sha": SHA, "created_at": "2026-11-22T20:00:00Z",
            "conclusion": conclusion, "status": status, "event": event}


def job(name, result="success", status="completed"):
    return {"name": name, "conclusion": result, "status": status}


class ProgressTests(unittest.TestCase):
    def test_skipped_running_unknown_are_not_passed(self):
        self.assertEqual(mod.job_state([], "model"), "unobserved")
        self.assertEqual(mod.job_state([job("model", "skipped")], "model"), "skipped")
        self.assertEqual(mod.job_state([job("model", None, "in_progress")], "model"), "running")

    def test_backend_matrix_failure_blocks(self):
        jobs = [job("backend_research (mint)"), job("backend_research (zorin)", "failure")]
        self.assertEqual(mod.job_state(jobs, "backend_research"), "blocked")

    def test_idle_not_finished_install(self):
        stages = ["supervisor", "backend_developer", "safety_review",
                  "windows_wpf_acceptance", "integrator_publisher"]
        jobs = [job(stages[0])] + [job(s, "skipped") for s in stages[1:]]
        actual = mod.pipeline("gaslux-agent-clock.yml", [run()], jobs)
        self.assertEqual((actual["state"], actual["passed"], actual["total"]),
                         ("idle", 1, 5))

    def test_merger_stages_only_real_success(self):
        jobs = [job("select"), job("windows_acceptance"), job("trusted_integrator")]
        actual = mod.pipeline("gaslux-agent-integrator.yml", [run()], jobs)
        self.assertEqual((actual["state"], actual["passed"]), ("passed", 3))

    def test_failure_stays_blocked(self):
        actual = mod.pipeline("gaslux-agent-feature-factory.yml",
                              [run(conclusion="failure")],
                              [job("select"), job("model", "failure")])
        self.assertEqual((actual["state"], actual["passed"]), ("blocked", 1))

    def test_malformed_run_identity_refused(self):
        with self.assertRaises(ValueError):
            mod.pipeline("gaslux-agent-clock.yml", [{**run(), "head_sha": "bad"}], [])

    def test_release_claims_are_not_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "docs/autonomy"
            src.mkdir(parents=True)
            goal = {"schema_version": 1, "backends": [{"id": "mint", "platforms": ["w10"]}],
                    "gates": ["install", "recovery"]}
            evidence = {"schema_version": 1, "records": [
                {"backend": "mint", "platform": "w10", "gate": "install"}]}
            (src / "goal.json").write_text(json.dumps(goal))
            (src / "evidence.json").write_text(json.dumps(evidence))
            stats = mod.release_claims(Path(tmp))
            self.assertEqual((stats["required"], stats["registered_claims"],
                              stats["externally_attested"]), (2, 1, 0))
            self.assertFalse(stats["release_eligible"])
            evidence["records"] *= 2
            (src / "evidence.json").write_text(json.dumps(evidence))
            with self.assertRaises(ValueError):
                mod.release_claims(Path(tmp))

    def test_bar_never_overstates(self):
        self.assertEqual(len(mod.progress_bar(1, 3)), 12)
        with self.assertRaises(ValueError):
            mod.progress_bar(2, 1)

    def test_markdown_labels_not_product_progress(self):
        p = mod.pipeline("gaslux-agent-clock.yml", [run()], [job("supervisor")])
        txt = mod.render({"paused": True,
                          "release": {"required": 136, "registered_claims": 0,
                                      "externally_attested": 0},
                          "pipelines": [p]})
        self.assertIn("0/136", txt)
        self.assertIn("PAUSED", txt)
        self.assertIn("não a percentagem de funcionalidades", txt)

    def test_missing_and_partial_api_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "docs/autonomy"
            src.mkdir(parents=True)
            (src / "goal.json").write_text(json.dumps({
                "schema_version": 1, "backends": [{"id": "mint", "platforms": ["w10"]}],
                "gates": ["install"]}))
            (src / "evidence.json").write_text('{"schema_version":1,"records":[]}')
            with patch.object(mod, "fetch", side_effect=[
                {"workflow_runs": [run()]}, {"jobs": [], "total_count": 101}]):
                with self.assertRaises(ValueError):
                    mod.collect("not-secret", Path(tmp), False)
            with patch.object(mod, "fetch", return_value={"workflow_runs": []}) as f:
                result = mod.collect("not-secret", Path(tmp), True)
            self.assertEqual(f.call_count, 4)
            self.assertFalse(result["write_or_merge_authority"])


    def test_emergency_pause_blocks_all_three_write_entrypoints_before_network(self):
        roots = Path(__file__).resolve().parents[1] / "tools"
        from unittest.mock import patch
        cases = (
            ("gaslux_agent_integrate.py", "merge", (1, "a" * 40)),
            ("gaslux_agent_trusted_publish.py", "publish", ()),
            ("gaslux_agent_feature_factory.py", "publish",
             (Path("."), Path("."), "mint", "a" * 40)),
        )
        for filename, method, args in cases:
            with self.subTest(entrypoint=filename):
                spec = importlib.util.spec_from_file_location(filename[:-3], roots / filename)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                with patch.dict("os.environ", {"GASLUX_AUTONOMY_PAUSED": "true"}):
                    with self.assertRaisesRegex(RuntimeError, "GASLUX_AUTONOMY_PAUSED"):
                        getattr(module, method)(*args)

    def test_workflow_authority_paused_and_reporter_readonly(self):
        workflows = Path(__file__).resolve().parents[2] / ".github/workflows"
        for name in ("gaslux-agent-clock.yml", "gaslux-agent-feature-factory.yml",
                     "gaslux-agent-integrator.yml", "gaslux-agent-lifecycle-research.yml"):
            with self.subTest(workflow=name):
                text = (workflows / name).read_text(encoding="utf-8")
                self.assertIn("GASLUX_AUTONOMY_PAUSED", text)
        clock = (workflows / "gaslux-agent-clock.yml").read_text(encoding="utf-8")
        self.assertIn("  autonomy_progress:", clock)
        self.assertIn("      actions: read", clock)
        self.assertIn("          persist-credentials: false", clock)


if __name__ == "__main__":
    unittest.main()
