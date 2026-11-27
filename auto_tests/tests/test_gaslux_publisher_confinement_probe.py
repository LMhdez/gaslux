"""Offline contracts for disposable confinement proof, no network."""
import os
import io
import urllib.error
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_publisher_confinement_probe as P


class ProbeTests(unittest.TestCase):
    def test_names_are_run_scoped(self):
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}, clear=True):
            self.assertEqual(P.names(), ("lab/gaslux-confinement-123-2-base",
                                         "lab/gaslux-confinement-123-2-candidate"))
            os.environ["GITHUB_RUN_ID"] = "../dev"
            with self.assertRaises(ValueError):
                P.names()

    def test_default_context_denies_before_network(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(P.A, "api") as api:
            with self.assertRaises(ValueError):
                P.context()
            api.assert_not_called()

    def test_ref_scope_denies_protected_branches(self):
        with patch.object(P, "names", return_value=("lab/base", "lab/head")), \
             patch.object(P.subprocess, "run") as run:
            for branch, sha in (("dev", P.lab.HEAD), ("main", P.lab.HEAD),
                                ("lab/base", P.lab.HEAD)):
                with self.assertRaises(ValueError):
                    P.push_new(Path("."), branch, sha)
            run.assert_not_called()

    def test_actual_update_success_fails(self):
        with patch.dict(os.environ, {"GH_TOKEN": "test"}), \
             patch.object(P, "names", return_value=("lab/base", "lab/head")), \
             patch.object(P.lab, "ref", return_value=P.lab.BASE), \
             patch.object(P.urllib.request, "urlopen") as opener:
            with self.assertRaisesRegex(RuntimeError, "accepted"):
                P.attempt_update("lab/base")
            self.assertTrue(opener.call_args.args[0].full_url.endswith("/git/refs/heads/lab/base"))

    def test_only_rule_specific_denial_is_accepted(self):
        for message, accepted in (
            ("Repository rule violations found. Cannot update this protected ref.", True),
            ("Resource not accessible by integration", False),
            ("Validation Failed", False),
        ):
            with self.subTest(message=message), patch.dict(os.environ, {"GH_TOKEN": "test"}), \
                 patch.object(P, "names", return_value=("lab/base", "lab/head")), \
                 patch.object(P.lab, "ref", return_value=P.lab.BASE), \
                 patch.object(P.urllib.request, "urlopen", side_effect=urllib.error.HTTPError(
                     "https://api.github.com", 422, "denied", None,
                     io.BytesIO(P.json.dumps({"message": message}).encode()))):
                if accepted:
                    self.assertEqual(P.attempt_update("lab/base"), 422)
                else:
                    with self.assertRaises(ValueError):
                        P.attempt_update("lab/base")

    def test_exact_denial_and_close(self):
        responses = [{}, {"state": "closed", "merged": False, "number": 999, "body": P.BODY}]
        with patch.object(P, "context", return_value=("a", "b")), \
             patch.object(P, "exact_pr"), patch.object(P, "names", return_value=("lab/base", "lab/head")), \
             patch.object(P, "attempt_update", return_value=422), \
             patch.object(P.lab, "ref", side_effect=[P.lab.BASE, P.lab.HEAD]), \
             patch.object(P.A, "api", side_effect=responses) as api:
            out = P.deny_and_close(999)
            self.assertTrue(out["closed_without_merge"])
            self.assertFalse(out["merge_authorized"])
            self.assertEqual(api.call_count, 2)

    def test_workflow_write_probe_is_explicit_and_separate_from_review_credentials(self):
        workflow = (Path(P.__file__).resolve().parents[2] /
                    ".github/workflows/gaslux-agent-integrator.yml").read_text()
        publisher = workflow.split("  paused_publisher_confinement:", 1)[1].split(
            "  paused_integrator_confinement:", 1)[0]
        integrator = workflow.split("  paused_integrator_confinement:", 1)[1].split(
            "  paused_safety_credential_probe:", 1)[0]
        for job in (publisher, integrator):
            for required in ("github.ref == 'refs/heads/main'",
                             "github.event_name == 'workflow_dispatch'",
                             "inputs.paused_confinement_probe == true",
                             "vars.GASLUX_AUTONOMY_PAUSED == 'true'",
                             "vars.GASLUX_PRODUCTION_MERGE_ENABLED == 'false'",
                             "vars.GASLUX_APP_STATUS_GATES_ENABLED == 'false'",
                             "persist-credentials: false"):
                self.assertIn(required, job)
            self.assertNotIn("gh pr merge", job)
        self.assertIn("environment: gaslux-main-publisher", publisher)
        self.assertIn("needs: paused_publisher_confinement", integrator)
        self.assertNotIn("private-key:", integrator)
