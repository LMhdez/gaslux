"""Offline contracts for disposable confinement proof, no network."""
import os
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

    def test_update_success_fails_without_close(self):
        with patch.object(P, "context", return_value=("a", "b")), \
             patch.object(P, "exact_pr"), patch.object(P, "names", return_value=("lab/base", "lab/head")), \
             patch.object(P.A, "api", return_value={}) as api:
            with self.assertRaisesRegex(RuntimeError, "accepted"):
                P.deny_and_close(999)
            api.assert_called_once_with("PATCH", "/git/refs/heads/lab/base",
                                        {"sha": P.lab.HEAD, "force": False})

    def test_unexpected_denial_cannot_close(self):
        with patch.object(P, "context", return_value=("a", "b")), \
             patch.object(P, "exact_pr"), patch.object(P, "names", return_value=("lab/base", "lab/head")), \
             patch.object(P.A, "api", side_effect=RuntimeError("GitHub PATCH failed: HTTP 404")) as api:
            with self.assertRaises(ValueError):
                P.deny_and_close(999)
            api.assert_called_once()

    def test_exact_denial_and_close(self):
        responses = [RuntimeError("GitHub PATCH failed: HTTP 422"), {},
                     {"state": "closed", "merged": False, "number": 999, "body": P.BODY}]
        with patch.object(P, "context", return_value=("a", "b")), \
             patch.object(P, "exact_pr"), patch.object(P, "names", return_value=("lab/base", "lab/head")), \
             patch.object(P.lab, "ref", side_effect=[P.lab.BASE, P.lab.HEAD]), \
             patch.object(P.A, "api", side_effect=responses) as api:
            out = P.deny_and_close(999)
            self.assertTrue(out["closed_without_merge"])
            self.assertFalse(out["merge_authorized"])
            self.assertEqual(api.call_count, 3)
